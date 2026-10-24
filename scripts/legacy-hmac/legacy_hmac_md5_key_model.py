"""Bounded public-shape evaluator; constructor payloads retain byte origins.

This is not general LLVM semantics or a proof of BitString::new itself.
Unknown instructions, values, address arithmetic and predicates reject.
"""
import re

import legacy_hmac_md5_normalization as normalization

bits, transport = normalization.bits, normalization.transport
flow, syntax, require, VALUE = normalization.flow, normalization.syntax, normalization.require, normalization.VALUE
Bits, Pointer, Memory = bits.Bits, bits.Pointer, bits.Memory
ATOM = transport.ATOM
TYPE = r"(?:ptr|i1|i4|i8|i64|<[48] x ptr>|<[48] x i1>|<2 x i64>)"


def width(dtype):
    return 4 if dtype == "i4" else bits.width(dtype)


class State:
    def __init__(self, check, lengths, mask, backend, failure):
        require(len(lengths) == 8 and all(0 <= n < 1 << 63 for n in lengths), "invalid key-shape scenario")
        self.check, self.lengths, self.mask = check, lengths, mask
        self.failure, self.failed = failure, False
        self.values = {name: Pointer(name) for name in check.allocs}
        self.values[check.inputs] = Pointer(check.inputs)
        self.values[check.selection] = Bits.integer(backend, 8)
        self.memory = Memory({**check.allocs, check.inputs: 384, check.result: 32})
        self.values[check.result] = Pointer(check.result)
        self.live = {check.inputs, check.result}
        self.constructed, self.visited = [], set()
        for lane, length in enumerate(lengths):
            self.memory.store(Pointer(check.inputs, lane * 48),
                              Pointer("key" + str(lane)) if mask & (1 << lane) else Bits.integer(0, 64))
            self.memory.store(Pointer(check.inputs, lane * 48 + 8), Bits.integer(length, 64))

    def value(self, value, dtype):
        if value in self.values:
            return self.values[value]
        if value in ("null", "false", "true", "zeroinitializer") or re.fullmatch(r"-?\d+", value):
            number = int(value == "true") if not re.fullmatch(r"-?\d+", value) else int(value)
            return Bits.integer(number, width(dtype))
        if value in ("poison", "undef"):
            if re.fullmatch(r"<[48] x (ptr|i1)>", dtype):
                return (None,) * int(dtype[1])
            return Bits.unknown(width(dtype))
        require(False, "unbound key construction value: " + value)

    def integer(self, value, dtype="i64"):
        parsed = self.value(value, dtype)
        require(isinstance(parsed, Bits) and parsed.number() is not None, "unknown key-shape integer")
        return parsed.number()

    def address(self, value, size=0, writing=False):
        pointer = self.value(value, "ptr")
        self.memory.bounds(pointer, size)
        require(pointer.root in self.live and (not writing or pointer.root != self.check.inputs),
                "key descriptor access outside owned/live storage")
        return pointer

    def pointer_equal(self, left, right):
        require(isinstance(left, Pointer) or left == Bits.integer(0, 64), "unknown key pointer comparison")
        require(isinstance(right, Pointer) or right == Bits.integer(0, 64), "unknown key pointer comparison")
        return left == right

    def expression(self, expression):
        gep = re.fullmatch(rf'getelementptr(?: inbounds)?(?: nuw)? (i8|%"[^"]+"), ptr ({VALUE}), i64 ({ATOM})', expression)
        load = re.fullmatch(rf"load (ptr|i8|i64), ptr ({VALUE}), align \d+(?:, !.*)?", expression)
        compare = re.fullmatch(rf"icmp(?: samesign)? (eq|ne|ugt|ult|uge|ule) (ptr|i4|i8|i64) ({ATOM}), ({ATOM})", expression)
        binary = re.fullmatch(rf"(add|sub|shl|lshr|or|and)(?: nuw)?(?: nsw)?(?: disjoint)?(?: exact)? (i1|i8|i64) ({ATOM}), ({ATOM})", expression)
        cast = re.fullmatch(rf"(trunc|zext)(?: nuw)?(?: nneg)? (i1|i8|i64) ({ATOM}) to (i1|i8|i64)", expression)
        select = re.fullmatch(rf"select i1 ({ATOM}), (i64|i1) ({ATOM}), \2 ({ATOM})", expression)
        insert = re.fullmatch(rf"insertelement <([48]) x ptr> ({ATOM}), ptr ({ATOM}), i64 ([0-7])", expression)
        vector_cmp = re.fullmatch(rf"icmp (eq|ne) <([48]) x ptr> ({ATOM}), (?:zeroinitializer|splat \(ptr null\))", expression)
        bitcast = re.fullmatch(rf"bitcast <([48]) x i1> ({VALUE}) to i\1", expression)
        if gep:
            base = self.value(gep[2], "ptr")
            stride = 1 if gep[1] == "i8" else self.check.types.get(gep[1])
            require(isinstance(base, Pointer) and stride, "unknown key descriptor GEP")
            result = Pointer(base.root, base.offset + stride * self.integer(gep[3]))
            self.memory.bounds(result, 0)
            return result
        if load:
            address = self.address(load[2], bits.width(load[1]) // 8)
            if address.root == self.check.inputs:
                lane, offset = divmod(address.offset, 48)
                require((offset == 0 and load[1] == "ptr") or
                        (offset == 8 and load[1] == "i64" and self.mask & (1 << lane)),
                        "key construction reads inactive/unrelated input payload")
            return self.memory.load(address, load[1])
        if compare:
            op, dtype, a, b = compare.groups()
            if dtype == "ptr":
                require(op in ("eq", "ne"), "ordered key pointer comparison")
                result = self.pointer_equal(self.value(a, dtype), self.value(b, dtype)) == (op == "eq")
            else:
                left, right = self.integer(a, dtype), self.integer(b, dtype)
                result = {"eq": left == right, "ne": left != right, "ugt": left > right,
                          "ult": left < right, "uge": left >= right, "ule": left <= right}[op]
            return Bits.integer(int(result), 1)
        if binary:
            op, dtype, a, b = binary.groups()
            left, right = self.integer(a, dtype), self.integer(b, dtype)
            extent = bits.width(dtype)
            require(op not in ("shl", "lshr") or right < extent, "oversized key-shape shift")
            if op in ("or", "and"):
                result = left | right if op == "or" else left & right
            else:
                operation = {"add": lambda a, b: a + b, "sub": lambda a, b: a - b,
                             "shl": lambda a, b: a << b, "lshr": lambda a, b: a >> b}[op]
                result = operation(left, right)
                if " nuw " in expression:
                    require(0 <= result < 1 << extent, "unsigned key-shape arithmetic overflows")
                if " nsw " in expression:
                    signed = lambda n: n if n < 1 << (extent - 1) else n - (1 << extent)
                    signed_result = operation(signed(left), right if op in ("shl", "lshr") else signed(right))
                    require(-(1 << (extent - 1)) <= signed_result < 1 << (extent - 1), "signed key-shape arithmetic overflows")
                if " exact " in expression:
                    require(op == "lshr" and left % (1 << right) == 0, "inexact key-shape shift")
            return Bits.integer(result, extent)
        if cast:
            return bits.packed(self.value(cast[3], cast[2])).resize(bits.width(cast[4]))
        if select:
            return self.value(select[3] if self.integer(select[1], "i1") else select[4], select[2])
        if insert:
            vector = list(self.value(insert[2], f"<{insert[1]} x ptr>"))
            require(len(vector) == int(insert[1]) and int(insert[4]) < len(vector), "key activity vector width changed")
            vector[int(insert[4])] = self.value(insert[3], "ptr")
            return tuple(vector)
        if vector_cmp:
            vector = self.value(vector_cmp[3], f"<{vector_cmp[2]} x ptr>")
            require(len(vector) == int(vector_cmp[2]), "key activity comparison width changed")
            return tuple(int(self.pointer_equal(value, Bits.integer(0, 64)) == (vector_cmp[1] == "eq")) for value in vector)
        if bitcast:
            vector = self.value(bitcast[2], f"<{bitcast[1]} x i1>")
            require(len(vector) == int(bitcast[1]) and all(x in (0, 1) for x in vector), "unknown key activity vector")
            return Bits.integer(sum(x << i for i, x in enumerate(vector)), len(vector))
        require(False, "unparsed key construction expression: " + expression)

    def call(self, name, args):
        if name in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
            root = syntax.operand(args[-1])
            require(root in self.check.allocs and len(args) in (1, 2) and
                    (len(args) == 1 or args[0] == "i64 " + str(self.check.allocs[root])), "key lifetime identity/extent changed")
            if name == "llvm.lifetime.start.p0":
                require(root not in self.live, "key lifetime restarted while live")
                self.live.add(root)
            else:
                require(root in self.live, "key lifetime ended twice")
                self.live.remove(root)
            self.memory.invalidate(root)
        elif name == "llvm.experimental.noalias.scope.decl":
            require(len(args) == 1 and re.fullmatch(r"metadata !\d+", args[0]), "key alias metadata changed")
        elif name in ("llvm.memcpy.p0.p0.i64", "llvm.memset.p0.i64"):
            require(len(args) == 4 and re.fullmatch(r"i64 \d+", args[2]) and args[3] == "i1 false", "key memory transfer changed")
            count = int(args[2].split()[-1])
            dest = self.address(syntax.operand(args[0]), count, True)
            if "memcpy" in name:
                source = self.address(syntax.operand(args[1]), count)
                require(source.root != dest.root or source.offset + count <= dest.offset or
                        dest.offset + count <= source.offset, "overlapping key descriptor memcpy")
                data = Bits(tuple(bit for i in range(count)
                                  for bit in self.memory.cells.get((source.root, source.offset + i), (None,) * 8)))
            else:
                require(args[1] == "i8 0", "key initialization is not zero")
                data = Bits.integer(0, count * 8)
            self.memory.store(dest, data)
        elif self.check.constructor(name):
            require(len(args) == 4 and args[3] == "i8 noundef 8", "key constructor bit width/arity changed")
            dest = self.address(syntax.operand(args[0]), 32, True)
            key = self.value(syntax.operand(args[1]), "ptr")
            length = re.fullmatch(rf"i64 noundef ({ATOM})", args[2])
            require(length and isinstance(key, Pointer) and re.fullmatch(r"key[0-7]", key.root)
                    and key.offset == 0, "constructor key pointer changed")
            lane = int(key.root[-1])
            require(lane not in self.constructed and self.mask & (1 << lane)
                    and self.integer(length[1]) == self.lengths[lane] > 64,
                    "constructor lane/length/inactive key changed")
            self.constructed.append(lane)
            self.memory.invalidate(dest.root)
            if self.failure == lane or self.lengths[lane] > ((1 << 64) - 1) // 8:
                self.failed = True
                self.memory.store(dest, Bits.integer(0, 64))
            else:
                self.memory.store(dest, key)
                self.memory.store(Pointer(dest.root, dest.offset + 8), Bits.token(("descriptor", lane), 192))
        elif name in ("llvm.ctpop.i8", "llvm.umin.i64"):
            dtype = "i8" if "ctpop" in name else "i64"
            values = []
            for arg in args:
                match = re.fullmatch(dtype + rf"(?: range\([^)]*\))? ({ATOM})", arg)
                require(match, "key routing intrinsic argument changed")
                values.append(self.integer(match[1], dtype))
            require(len(values) == (1 if "ctpop" in name else 2), "key routing intrinsic arity changed")
            return Bits.integer(values[0].bit_count() if "ctpop" in name else min(values), bits.width(dtype))
        else:
            require(False, "unknown effect during key construction/routing: " + name)
        return None

    def walk(self):
        label, index, previous = next(iter(self.check.graph)), 0, None
        for _ in range(2000):
            require(label in self.check.graph, "unknown key construction edge")
            if (label, index) in self.check.frontiers:
                return self.check.frontiers[(label, index)]
            lines = self.check.graph[label]
            phis = {}
            while index < len(lines) and " = phi " in lines[index]:
                match = re.fullmatch(rf"({VALUE}) = phi ({TYPE}) (.*)", lines[index])
                require(match, "unparsed key routing phi")
                pattern = rf"\[ ({ATOM}), %{flow.LABEL} \]"
                require(re.fullmatch(pattern + "(?:, " + pattern + ")*", match[3]), "malformed key routing phi")
                edges = re.findall(pattern, match[3])
                require(len({edge for _, edge in edges}) == len(edges), "duplicate key routing phi edge")
                selected = [value for value, edge in edges if edge == previous]
                require(len(selected) == 1, "key routing phi predecessor missing")
                phis[match[1]] = self.value(selected[0], match[2])
                self.visited.add((label, index)); index += 1
            self.values.update(phis)
            while index < len(lines):
                site, line = (label, index), lines[index]
                if site in self.check.frontiers:
                    return self.check.frontiers[site]
                self.visited.add(site)
                definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
                store = re.fullmatch(rf"store (ptr|i8|i64) ({ATOM}), ptr ({VALUE}), align \d+(?:, !.*)?", line)
                branch = re.fullmatch(rf"br i1 ({ATOM}), label %{flow.LABEL}, label %{flow.LABEL}", line)
                jump = re.fullmatch(r"br label %" + flow.LABEL, line)
                call = syntax.call(line)
                if line.startswith(tuple(name + " = alloca " for name in self.check.allocs)):
                    pass
                elif call:
                    require("invoke " not in line, "unexpected key constructor unwind")
                    result = self.call(*call)
                    require(bool(definition) == (result is not None), "key call result shape changed")
                    if definition:
                        self.values[definition[1]] = result
                elif definition:
                    self.values[definition[1]] = self.expression(definition[2])
                elif store:
                    address = self.address(store[3], bits.width(store[1]) // 8, True)
                    self.memory.store(address, self.value(store[2], store[1]))
                    if address == Pointer(self.check.result):
                        self.check.error_exclusion(site)
                        return "error"
                elif branch or jump:
                    target = branch[2 if self.integer(branch[1], "i1") else 3] if branch else jump[1]
                    previous, label, index = label, target, 0
                    break
                else:
                    require(False, "unparsed key construction instruction: " + line)
                index += 1
            else:
                require(False, "key construction bypassed its frontier")
        require(False, "key routing instruction bound exhausted")
