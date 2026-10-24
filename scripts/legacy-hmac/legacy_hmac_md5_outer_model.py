"""Bounded conditional outer-prefix/descriptor evaluator, not general LLVM."""
import re

import legacy_hmac_md5_key_model as model
import legacy_hmac_md5_pad_model as pad

bits, flow, syntax, require, VALUE = model.bits, model.flow, model.syntax, model.require, model.VALUE
Bits, Pointer, Memory = model.Bits, model.Pointer, model.Memory
ATOM = model.ATOM
TYPE = r"(?:ptr|i1|i8|i64)"


class State(model.State):
    def __init__(self, check, mask, failure):
        self.check, self.mask, self.failure = check, mask, failure
        self.failed, self.constructed, self.visited, self.xors = False, [], set(), []
        self.values = {name: Pointer(name) for name in (*check.allocs, check.inputs, check.control)}
        self.values.update(check.seeds)
        self.memory = Memory({**check.allocs, check.inputs: 384, "inner-data": 128})
        self.live = {check.inputs, check.pad, check.owner, "inner-data"}
        self.memory.store(Pointer(check.owner), Pointer("inner-data"))
        self.memory.store(Pointer(check.owner, 8), Bits.integer(128, 64))
        for lane in range(8):
            self.memory.store(Pointer(check.inputs, lane * 48),
                              Pointer("key" + str(lane)) if mask & (1 << lane) else Bits.integer(0, 64))
        for offset in range(512):
            self.memory.store(Pointer(check.pad, offset), Bits.token(("ipad", offset), 8))

    def expression(self, expression):
        gep = re.fullmatch(rf'getelementptr(?: inbounds)?(?: nuw)? \[(\d+) x i8\], ptr ({VALUE}), i64 ({ATOM})', expression)
        select = re.fullmatch(rf"select i1 ({ATOM}), ptr ({VALUE}), ptr inttoptr \(i64 1 to ptr\)", expression)
        compare = re.fullmatch(rf"icmp (eq|ne) i64 ({VALUE}), 0", expression)
        if gep:
            base = self.value(gep[2], "ptr")
            require(isinstance(base, Pointer), "outer descriptor base is not an owner")
            pointer = Pointer(base.root, base.offset + int(gep[1]) * self.integer(gep[3]))
            self.memory.bounds(pointer, 0)
            return pointer
        if select:
            require(self.integer(select[1], "i1") == 1, "valid inner owner unexpectedly selects dangling pointer")
            return self.value(select[2], "ptr")
        if compare and self.value(compare[2], "i64") == Pointer("inner-data").bits():
            # The scope of this evaluator assumes a valid, non-null 128-byte
            # inner owner. No general symbolic pointer non-nullness is inferred.
            return Bits.integer(int(compare[1] == "ne"), 1)
        return super().expression(expression)

    def call(self, name, args):
        if name in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
            require(syntax.operand(args[-1]) in self.check.lifetimes, "outer construction changes unrelated owner lifetime")
        if name in ("llvm.memcpy.p0.p0.i64", "llvm.memset.p0.i64"):
            dest = self.address(syntax.operand(args[0]), 0, True)
            if name == "llvm.memcpy.p0.p0.i64":
                source = self.address(syntax.operand(args[1]))
                require(dest.root in self.check.temporaries | {self.check.outer}
                        and source.root in self.check.temporaries | {self.check.outer}, "outer descriptor copy escapes temporaries")
            else:
                require(dest == Pointer(self.check.final) and args[1:] == ["i8 0", "i64 128", "i1 false"],
                        "outer construction memset changes non-output owner")
        if pad.primitive(name, "xor_secret_byte_bits"):
            require(not self.failed and len(args) == 5 and args[2:] == ["i8 noundef 0", "i8 noundef 8", "i8 noundef 0"],
                    "outer XOR geometry or failure ordering changed")
            dest = self.address(syntax.operand(args[0]), 1, True)
            source = self.address(syntax.operand(args[1]), 1)
            require(dest.root == self.check.pad and source.root in self.check.locals and source.offset == 0,
                    "outer XOR input/output owner changed")
            mask = self.memory.load(source, "i8").number()
            require(mask is not None, "outer XOR mask is unknown")
            self.xors.append(dest.offset)
            if self.failure == ("xor", dest.offset):
                self.failed = True
                return Bits.integer(1, 1)
            previous = self.memory.load(dest, "i8")
            self.memory.store(dest, Bits(tuple(("not", bit) if mask & (1 << i) else bit
                                              for i, bit in enumerate(previous.data))))
            return Bits.integer(0, 1)
        if self.check.constructor(name):
            require(not self.failed and len(args) == 4 and args[2:] == ["i64 noundef 16", "i8 noundef 8"],
                    "outer descriptor length/bit count/failure ordering changed")
            dest = self.address(syntax.operand(args[0]), 32, True)
            digest = self.address(syntax.operand(args[1]), 16)
            lane = digest.offset // 16
            require(dest.root in self.check.temporaries and digest.root == "inner-data" and digest.offset % 16 == 0
                    and lane not in self.constructed and self.mask & (1 << lane), "outer digest lane/provenance changed")
            self.constructed.append(lane)
            self.memory.invalidate(dest.root)
            if self.failure == ("constructor", lane):
                self.failed = True
                self.memory.store(dest, Bits.integer(0, 64))
            else:
                self.memory.store(dest, digest)
                self.memory.store(Pointer(dest.root, dest.offset + 8), Bits.token(("descriptor", lane), 192))
            return None
        return super().call(name, args)

    def walk(self):
        label, index = self.check.start
        previous = None
        for _ in range(10000):
            require(label in self.check.graph, "unknown outer construction edge")
            if label not in self.check.relevant:
                return False
            lines = self.check.graph[label]
            phis = {}
            while index < len(lines) and " = phi " in lines[index]:
                match = re.fullmatch(rf"({VALUE}) = phi ({TYPE}) (.*)", lines[index])
                require(match, "unparsed outer construction phi")
                pattern = rf"\[ ({ATOM}), %{flow.LABEL} \]"
                require(re.fullmatch(pattern + "(?:, " + pattern + ")*", match[3]), "malformed outer phi")
                edges = re.findall(pattern, match[3])
                require(len({edge for _, edge in edges}) == len(edges), "duplicate outer phi predecessor")
                chosen = [value for value, edge in edges if edge == previous]
                require(len(chosen) == 1, "outer phi predecessor missing")
                phis[match[1]] = self.value(chosen[0], match[2])
                self.visited.add((label, index)); index += 1
            self.values.update(phis)
            while index < len(lines):
                site, line = (label, index), lines[index]
                if site == self.check.stop:
                    return True
                self.visited.add(site)
                definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
                store = re.fullmatch(rf"store (ptr|i8|i64) ({ATOM}), ptr ({VALUE}), align \d+(?:, !.*)?", line)
                branch = re.fullmatch(rf"br i1 ({ATOM}), label %{flow.LABEL}, label %{flow.LABEL}", line)
                jump = re.fullmatch(r"br label %" + flow.LABEL, line)
                call = syntax.call(line)
                target = None
                if call:
                    result = self.call(*call)
                    require(bool(definition) == (result is not None), "outer call result discarded/invented")
                    if definition:
                        self.values[definition[1]] = result
                    if "invoke " in line:
                        normal, unwind = self.check.results.continuation(self.check.graph, site)
                        require(unwind[0] not in self.check.relevant, "outer constructor/XOR unwind reaches dispatch")
                        target = normal[0]
                elif definition:
                    self.values[definition[1]] = self.expression(definition[2])
                elif store:
                    pointer = self.address(store[3], bits.width(store[1]) // 8, True)
                    require(pointer.root in self.check.writable, "outer construction store outside owned temporaries")
                    self.memory.store(pointer, self.value(store[2], store[1]))
                elif branch or jump:
                    target = branch[2 if self.integer(branch[1], "i1") else 3] if branch else jump[1]
                else:
                    require(False, "unparsed outer construction instruction: " + line)
                if target is not None:
                    previous, label, index = label, target, 0
                    break
                index += 1
            else:
                require(False, "unterminated outer descriptor block")
        require(False, "outer construction step bound exhausted")
