"""Small fail-closed evaluator for the emitted post-normalization pad loop.

Copy/XOR semantics are source-bound premises, not re-proved machine code.
Only public lengths/indices control execution; pad bytes retain symbolic origins.
"""
import functools
import re

import legacy_hmac_md5_phases as phases

flow, syntax, require, VALUE = phases.flow, phases.syntax, phases.require, phases.VALUE
ATOM = rf"(?:{VALUE}|-?\d+|true|false|null)"
GEP = rf'getelementptr(?: inbounds)?(?: nuw)? (i8|\[(\d+) x i8\]|%"[^"]+"), ptr ({VALUE}), i64 ({ATOM})'


def primitive(name, function):
    return bool(re.fullmatch(r"_RNvNtCs\w+_11brynja_core13secret_memory" + str(len(function)) + function
                            + r"|_ZN11brynja_core13secret_memory" + str(len(function)) + function
                            + r"17h[0-9a-f]+E", name))


@functools.lru_cache(maxsize=16384)
def parse(line):
    definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
    name, expression = definition.groups() if definition else (None, line)
    patterns = (
        ("gep", GEP),
        ("load", rf"load (ptr|i64), ptr ({VALUE}), align \d+(?:, !.*)?"),
        ("binary", rf"(add|lshr)(?: nuw)?(?: nsw)? i64 ({ATOM}), ({ATOM})"),
        ("compare", rf"icmp(?: samesign)? (eq|ne|ugt|ult|uge|ule) (ptr|i\d+) ({ATOM}), ({ATOM})"),
        ("select", rf"select i1 ({ATOM}), i1 ({ATOM}), i1 ({ATOM})"),
        ("trunc", rf"trunc(?: nuw)? i64 ({ATOM}) to i1"),
        ("store", rf"store i8 ({ATOM}), ptr ({VALUE}), align (?:1|2|4|8)(?:, !.*)?"),
        ("branch", rf"br i1 ({ATOM}), label %{flow.LABEL}, label %{flow.LABEL}"),
        ("jump", r"br label %" + flow.LABEL),
        ("edge", "to label %" + flow.LABEL + " unwind label %" + flow.LABEL + r"(?:, !.*)?"),
    )
    for kind, pattern in patterns:
        match = re.fullmatch(pattern, expression)
        if match:
            require(bool(name) == (kind in ("gep", "load", "binary", "compare", "select", "trunc")),
                    "pad instruction result shape changed")
            return kind, name, match.groups()
    call = syntax.call(line)
    if call:
        return "call", name, call
    require(False, "unsupported pad-loop instruction: " + line)


class State:
    def __init__(self, check, lengths, mask, normalized, failure):
        require(len(lengths) == 8 and all(0 <= n < 1 << 63 for n in lengths), "invalid pad scenario")
        self.check, self.lengths, self.mask = check, lengths, mask
        self.normalized, self.failure, self.failed = normalized, failure, False
        self.values = {name: (name, 0) for name in (check.inputs, check.pads, check.owner, *check.locals)}
        self.values.update(check.pointers)
        self.bytes = [0] * 512
        self.local, self.live, self.calls = {}, set(), []
        self.sites = set()

    def value(self, name):
        if name == "null":
            return None
        if name in ("true", "false"):
            return int(name == "true")
        if re.fullmatch(r"-?\d+", name):
            return int(name)
        require(name in self.values, "unbound pad value: " + name)
        return self.values[name]

    def read(self, address, kind):
        require(isinstance(address, tuple) and len(address) == 2, "non-address pad load")
        root, offset = address
        if root == self.check.inputs:
            lane, field = divmod(offset, 48)
            require(0 <= lane < 8 and (kind, field) in (("ptr", 0), ("i64", 8)), "wrong input key field")
            if field == 0:
                return ("key" + str(lane), 0) if self.mask & (1 << lane) else None
            require(self.mask & (1 << lane), "inactive key length read")
            return self.lengths[lane]
        if root == self.check.owner:
            require((kind, offset) in (("i64", 0), ("ptr", 8), ("i64", 16)), "wrong normalized owner field")
            present, pointer, length = self.normalized
            require(offset == 0 or present, "absent normalized owner payload read")
            return {0: int(present), 8: ("normalized", 0) if pointer else None, 16: length}[offset]
        require(False, "unmodeled pad load")

    def argument(self, argument):
        if argument.startswith("ptr "):
            return self.value(syntax.operand(argument))
        match = re.fullmatch(rf"i(?:8|64)(?: noundef)? ({ATOM})", argument)
        require(match, "unknown pad primitive argument")
        return self.value(match[1])

    def span(self, pointer, size, writing=False):
        require(isinstance(pointer, tuple) and len(pointer) == 2 and isinstance(size, int), "unknown pad span")
        root, offset = pointer
        if root == self.check.pads:
            extent = 512
        elif root == "normalized":
            require(not writing and self.normalized[:2] == (True, True), "invalid normalized source")
            extent = min(128, self.normalized[2])
        elif re.fullmatch(r"key[0-7]", root):
            require(not writing, "key source modified")
            extent = self.lengths[int(root[-1])]
        else:
            require(False, "unknown pad buffer: " + root)
        require(0 <= offset <= extent and 0 <= size <= extent - offset, "pad access out of bounds")
        return root, offset

    def copy(self, args):
        require(len(args) == 4, "pad copy arity")
        dest, count, source, available = map(self.argument, args)
        require(count == available and 0 < count <= 64, "wrong pad copy length")
        dr, at = self.span(dest, count, True)
        sr, begin = self.span(source, count)
        require(dr == self.check.pads and sr != dr, "pad copy overlaps or writes wrong owner")
        self.calls.append(("copy", at))
        if self.failure == ("copy", at):
            self.failed = True
            return 0  # a valid SecretMemoryError, distinct from compiled Ok
        self.bytes[at:at + count] = [(sr, byte) for byte in range(begin, begin + count)]
        return self.check.copy_ok

    def xor(self, args):
        require(len(args) == 5, "pad XOR arity")
        dest, source, right, count, left = map(self.argument, args)
        require((right, count, left) == (0, 8, 0), "pad XOR bit geometry changed")
        root, at = self.span(dest, 1, True)
        require(root == self.check.pads and source in self.local and source[0] in self.live,
                "unbound pad XOR mask")
        self.calls.append(("xor", at))
        if self.failure == ("xor", at):
            self.failed = True
            return 1
        self.bytes[at] = ("xor", self.bytes[at], self.local[source])
        return 0

    def evaluate(self, line):
        kind, name, args = parse(line)
        if kind == "gep":
            dtype, width, base, offset = args
            stride = 1 if dtype == "i8" else int(width) if width else self.check.types.get(dtype)
            pointer, index = self.value(base), self.value(offset)
            require(stride and isinstance(pointer, tuple) and isinstance(index, int) and index >= 0,
                    "unknown pad address arithmetic")
            result = pointer[0], pointer[1] + stride * index
            require(result[1] < 1 << 64, "pad address wraps")
        elif kind == "load":
            result = self.read(self.value(args[1]), args[0])
        elif kind == "binary":
            op, lhs, rhs = args
            left, right = self.value(lhs), self.value(rhs)
            require(isinstance(left, int) and isinstance(right, int) and 0 <= left < 1 << 64,
                    "pad arithmetic on unknown/secret value")
            require(op != "lshr" or 0 <= right < 64, "invalid pad shift")
            result = left + right if op == "add" else left >> right
            require(0 <= result < 1 << 64, "pad cursor wraps")
        elif kind == "compare":
            op, dtype, lhs, rhs = args
            left, right = self.value(lhs), self.value(rhs)
            if dtype != "ptr":
                require(isinstance(left, int) and isinstance(right, int), "pad comparison on unknown value")
                bits = (1 << int(dtype[1:])) - 1
                left, right = left & bits, right & bits
            if op in ("eq", "ne"):
                result = int((left == right) == (op == "eq"))
            else:
                require(dtype != "ptr", "ordered pad pointer comparison")
                result = int({"ugt": left > right, "ult": left < right, "uge": left >= right, "ule": left <= right}[op])
        elif kind == "select":
            condition = self.value(args[0])
            require(condition in (0, 1), "unknown pad selection")
            result = self.value(args[1 if condition else 2])
        elif kind == "trunc":
            result = self.value(args[0]) & 1
        elif kind == "store":
            byte, pointer = self.value(args[0]), self.value(args[1])
            require(pointer[0] in self.live and pointer[1] == 0 and 0 <= byte <= 255,
                    "unapproved pad scalar store")
            self.local[pointer] = byte
            return None
        elif kind == "call":
            symbol, operands = args
            if symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
                root = syntax.operand(operands[-1])
                require(root in self.check.locals and len(operands) in (1, 2) and
                        (len(operands) == 1 or operands[0] == "i64 1"), "pad mask lifetime changed")
                if symbol == "llvm.lifetime.start.p0":
                    require(root not in self.live, "repeated pad mask lifetime")
                    self.live.add(root)
                else:
                    require(root in self.live, "pad mask lifetime ended twice")
                    self.live.remove(root)
                self.local.pop((root, 0), None)
                return None
            require(not self.failed, "pad work continues after primitive failure")
            if primitive(symbol, "copy_secret_region"):
                result = self.copy(operands)
            elif primitive(symbol, "xor_secret_byte_bits"):
                result = self.xor(operands)
            else:
                require(False, "unknown call in pad loop: " + symbol)
        elif kind in ("branch", "jump", "edge"):
            if kind == "branch":
                condition = self.value(args[0])
                require(condition in (0, 1), "unknown pad branch")
                return args[1 if condition else 2]
            return args[0]  # normal invoke edge; unwind is separately excluded
        else:
            require(False, "unknown pad instruction")
        require(name is not None, "pad operation result discarded")
        self.values[name] = result
        return None

    def walk(self):
        label, previous = self.check.start, self.check.previous
        for _ in range(12000):
            if label in self.check.stops:
                return self.check.stops[label]
            require(label in self.check.graph, "unknown pad edge")
            lines = self.check.graph[label]
            values, index = {}, 0
            while index < len(lines) and " = phi " in lines[index]:
                match = re.fullmatch(rf"({VALUE}) = phi (?:ptr|i64) (.*)", lines[index])
                require(match, "unparsed pad phi")
                pattern = rf"\[ ({ATOM}), %{flow.LABEL} \]"
                require(re.fullmatch(pattern + "(?:, " + pattern + ")*", match[2]), "malformed pad phi")
                edges = re.findall(pattern, match[2])
                require(len({edge for _, edge in edges}) == len(edges), "duplicate pad phi predecessor")
                chosen = [value for value, edge in edges if edge == previous]
                require(len(chosen) == 1, "pad phi predecessor missing")
                values[match[1]] = self.value(chosen[0])
                self.sites.add((label, index))
                index += 1
            self.values.update(values)
            for index in range(index, len(lines)):
                self.sites.add((label, index))
                target = self.evaluate(lines[index])
                if target is not None:
                    require(index == len(lines) - 1, "instructions after pad terminator")
                    previous, label = label, target
                    break
            else:
                require(False, "unterminated pad block")
        require(False, "pad loop analysis bound exceeded")
