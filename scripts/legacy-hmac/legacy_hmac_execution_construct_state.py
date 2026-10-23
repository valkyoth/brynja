"""Public cursor metadata and byte provenance after SHA-1 stream admission."""
import re

import legacy_hmac_execution_admission as admission

VALUE, flow, require = admission.VALUE, admission.flow, admission.require


class State(admission.State):
    def __init__(self, seed, pointers):
        self.__dict__.update(seed.clone().__dict__)
        self.pointers = dict(pointers)
        self.updates = ()
        self.normalized = False
        self.tags = set()

    def key(self):
        return super().key(), frozenset(self.pointers.items()), self.updates, self.normalized, frozenset(self.tags)

    def address(self, name):
        return self.pointers.get(name, (name, 0))

    def rooted(self, name):
        return any(row[0] == self.address(name)[0] for row in self.memory)

    def invalidate(self, address, size):
        root, offset = address
        self.tags = {(base, start, width) for base, start, width in self.tags
                     if base != root or not (offset < start + width and start < offset + size)}
        self.constants = {key: value for key, value in self.constants.items()
                          if key[0] != root or not (offset < key[1] + key[2] and key[1] < offset + size)}

    def transfer(self, destination, source, size):
        self.invalidate(destination, size)
        super().transfer(destination, source, size)

    def store(self, address, size, value):
        self.invalidate(address, size)
        super().store(address, size, value)

    def end(self, root):
        super().end(root)
        self.tags = {key for key in self.tags if key[0] != root}

    def number(self, value, niche):
        if isinstance(value, tuple) and len(value) == 3 and value[1:] == (441, 1):
            return niche
        return value if isinstance(value, int) else None

    def evaluate(self, line, predecessor, niche, types, tag):
        definition = re.match(rf"({VALUE}) = (.*)", line)
        if not definition:
            return False
        name, expression = definition.groups()
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? (i8|\[(\d+) x i8\]|%"[^"]+"), ptr ('
                           + VALUE + r"), i64 (" + VALUE + r"|-?\d+)", expression)
        phi = re.fullmatch(r"phi ptr (.*)", expression)
        if gep:
            stride = 1 if gep[1] == "i8" else int(gep[2]) if gep[2] else types.get(gep[1])
            offset = self.value(gep[4])
            require(stride and isinstance(offset, int), "unknown constructor pointer offset")
            root, base = self.address(gep[3])
            self.pointers[name] = root, base + offset * stride
            return True
        if phi:
            selected = [value for value, label in re.findall(r"\[ (.*?), %" + flow.LABEL + r" \]", phi[1])
                        if label == predecessor]
            require(len(selected) == 1 and re.fullmatch(VALUE, selected[0]), "unknown constructor pointer phi")
            self.pointers[name] = self.address(selected[0])
            return True
        admission.provenance.evaluate(line, self, self.address, predecessor)
        if re.fullmatch(r"trunc(?: nuw)? i64 " + re.escape(tag) + r" to i8", expression):
            self.assign(name, "tag-byte")
            return True
        arithmetic = re.fullmatch(rf"(add|sub)(?: nuw)?(?: nsw)? i(\d+) ({VALUE}|-?\d+), ({VALUE}|-?\d+)", expression)
        compare = re.fullmatch(rf"icmp(?: samesign)? (eq|ne|ult|ugt|ule|uge) i(\d+) ({VALUE}|-?\d+), ({VALUE}|-?\d+)", expression)
        match = arithmetic or compare
        if match:
            operands = [self.value(value) for value in match.group(3, 4)]
            require(all(not isinstance(value, tuple) or compare and value[1:] == (441, 1) for value in operands),
                    "constructor arithmetic on stream bytes")
            left, right = (self.number(value, niche) for value in operands)
            if left is not None and right is not None:
                if arithmetic:
                    value = left + right if match[1] == "add" else left - right
                    require(0 <= value < 1 << int(match[2]), "constructor cursor wraps")
                else:
                    left, right = left % (1 << int(match[2])), right % (1 << int(match[2]))
                    value = int({"eq": left == right, "ne": left != right, "ult": left < right,
                                 "ugt": left > right, "ule": left <= right, "uge": left >= right}[match[1]])
                self.assign(name, value)
        return bool(match or re.match(r"(?:load i\d+|phi i\d+|trunc)", expression))
