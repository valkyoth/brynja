"""Public metadata and partial owner moves after accelerated admission."""
import re

import hmac_constructor_state as provenance
import hmac_execution_admission as admission
import hmac_execution_admission_contracts as contracts
import hmac_engine_final as syntax
from hmac_engine_codegen import require, LABEL

VALUE = syntax.VALUE


class State(admission.State):
    def __init__(self, seed, pointers):
        self.__dict__.update(seed.clone().__dict__)
        self.pointers = dict(pointers)
        self.updates = ()
        self.normalized = False

    def key(self):
        return super().key(), tuple(sorted(self.pointers.items())), self.updates, self.normalized

    def address(self, name):
        return self.pointers.get(name, (name, 0))

    def rooted(self, name):
        return any(row[0] == self.address(name)[0] for row in self.memory)

    def store(self, address, size, value):
        # Arm may pack cursor/end into one constant i128/vector store.
        # Updating its cursor must not discard the still-live end field.
        fragments = {}
        root, offset = address
        for (base, start, width), previous in self.constants.items():
            if base != root or start >= offset + size or start + width <= offset:
                continue
            if start < offset:
                count = offset - start
                fragments[base, start, count] = previous % (1 << (8 * count))
            if start + width > offset + size:
                begin = offset + size
                fragments[base, begin, start + width - begin] = previous >> (8 * (begin - start))
        super().store(address, size, value)
        self.constants.update(fragments)

    def number(self, value, discriminator, route):
        if isinstance(value, tuple) and value[1:] == (discriminator, 8):
            return route
        return value if isinstance(value, int) else None

    def evaluate(self, line, predecessor, discriminator, route, types):
        definition = re.match("(" + VALUE + r") = (.*)", line)
        if not definition:
            return False
        name, expression = definition.groups()
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? (i8|\[(\d+) x i8\]|%"[^"]+"), ptr ('
                           + VALUE + r"), i64 (" + VALUE + r"|-?\d+)", expression)
        phi = re.fullmatch(r"phi ptr (.*)", expression)
        if gep:
            stride = 1 if gep[1] == "i8" else int(gep[2]) if gep[2] else types.get(gep[1])
            offset = self.value(gep[4])
            require(stride and isinstance(offset, int), "unknown constructor iterator offset")
            root, base = self.address(gep[3])
            self.pointers[name] = root, base + offset * stride
            return True
        if phi:
            choices = re.findall(r"\[ (.*?), %" + LABEL + r" \]", phi[1])
            selected = [value for value, label in choices if label == predecessor]
            require(len(selected) == 1 and (re.fullmatch(VALUE, selected[0])
                    or selected[0] == "inttoptr (i64 1 to ptr)"), "unbound constructor pointer phi")
            self.pointers[name] = self.address(selected[0])
            return True
        provenance.evaluate(line, self, self.address, predecessor)
        arithmetic = re.fullmatch(r"(add|sub)(?: nuw)?(?: nsw)? i(\d+) ("
                                  + VALUE + r"|-?\d+), (" + VALUE + r"|-?\d+)", expression)
        comparison = re.fullmatch(r"icmp(?: samesign)? (eq|ne|ult|ugt|ule|uge) i(\d+) ("
                                  + VALUE + r"|-?\d+), (" + VALUE + r"|-?\d+)", expression)
        match = arithmetic or comparison
        if match:
            operands = [self.value(operand) for operand in match.group(3, 4)]
            require(all(not isinstance(value, tuple) or comparison
                        and value[1:] == (discriminator, 8) for value in operands),
                    "constructor arithmetic on owner bytes")
            left, right = (self.number(self.value(operand), discriminator, route)
                           for operand in match.group(3, 4))
            if left is not None and right is not None:
                if arithmetic:
                    result = left + right if match[1] == "add" else left - right
                    require(0 <= result < (1 << int(match[2])), "constructor cursor arithmetic wraps")
                else:
                    left, right = left % (1 << int(match[2])), right % (1 << int(match[2]))
                    result = int({"eq": left == right, "ne": left != right, "ult": left < right,
                                  "ugt": left > right, "ule": left <= right, "uge": left >= right}[match[1]])
                self.assign(name, result)
        return bool(gep or phi or match or re.match(r"(?:load i\d+|phi i\d+|trunc)", expression))


def iterator_cursor(state, identity, compiler):
    shape, discriminator, absent, cached, start = contracts.geometry(identity, compiler)
    offset = 32 if identity.startswith("sha3_") else 16
    cursor = contracts.constant(state, ("%states", offset), 8)
    require(cursor in range(4) and contracts.constant(state, ("%states", offset + 8), 8) == 3
            and contracts.constant(state, ("%states", 0), 1) == 1, "invalid remaining iterator range")
    for index in (3, 4):
        require(contracts.constant(state, ("%states", start + index * shape.stride + discriminator), 8)
                == cached % (1 << 64), "nonempty constructor iterator cache")
    return cursor
