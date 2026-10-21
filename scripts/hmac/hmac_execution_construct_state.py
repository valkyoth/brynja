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
        self.tag_fields = set()

    def key(self):
        return (super().key(), tuple(sorted(self.pointers.items())), self.updates,
                self.normalized, frozenset(self.tag_fields))

    def forget_tags(self, address, size):
        require(type(size) is int and 0 <= size < (1 << 64), "unreviewed constructor write extent")
        root, offset = address
        self.tag_fields = {(base, start) for base, start in self.tag_fields
                           if base != root or start >= offset + size or start + 8 <= offset}

    def transfer(self, destination, source, size):
        # Dynamic hosted tag fields are stored directly, not carried by an
        # owner memcpy. A new representation requires an explicit review.
        self.forget_tags(destination, size)
        super().transfer(destination, source, size)

    def address(self, name):
        return self.pointers.get(name, (name, 0))

    def rooted(self, name):
        return any(row[0] == self.address(name)[0] for row in self.memory)

    def tagged(self, name):
        return any(root == self.address(name)[0] for root, _ in self.tag_fields)

    def store(self, address, size, value):
        self.forget_tags(address, size)
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

    def number(self, value, discriminator, route, profile="runtime"):
        return contracts.owner_value(value, discriminator, route, profile)

    def evaluate(self, line, predecessor, discriminator, route, types, profile="runtime"):
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
        pointer_load = re.match(r"load ptr, ptr (" + VALUE + "),", expression)
        pointer_compare = re.fullmatch(r"icmp (eq|ne) ptr (" + VALUE + r"), null", expression)
        if pointer_load and self.rooted(pointer_load[1]):
            value = self.load(self.address(pointer_load[1]), 8)
            require(profile == "static" and isinstance(value, tuple)
                    and value[0] < 3 and value[1:] == (64, 8), "unknown constructor pointer metadata")
            self.assign(name, ("nonnull", True))
            return True
        if pointer_compare and self.value(pointer_compare[2]) is not None:
            require(self.value(pointer_compare[2]) == ("nonnull", True), "unbound constructor pointer condition")
            self.assign(name, int(pointer_compare[1] == "ne"))
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
                        and value[1:] == (discriminator, contracts.metadata_size(profile))
                        for value in operands),
                    "constructor arithmetic on owner bytes")
            left, right = (self.number(self.value(operand), discriminator, route, profile)
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


def iterator_cursor(state, identity, compiler, profile="runtime", pool_name="%states"):
    shape, discriminator, absent, cached, start = contracts.geometry(identity, compiler, profile)
    size = contracts.metadata_size(profile)
    offset = 32 if identity.startswith("sha3_") else 16
    cursor = contracts.constant(state, (pool_name, offset), 8)
    require(cursor in range(4) and contracts.constant(state, (pool_name, offset + 8), 8) == 3
            and contracts.constant(state, (pool_name, 0), 1) == 1, "invalid remaining iterator range")
    for index in (3, 4):
        require(contracts.constant(state, (pool_name, start + index * shape.stride + discriminator), size)
                == cached % (1 << (8 * size)), "nonempty constructor iterator cache")
    return cursor
