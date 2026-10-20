"""Bounded byte-range provenance for emitted HMAC constructor moves."""
import copy
import re

from hmac_engine_codegen import LABEL, require
from hmac_engine_final import VALUE


class State:
    def __init__(self):
        # (allocation, destination offset, length, logical owner, source offset).
        self.memory = set()
        self.constants = {}
        self.values = {}
        self.born = set()
        self.done = set()

    def clone(self):
        return copy.deepcopy(self)

    def key(self):
        return (frozenset(self.memory), frozenset(self.constants.items()),
                frozenset(self.values.items()), frozenset(self.born), frozenset(self.done))

    def overlap(self, address, size):
        root, offset = address
        return {row for row in self.memory if row[0] == root
                and offset < row[1] + row[2] and row[1] < offset + size}

    def value(self, operand):
        if operand in ("true", "false"):
            return int(operand == "true")
        if re.fullmatch(r"-?\d+", operand):
            return int(operand)
        return self.values.get(operand)

    def assign(self, name, value):
        self.values.pop(name, None)
        if value is not None:
            self.values[name] = value

    def complete(self, address, width):
        root, offset = address
        rows = self.overlap(address, width)
        tokens = {row[3] for row in rows}
        require(len(tokens) == 1, "constructor missing/ambiguous owner")
        token = next(iter(tokens))
        intervals = []
        for base, start, length, owner, source in rows:
            lo, hi = max(start, offset), min(start + length, offset + width)
            require(source + lo - start == lo - offset, "constructor owner byte order")
            intervals.append((lo - offset, hi - offset))
        end = 0
        for lo, hi in sorted(intervals):
            require(lo == end, "constructor incomplete/overlapping owner")
            end = hi
        require(end == width and token not in self.done, "constructor incomplete/consumed owner")
        return token

    def birth(self, address, width, token):
        require(token not in self.born and not self.overlap(address, width),
                "duplicate/overwriting constructor birth")
        self.born.add(token)
        self.memory.add((*address, width, token, 0))

    def transfer(self, destination, source, size):
        require(not self.overlap(destination, size), "constructor owner overwritten by copy")
        root, offset = source
        for base, start, length, token, original in self.overlap(source, size):
            require(token not in self.done, "constructor copy after consumption")
            lo, hi = max(start, offset), min(start + length, offset + size)
            self.memory.add((destination[0], destination[1] + lo - offset, hi - lo,
                             token, original + lo - start))

    def load(self, address, size):
        rows = self.overlap(address, size)
        if rows:
            require(len(rows) == 1, "unsupported split constructor scalar load")
            base, start, length, token, original = next(iter(rows))
            require(start <= address[1] and address[1] + size <= start + length
                    and token not in self.done, "invalid constructor scalar load")
            return token, original + address[1] - start, size
        return self.constants.get((*address, size))

    def store(self, address, size, value):
        require(not self.overlap(address, size), "constructor owner overwritten by store")
        if isinstance(value, tuple):
            token, original, length = value
            require(size == length and token not in self.done, "constructor scalar copy width")
            self.memory.add((*address, size, token, original))
        for key in list(self.constants):
            if key[0] == address[0] and key[1] < address[1] + size and address[1] < key[1] + key[2]:
                del self.constants[key]
        if isinstance(value, int):
            self.constants[(*address, size)] = value

    def end(self, root):
        self.memory = {row for row in self.memory if row[0] != root}
        self.constants = {key: value for key, value in self.constants.items() if key[0] != root}


def evaluate(line, state, address, predecessor):
    """Only result discriminants, scalar move pieces and branch facts."""
    definition = re.match("(" + VALUE + r") = (.*)", line)
    if not definition:
        return
    name, expression = definition.groups()
    value = None
    load = re.match(r"load i(\d+), ptr (" + VALUE + ")", expression)
    phi = re.match(r"phi i\d+ (.*)", expression)
    trunc = re.match(r"trunc(?: nuw)? i\d+ (" + VALUE + r") to i1", expression)
    compare = re.match(r"icmp(?: samesign)? (eq|ne) i\d+ (" + VALUE
                       + r"), (-?\d+)", expression)
    if load:
        value = state.load(address(load[2]), (int(load[1]) + 7) // 8)
    elif phi:
        choices = re.findall(r"\[ ([-\w%.]+), %" + LABEL + r" \]", phi[1])
        selected = [operand for operand, label in choices if label == predecessor]
        require(len(selected) == 1, "unknown constructor phi predecessor")
        value = state.value(selected[0])
    elif trunc:
        source = state.value(trunc[1])
        if isinstance(source, int):
            value = source & 1
    elif compare:
        source = state.value(compare[2])
        if isinstance(source, int):
            value = int((source == int(compare[3])) == (compare[1] == "eq"))
    if isinstance(value, tuple):
        require(load or phi, "unsupported constructor scalar provenance")
    state.assign(name, value)
