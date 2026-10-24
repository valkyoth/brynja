"""Bit provenance for split/reassembled normalization result fields.

None denotes an unknown bit, never evidence of a constant or owner identity.
Pointer/length tokens survive shifts and disjoint field packing without being
replaced by convenient concrete addresses. This is not general LLVM semantics.
"""
from dataclasses import dataclass
import re

import legacy_hmac_md5_phases as phases

require = phases.require


@dataclass(frozen=True)
class Bits:
    data: tuple

    @classmethod
    def integer(cls, number, width):
        return cls(tuple((number >> bit) & 1 for bit in range(width)))

    @classmethod
    def unknown(cls, width):
        return cls((None,) * width)

    @classmethod
    def token(cls, name, width=64):
        return cls(tuple((name, bit) for bit in range(width)))

    def number(self):
        if all(bit in (0, 1) for bit in self.data):
            return sum(bit << index for index, bit in enumerate(self.data))
        return None

    def resize(self, width):
        return Bits(self.data[:width] + (0,) * max(0, width - len(self.data)))

    def binary(self, op, other):
        require(len(self.data) == len(other.data), "normalization operand width mismatch")
        if op in ("shl", "lshr"):
            shift = other.number()
            require(shift is not None and shift < len(self.data), "unknown/oversized normalization shift")
            if not shift:
                return self
            return Bits((0,) * shift + self.data[:-shift] if op == "shl" else self.data[shift:] + (0,) * shift)
        result = []
        for left, right in zip(self.data, other.data):
            if op == "or":
                bit = 1 if left == 1 or right == 1 else right if left == 0 else left if right == 0 else None
            elif op == "and":
                bit = 0 if left == 0 or right == 0 else right if left == 1 else left if right == 1 else None
            else:
                require(False, "unknown normalization bit operation")
            result.append(bit)
        return Bits(tuple(result))

    def compare(self, op, other):
        require(len(self.data) == len(other.data), "normalization comparison width mismatch")
        left, right = self.number(), other.number()
        if left is None or right is None:
            # Do not infer equality for two unrelated all-unknown words.
            return Bits.unknown(1)
        return Bits.integer(int({"eq": left == right, "ne": left != right,
                                 "uge": left >= right, "ugt": left > right,
                                 "ule": left <= right, "ult": left < right}[op]), 1)


@dataclass(frozen=True)
class Pointer:
    root: str
    offset: int = 0

    def bits(self):
        return Bits.token((self.root, self.offset))


def width(dtype):
    if dtype == "ptr":
        return 64
    integer = re.fullmatch(r"i(1|8|16|32|40|48|64)", dtype)
    if integer:
        return int(integer[1])
    require(dtype in ("<2 x i64>", "{ i8, i8 }"), "unknown normalization type: " + dtype)
    return 128 if dtype.startswith("<") else 16


def unpack(value, dtype):
    require(len(value.data) == width(dtype), "normalization value has wrong extent")
    if dtype != "ptr":
        return value
    first = value.data[0]
    if isinstance(first, tuple) and isinstance(first[0], tuple) and len(first[0]) == 2:
        pointer = Pointer(*first[0])
        if value == pointer.bits():
            return pointer
    return value  # unknown/corrupted pointers remain unusable as addresses


def packed(value):
    return value.bits() if isinstance(value, Pointer) else value


class Memory:
    def __init__(self, sizes):
        self.sizes, self.cells = dict(sizes), {}

    def bounds(self, pointer, count):
        require(isinstance(pointer, Pointer) and pointer.root in self.sizes and pointer.offset >= 0
                and 0 <= count <= self.sizes[pointer.root] - pointer.offset, "unbound/out-of-bounds normalization memory")

    def store(self, pointer, value):
        value = packed(value)
        require(isinstance(value, Bits) and len(value.data) % 8 == 0, "invalid normalization store width")
        self.bounds(pointer, len(value.data) // 8)
        for index in range(0, len(value.data), 8):
            self.cells[(pointer.root, pointer.offset + index // 8)] = value.data[index:index + 8]

    def load(self, pointer, dtype):
        count = width(dtype) // 8
        self.bounds(pointer, count)
        bits = tuple(bit for byte in range(pointer.offset, pointer.offset + count)
                     for bit in self.cells.get((pointer.root, byte), (None,) * 8))
        return unpack(Bits(bits), dtype)

    def invalidate(self, root):
        self.cells = {key: value for key, value in self.cells.items() if key[0] != root}
