"""Bounded full-memory dump reader for synthetic Windows protection probes.

Inspect only specified virtual address ranges, never search the whole dump for
a marker that might also occur in an ordinary Python heap or another mapping.
No dump content is returned or logged.
"""
import struct

from windows_protection_probe import require

LIMIT = 512 * 1024 * 1024


def unpack(blob, offset, fmt):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(blob) and size <= len(blob) - offset,
            'truncated minidump structure')
    return struct.unpack_from(fmt, blob, offset)


def memory_ranges(blob):
    require(32 <= len(blob) <= LIMIT, 'bounded minidump size')
    signature, version, streams, directory, _, _, flags = unpack(blob, 0, '<6IQ')
    require(signature == 0x504d444d and version & 0xffff == 0xa793,
            'minidump signature/version')
    require(flags & 2 != 0, 'full-memory minidump required')
    require(0 < streams <= 128 and directory >= 32
            and directory + streams * 12 <= len(blob), 'bounded stream directory')
    lists = []
    for index in range(streams):
        kind, size, offset = unpack(blob, directory + index * 12, '<III')
        require(offset <= len(blob) and size <= len(blob) - offset, 'stream file bounds')
        if kind == 9:  # Memory64ListStream
            lists.append((size, offset))
    require(len(lists) == 1, 'exactly one full-memory range stream')
    size, offset = lists[0]
    require(offset >= directory + streams * 12 and size >= 16, 'memory stream header bounds')
    count, payload = unpack(blob, offset, '<QQ')
    require(0 < count <= 65536 and size == 16 + 16 * count, 'memory descriptor bounds')
    require(offset + size <= payload <= len(blob), 'memory payload must follow descriptors')
    ranges = []
    for index in range(count):
        address, length = unpack(blob, offset + 16 + index * 16, '<QQ')
        require(0 < length and address + length <= 2**64,
                f'virtual range bounds: descriptor={index}; zero_length={length == 0}; '
                f'address_overflow={address + length > 2**64}')
        require(length <= len(blob) - payload, 'memory payload file bounds')
        ranges.append((address, length, payload))
        payload += length
    ordered = sorted(ranges)
    require(all(a + length <= b for (a, length, _), (b, _, _) in zip(ordered, ordered[1:])),
            'overlapping memory descriptors')
    return ranges


def observe(blob, address, size, value):
    require(type(address) is int and type(size) is int and type(value) is int
            and address >= 0 and 0 < size <= 65536 and address + size <= 2**64
            and 0 <= value <= 255, 'bounded synthetic target')
    included = 0
    matches = True
    for start, length, offset in memory_ranges(blob):
        lower, upper = max(address, start), min(address + size, start + length)
        if lower < upper:
            count = upper - lower
            included += count
            matches &= blob[offset + lower - start:offset + upper - start] == bytes([value]) * count
    # Absent bytes must not become a vacuous marker-matches claim.
    return {'included_bytes': included, 'expected_bytes': size,
            'complete_marker': included == size and matches}
