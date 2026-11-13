"""Exact linked RV64 clearing templates; not a spill-erasure proof.

The only relocation allowed is an AUIPC/JALR tail transfer to the separately
checked volatile clearing body. No instruction bytes are masked or ignored.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('cleanup_machine', Path(__file__).with_name('aes_riscv_machine.py'))
machine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(machine)

require = machine.require

# MSRV: if len == 0 return; next = ptr+1; len--; *ptr = 0;
#       ptr = next; repeat while len != 0; return.
# Current: if len == 0 return; end = ptr+len; next = ptr+1;
#          *ptr = 0; ptr = next; repeat while next != end; return.
# Both require the Rust caller's valid, non-wrapping writable slice contract.
CLEAR = {
    '1.90.0': bytes.fromhex('81c913061500fd15230005003285f5f98280'),
    '1.99.1': bytes.fromhex('89c9aa9513061500230005003285e31bb6fe8280'),
}


def tail(source, target):
    """Encode AUIPC t1,hi; JALR zero,lo(t1), including signed low rounding."""
    require(source >= 0 and target >= 0 and not (source | target) & 1,
            'unaligned cleanup transfer')
    delta = target - source
    high = (delta + 0x800) >> 12
    low = delta - (high << 12)
    require(-(1 << 19) <= high < (1 << 19), 'cleanup transfer out of range')
    return (((high & 0xfffff) << 12) | 0x317).to_bytes(4, 'little') + (
        ((low & 0xfff) << 20) | 0x30067).to_bytes(4, 'little')


def destroy(compiler, panic, address, clear):
    require(compiler in CLEAR and panic in ('abort', 'unwind'), 'unknown cleanup profile')
    if (compiler, panic) == ('1.99.1', 'unwind'):
        # Branch on explicit-clear flag a2. Both choices test the Option slice
        # pointer a0; non-null owners tail-call clear with unchanged a0/a1.
        # Null owners return. No secret data, stack, or indirect callback read.
        return (bytes.fromhex('11c611c9') + tail(address + 4, clear)
                + bytes.fromhex('09c5') + tail(address + 14, clear) + bytes.fromhex('8280'))
    # Explicit clear/drop merged by LTO: null owner returns, otherwise tail-clear.
    return bytes.fromhex('09c5') + tail(address + 2, clear) + bytes.fromhex('8280')


def select(nm):
    suffix = r'(?:17h[0-9a-f]{16}E)?$'
    patterns = {
        'clear': r'11brynja_core22secret_memory_volatile23zeroize_region_volatile' + suffix,
        'block': r'30brynja_aes_accelerated_fixture9lifecycle13destroy_block' + suffix,
        'key': r'30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key' + suffix,
    }
    rows = {}
    for line in nm.splitlines():
        if not ('zeroize_region_volatile' in line or ('lifecycle' in line and 'destroy_' in line)):
            continue
        fields = line.split()
        require(len(fields) == 4, 'malformed cleanup symbol')
        address, size, kind, symbol = fields
        roles = [role for role, pattern in patterns.items() if re.search(pattern, symbol)]
        require(len(roles) == 1 and kind in ('t', 'T'), 'unexpected cleanup symbol')
        role = roles[0]
        require(role not in rows, 'duplicate cleanup role')
        address, size = int(address, 16), int(size, 16)
        require(address > 0 and address % 2 == 0 and 0 < size <= 24, 'invalid cleanup extent')
        rows[role] = (address, size, symbol)
    require(set(rows) == set(patterns), 'incomplete cleanup population')
    extents = sorted((a, a + size) for a, size, _ in rows.values())
    require(all(end <= start for (_, end), (start, _) in zip(extents, extents[1:])),
            'overlapping cleanup bodies')
    return rows


def inspect(nm, image, compiler, panic):
    require(compiler in CLEAR and panic in ('abort', 'unwind'), 'unknown cleanup profile')
    rows = select(nm)
    reports = []
    for role, (address, size, symbol) in rows.items():
        offset = machine.mapped(image, address, size)
        raw = image[offset:offset + size]
        expected = CLEAR[compiler] if role == 'clear' else destroy(compiler, panic, address, rows['clear'][0])
        require(raw == expected, 'cleanup template mismatch: ' + role)
        reports.append({'role': role, 'symbol': symbol, 'address': address, 'size': size,
                        'body_sha256': hashlib.sha256(raw).hexdigest()})
    return {'bodies': reports, 'scope': 'volatile byte clearing and two retained destruction bodies only; '
            'not all callsites, constructors, output staging, exception tables, or compiler spills'}
