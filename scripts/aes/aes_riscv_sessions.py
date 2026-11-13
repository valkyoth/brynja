"""Reviewed RV64 block-session bodies and their bound leaf/import call edges.

Exact bytes for the two compiler endpoints, not a general Rust ABI, startup
review, exception-table proof, fault detector, or timing qualification.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct

SPEC = importlib.util.spec_from_file_location('sessions_machine', Path(__file__).with_name('aes_riscv_machine.py'))
machine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(machine)
require = machine.require


def call(source, target):
    """AUIPC ra,hi; JALR ra,lo(ra), binding all register/opcode/immediate bits."""
    require(0 <= source < 2**64 and 0 <= target < 2**64 and not (source | target) & 1,
            'invalid session call address')
    high = (target - source + 0x800) >> 12
    low = target - source - (high << 12)
    require(-(1 << 19) <= high < (1 << 19), 'session call out of range')
    return (((high & 0xfffff) << 12) | 0x97).to_bytes(4, 'little') + (
        ((low & 0xfff) << 20) | 0x80e7).to_bytes(4, 'little')


def call_target(raw, source):
    require(len(raw) == 8, 'truncated session call')
    high, low = struct.unpack('<II', raw)
    require(high & 0xfff == 0x97 and low & 0xfffff == 0x80e7, 'unexpected session call encoding')
    target = source + machine.signed(high & 0xfffff000, 32) + machine.signed(low >> 20, 12)
    require(call(source, target) == raw, 'noncanonical session call')
    return target


def template(compiler, panic, direction, address, kernel, resume=None):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and direction in ('encrypt', 'decrypt'), 'unreviewed session profile')
    landing = (compiler, panic) == ('1.90.0', 'unwind')
    require((resume is not None) == landing, 'wrong session resume population')
    if landing:
        # s0 saves owner, s1 generation. Precheck health/generation/kernel;
        # preserve state/schedule pointers and supply the public direction.
        prefix = '011106ec22e826e42a840345850021c1ae8485456317b50208606390a4040345940089456361b504'
        prefix += '3285b6850146' if direction == 'encrypt' else '32850546b685'
        # Normal paths: postcheck, return discriminant, or terminal quarantine.
        # Landing pad: quarantine unless already terminal, preserving exception
        # pointer a0, then resume unwinding. Dispatch tables remain out of scope.
        suffix = ('0345840005cd8945631cb5021545e2604264a26405618280'
                  '1145e2604264a264056182801945e2604264a26405618280'
                  '0545e2604264a26405618280114505a00860639da40083459400'
                  '05456379b5002145e2604264a26405618280194589450d4610e0'
                  '2304b400e2604264a264056182800346840089456306b600'
                  '0d4610e02304b400')
    else:
        # s0 saves generation, s1 owner. Only the admitted RISC-V kernel enum
        # value 2 passes; MSRV uses >=2 under Rust's valid-enum precondition.
        if direction == 'encrypt':
            prefix = '0347850031c785476316f70418616395e504034795008947'
            prefix += '6362f704' if compiler == '1.90.0' else '6312f704'
            prefix += '011106ec22e826e42e84aa843285b6850146'
        else:
            prefix = '0347850039c785476317f70418616396e504034795008947'
            prefix += '6363f704' if compiler == '1.90.0' else '6313f704'
            prefix += '011106ec22e826e42e84b2850546aa842e85b685'
        suffix = ('a68503c5840015c109466312c5021545e2604264a26405618280'
                  '114582801545828019458280054582801145')
        if compiler == '1.90.0':
            suffix += '05a08861631da40003c6950005456379c5002145e2604264a264056182801945'
        else:
            suffix += '1da08861631ea40003c595000946631bc5001305f00fe2604264a26405618280194511a00545'
        suffix += '09468d4694e12384c500e2604264a26405618280'
    raw = bytes.fromhex(prefix)
    raw += call(address + len(raw), kernel) + bytes.fromhex(suffix)
    if landing:
        raw += call(address + len(raw), resume)
    return raw


def select(nm):
    operation = r'7Session10(encrypt|decrypt)(128|192|256)'
    legacy = r'_ZN17brynja_crypto_cpu3aes' + operation + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtC\w+_17brynja_crypto_cpu3aesNtB[0-9a-z]+_' + operation
    rows = {}
    for line in nm.splitlines():
        if not ('17brynja_crypto_cpu3aes' in line and '7Session' in line
                and any(d in line for d in ('encrypt', 'decrypt'))):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'malformed session symbol row')
        match = re.fullmatch(legacy, row[3]) or re.fullmatch(current, row[3])
        require(match is not None, 'unexpected session symbol')
        role = match[1], int(match[2])
        require(role not in rows, 'duplicate session role')
        address, size = int(row[1], 16), int(row[2], 16)
        require(address > 0 and address % 2 == 0 and 0 < size <= 194, 'invalid session extent')
        rows[role] = (row[3], address, size)
    require(set(rows) == {(d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)},
            'incomplete session population')
    return rows


def load_offset(image, address, length, flags):
    """After machine.mapped validates the ELF, bind data to its live PT_LOAD."""
    require(address >= 0 and 0 < length <= 1 << 20 and address + length < 2**64,
            'invalid import extent')
    offset = struct.unpack_from('<Q', image, 32)[0]
    count = struct.unpack_from('<H', image, 56)[0]
    matches = []
    for i in range(count):
        kind, access, pos, base, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', image, offset + 56*i)
        if kind == 1 and access in flags and base <= address and address + length <= base + size:
            matches.append(pos + address - base)
    require(len(matches) == 1, 'import lacks unique live mapping')
    return matches[0]


def runtime_import(image, address, expected_name):
    """Bind an allowed RV64 import stub to PT_DYNAMIC's actual named slot.

    The loader, resolved runtime implementation and exception tables are trusted.
    Section names and disassembler labels are not used as import authority.
    """
    require(expected_name in ('_Unwind_Resume', 'memcpy', 'memset', 'bcmp'), 'unreviewed runtime import')
    pos = machine.mapped(image, address, 16)  # Validates all program/load extents.
    high, load, jump, nop = struct.unpack_from('<IIII', image, pos)
    require(high & 0xfff == 0xe17 and load & 0xfffff == 0xe3e03
            and jump == 0xe0367 and nop == 0x13, 'unreviewed resume stub')
    slot = address + machine.signed(high & 0xfffff000, 32) + machine.signed(load >> 20, 12)
    require(slot % 8 == 0, 'unaligned resume slot')
    load_offset(image, slot, 8, (6,))
    offset = struct.unpack_from('<Q', image, 32)[0]
    count = struct.unpack_from('<H', image, 56)[0]
    dynamic = [struct.unpack_from('<IIQQQQQQ', image, offset + 56*i) for i in range(count)
               if struct.unpack_from('<I', image, offset + 56*i)[0] == 2]
    require(len(dynamic) == 1, 'missing/ambiguous dynamic table')
    _, flags, pos, base, _, length, memory, _ = dynamic[0]
    require(flags == 6 and 0 < length <= memory and length % 16 == 0
            and load_offset(image, base, length, (6,)) == pos, 'invalid dynamic table')
    tags, ended = {}, False
    needed = {2, 5, 6, 10, 11, 20, 23}
    for i in range(pos, pos + length, 16):
        tag, value = struct.unpack_from('<qQ', image, i)
        if ended or tag == 0:
            require(tag == value == 0, 'nonzero trailing dynamic entry')
            ended = True
        elif tag in needed:
            require(tag not in tags, 'duplicate import dynamic tag')
            tags[tag] = value
    require(ended and set(tags) == needed and tags[11] == 24 and tags[20] == 7
            and tags[2] % 24 == 0, 'incomplete/invalid import dynamic tags')
    reloc = load_offset(image, tags[23], tags[2], (4, 5))
    strings = load_offset(image, tags[5], tags[10], (4, 5))
    text = image[strings:strings + tags[10]]
    slots, found = set(), []
    for i in range(reloc, reloc + tags[2], 24):
        target, info, addend = struct.unpack_from('<QQq', image, i)
        index, kind = info >> 32, info & 0xffffffff
        require(kind == 5 and addend == 0 and index > 0 and target % 8 == 0
                and target not in slots, 'invalid/duplicate RV64 jump-slot relocation')
        slots.add(target)
        load_offset(image, target, 8, (6,))
        symbol = load_offset(image, tags[6] + index*24, 24, (4, 5))
        name, binding, visibility, section, value, _ = struct.unpack_from('<IBBHQQ', image, symbol)
        require(name < len(text), 'invalid import name offset')
        end = text.find(b'\0', name)
        require(end >= 0, 'unterminated import name')
        if text[name:end] == expected_name.encode('ascii'):
            require(binding == 0x12 and visibility == section == value == 0,
                    'resume is not an undefined global function')
            found.append(target)
    require(found == [slot], 'resume stub/import binding mismatch')
    return {'name': expected_name, 'address': address, 'slot': slot, 'size': 16,
            'scope': 'live import binding only; loader, runtime and exception tables trusted'}


def resume_import(image, address):
    return runtime_import(image, address, '_Unwind_Resume')


def check_body(image, address, size, compiler, panic, direction, kernel, resume):
    pos = machine.mapped(image, address, size)
    raw = image[pos:pos + size]
    require(raw == template(compiler, panic, direction, address, kernel, resume),
            'session template mismatch')
    return hashlib.sha256(raw).hexdigest()


def inspect(nm, image, compiler, panic):
    # Recheck the actual kernel bytes, not a caller-supplied width assertion.
    kernels = machine.inspect(nm, image)['kernels']
    symbols = {name: (address, size) for name, address, size, _, _ in machine.select(nm)}
    bound = {r['bits']: symbols[r['symbol']] for r in kernels if r['kind'] == 'transform'}
    rows = select(nm)
    runtime = None
    if (compiler, panic) == ('1.90.0', 'unwind'):
        _, address, size = rows['encrypt', 128]
        require(size == 194, 'wrong unwinding session extent')
        pos = machine.mapped(image, address, size)
        target = call_target(image[pos + 186:pos + 194], address + 186)
        runtime = resume_import(image, target)
    extents = [(a, a + size) for a, size in symbols.values()]
    extents += [(a, a + size) for _, a, size in rows.values()]
    if runtime:
        extents.append((runtime['address'], runtime['address'] + 16))
    extents.sort()
    require(all(end <= start for (_, end), (start, _) in zip(extents, extents[1:])),
            'overlapping session/kernel/runtime bodies')
    reports = []
    for (direction, bits), (symbol, address, size) in sorted(rows.items()):
        digest = check_body(image, address, size, compiler, panic, direction, bound[bits][0],
                            runtime['address'] if runtime else None)
        reports.append({'bits': bits, 'direction': direction, 'symbol': symbol,
                        'address': address, 'size': size, 'kernel_address': bound[bits][0],
                        'body_sha256': digest})
    return {'sessions': reports, 'resume_import': runtime,
            'scope': 'six block-session entry/postchecks, direction and matched-width leaf calls; '
                     'not constructor/startup, expansion callers, output staging, exception dispatch, '
                     'spill erasure, native admission or timing'}
