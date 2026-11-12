"""Bounded final-linked ARM helper review. Policies are never refreshed by a run."""
import hashlib
import json
from pathlib import Path
import re
import struct

POLICY = Path(__file__).with_name('aarch64-linked-review.json')
ROUND_ROLES = tuple(f'{kind}{bits}' for kind in ('expand', 'transform') for bits in (128, 192, 256))
ROLES = ('inverse', 'add_key', 'wide_add_key', 'substitute', 'mix', *ROUND_ROLES, 'zeroize')


def require(condition, message):
    if not condition:
        raise ValueError('AES ARM linked: ' + message)


def segments(image):
    require(len(image) >= 64 and image[:7] == b'\x7fELF\x02\x01\x01', 'invalid ELF header')
    kind, machine, version = struct.unpack_from('<HHI', image, 16)
    offset = struct.unpack_from('<Q', image, 32)[0]
    header, stride, count = struct.unpack_from('<HHH', image, 52)
    require(kind in (2, 3) and machine == 183 and version == 1 and header == 64
            and stride == 56 and 0 < count < 65535 and offset >= 64
            and offset + stride * count <= len(image), 'invalid ARM ELF program table')
    loads = []
    for i in range(count):
        kind, flags, pos, address, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', image, offset + i * stride)
        if kind == 1:
            require(filesz <= memsz and pos + filesz <= len(image) and address + memsz < 2**64,
                    'invalid ELF load extent')
            loads.append((address, memsz, pos, filesz, flags))
    loads.sort()
    require(loads and all(a[0] + a[1] <= b[0] for a, b in zip(loads, loads[1:])),
            'missing/overlapping ELF loads')
    return loads


def mapped(loads, address, size, flags):
    require(type(address) is int and type(size) is int and address >= 0 and size > 0
            and address + size < 2**64, 'invalid mapped extent')
    matches = [pos + address - base for base, _, pos, filesz, mode in loads
               if base <= address and address + size <= base + filesz
               and mode in (flags if isinstance(flags, tuple) else (flags,))]
    require(len(matches) == 1, 'range lacks unique file-backed mapping with required permissions')
    return matches[0]


def decode(assembly, row):
    symbol, start, size = row
    require(size > 0 and size % 4 == 0 and start % 4 == 0, 'unaligned symbol extent')
    require(re.findall(r'file format (\S+)', assembly) == ['elf64-littleaarch64'], 'wrong disassembly target')
    headers = list(re.finditer(r'^([0-9a-f]+) <([^>]+)>:\n', assembly, re.M))
    chosen = [i for i, match in enumerate(headers) if match[2] == symbol]
    require(len(chosen) == 1, 'missing/duplicate symbol header')
    index = chosen[0]
    require(int(headers[index][1], 16) == start, 'symbol address mismatch')
    end = headers[index + 1].start() if index + 1 < len(headers) else len(assembly)
    lines, raw = [], bytearray()
    for line in assembly[headers[index].end():end].splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)', line)
        require(match is not None, 'unrecognized disassembly row')
        require(int(match[1], 16) == start + len(raw) and len(raw) < size, 'noncontiguous/out-of-extent instruction')
        raw.extend(int(match[2], 16).to_bytes(4, 'little'))
        text = ' '.join(match[3].split('//', 1)[0].split())
        text = re.sub(r'#(-?)0x([0-9a-f]+)', lambda m: '#' + m[1] + str(int(m[2], 16)), text)
        lines.append(text)
    require(len(raw) == size, 'incomplete symbol extent')
    return lines, bytes(raw)


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def round_role(lines, symbol):
    if '6expand' in symbol:
        width = re.fullmatch(r'cmp x1, #(16|24|32)', lines[0]) if lines else None
        require(width is not None, 'missing expansion width admission')
        bits, kind = int(width[1]) * 8, 'expand'
    else:
        require('9transform' in symbol, 'unknown round helper')
        offsets = [int(m[1]) for line in lines
                   if (m := re.fullmatch(r'ldr q0, \[x20, #(160|192|224)\]', line))]
        require(len(offsets) == 2 and len(set(offsets)) == 1, 'ambiguous transform width')
        bits, kind = {160: 128, 192: 192, 224: 256}[offsets[0]], 'transform'
    require(('4wide' in symbol) == (bits != 128), 'round symbol/width mismatch')
    if symbol.startswith('_RI'):
        require(('Kj18_Kjd0_Kjc_' if bits == 192 else 'Kj20_Kjf0_Kje_') in symbol,
                'round generic width mismatch')
    return f'{kind}{bits}'


def select(rows, nm, assembly):
    selected = {}
    tokens = {'inverse': '5field7inverse', 'substitute': '10substitute', 'mix': '3mix',
              'add_key': '7add_key', 'wide_add_key': '4wide7add_key'}
    for role, token in tokens.items():
        found = [row for row in rows if token in row[0] and (role != 'add_key' or '4wide' not in row[0])]
        require(len(found) == 1, 'missing/duplicate helper: ' + role)
        selected[role] = found[0]
    for row in rows:
        if '6expand' in row[0] or '9transform' in row[0]:
            role = round_role(decode(assembly, row)[0], row[0])
            require(role not in selected, 'duplicate round helper')
            selected[role] = row
    zero_pattern = (r'(?:_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h[0-9a-f]{16}E'
                    r'|_RNvNtC\w+_11brynja_core22secret_memory_volatile23zeroize_region_volatile)')
    found = re.findall(r'^([0-9a-f]+) ([0-9a-f]+) [tT] (' + zero_pattern + r')$', nm, re.M)
    require(len(found) == 1, 'missing/duplicate exact zeroizer')
    address, size, name = found[0]
    selected['zeroize'] = name, int(address, 16), int(size, 16)
    require(set(selected) == set(ROLES), 'helper population mismatch')
    ordered = sorted(selected.values(), key=lambda row: row[1])
    require(all(size > 0 for _, _, size in ordered)
            and all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping/empty review bodies')
    return selected


def target_roles(role):
    if role == 'substitute':
        return ('inverse',)
    if role.startswith('expand'):
        return ('inverse', 'zeroize')
    if role.startswith('transform'):
        return ('substitute', 'mix', 'add_key' if role == 'transform128' else 'wide_add_key', 'zeroize')
    return ()


def observe(lines, raw, row, image, targets, *, callback=False, tail_calls=()):
    symbol, start, size = row
    require(len(lines) * 4 == len(raw) == size and lines, 'instruction partition changed')
    loads = segments(image)
    pos = mapped(loads, start, size, 5)
    require(image[pos:pos + size] == raw, 'decoded bytes differ from executable')
    normalized, encoded = [], bytearray(raw)
    require(isinstance(tail_calls, tuple) and len(set(tail_calls)) == len(tail_calls)
            and all(role in targets for role in tail_calls), 'invalid tail-call policy')
    pages, constants, calls, branches, indirect, tails = {}, [], 0, 0, 0, 0
    for i, line in enumerate(lines):
        pc = start + i * 4
        word = int.from_bytes(raw[i * 4:i * 4 + 4], 'little')
        if callback and line == 'blr x8':
            require(not pages and word == 0xd63f0100 and indirect == 0,
                    'callback encoding/population mismatch')
            normalized.append(line)
            indirect += 1
            continue
        branch = re.fullmatch(r'(bl|b|b\.(?:hs|ls|hi|lo|eq|ne)|cbn?z [wx](?:[0-9]|[12][0-9]|30)|tbn?z w(?:[0-9]|[12][0-9]|30), #(?:0|24))(?:,)? 0x([0-9a-f]+) <([^>]+)>', line)
        if branch:
            require(not pages, 'control flow crosses pending constant page')
            op, destination, annotation = branch.groups()
            destination = int(destination, 16)
            if op in ('bl', 'b'):
                require(word & 0xfc000000 == (0x94000000 if op == 'bl' else 0x14000000), 'branch encoding mismatch')
                actual = pc + signed(word & 0x3ffffff, 26) * 4
                mask = 0xfc000000
            elif op.startswith('b.'):
                condition = {'b.hs': 2, 'b.lo': 3, 'b.ls': 9, 'b.hi': 8, 'b.eq': 0, 'b.ne': 1}[op]
                require(word & 0xff00001f == 0x54000000 | condition, 'conditional encoding mismatch')
                actual = pc + signed((word >> 5) & 0x7ffff, 19) * 4
                mask = 0xff00001f
            elif op.startswith(('cbz ', 'cbnz ')):
                mnemonic, register = op.split()
                expected = 0x34000000 | (0x80000000 if register[0] == 'x' else 0) | (0x1000000 if mnemonic == 'cbnz' else 0) | int(register[1:])
                require(word & 0xff00001f == expected, 'compare-branch encoding mismatch')
                actual = pc + signed((word >> 5) & 0x7ffff, 19) * 4
                mask = 0xff00001f
            else:
                mnemonic, register, bit = op.replace(',', '').split()
                expected = 0x36000000 | (0x1000000 if mnemonic == 'tbnz' else 0) | (int(bit[1:]) << 19) | int(register[1:])
                require(word & 0xfff8001f == expected, 'test-branch encoding mismatch')
                actual = pc + signed((word >> 5) & 0x3fff, 14) * 4
                mask = 0xfff8001f
            require(actual == destination, 'branch decoded/encoded destination mismatch')
            external_tail = op == 'b' and not start <= destination < start + size
            if op == 'bl' or external_tail:
                matches = [role for role, (name, address, extent) in targets.items()
                           if name == annotation and address == destination and extent > 0]
                require(len(matches) == 1, 'unreviewed call target')
                require(not external_tail or matches[0] in tail_calls, 'unreviewed tail-call target')
                target = targets[matches[0]]
                require(target[1] + target[2] <= start or start + size <= target[1], 'overlapping call target')
                mapped(loads, target[1], target[2], 5)
                normalized.append(op + ' @' + matches[0])
                calls += not external_tail
                tails += external_tail
            else:
                relative = destination - start
                require(0 <= relative < size and relative % 4 == 0
                        and annotation == symbol + (f'+0x{relative:x}' if relative else ''), 'local branch annotation/extent mismatch')
                normalized.append(f'{op} @+{relative // 4}'); branches += 1
            # Local offsets remain in the encoding policy. Only bound external
            # call displacements vary with final link layout.
            if op == 'bl' or external_tail:
                encoded[i * 4:i * 4 + 4] = (word & mask).to_bytes(4, 'little')
            continue
        page = re.fullmatch(r'adrp x(\d+), 0x([0-9a-f]+) <[^>]+>', line)
        if page:
            register, address = int(page[1]), int(page[2], 16)
            require(register < 31 and word & 0x9f00001f == 0x90000000 | register, 'ADRP encoding mismatch')
            immediate = ((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3
            require(address == (pc & ~4095) + signed(immediate, 21) * 4096, 'ADRP destination mismatch')
            require(register not in pages, 'unconsumed constant page')
            pages[register] = (address, i)
            normalized.append(f'adrp x{register}, @page')
            encoded[i * 4:i * 4 + 4] = (word & 0x9f00001f).to_bytes(4, 'little')
            continue
        load = re.fullmatch(r'ldr ([dq])(\d+), \[x(\d+)(?:, #(\d+))?\]', line)
        if load and int(load[3]) in pages:
            kind, vector, register, offset = load.groups()
            vector, register, offset = int(vector), int(register), int(offset or 0)
            width = 8 if kind == 'd' else 16
            require(vector < 32 and word & 0xffc003ff == (0xfd400000 if kind == 'd' else 0x3dc00000) | (register << 5) | vector,
                    'constant load encoding mismatch')
            require(offset == ((word >> 10) & 0xfff) * width, 'constant load offset mismatch')
            address, origin = pages.pop(register)
            # GNU AArch64 links place .rodata in the read/execute load. Both
            # read-only modes are allowed; writable mappings are not.
            const_pos = mapped(loads, address + offset, width, (4, 5))
            constant = image[const_pos:const_pos + width].hex()
            constants.append((const_pos, width))
            normalized.append(f'ldr {kind}{vector}, [x{register}, @constant[{constant}]; page@{origin}]')
            encoded[i * 4:i * 4 + 4] = (word & 0xffc003ff).to_bytes(4, 'little')
            continue
        # Pending page bases must not be modified, read as data, or crossed by
        # control flow before their sole constant load. Templates additionally
        # bind every instruction between the page and load.
        for register in pages:
            require(not re.search(r'\b[wx]' + str(register) + r'\b', line), 'constant base used/clobbered before load')
        require(not re.search(r'\b(?:0x[0-9a-f]+|adr|adrp|bl|blr|br|cbz|cbnz|tbz|tbnz|b\.[a-z]+)\b', line)
                and not line.startswith('b ') and '<' not in line, 'unbound control/address instruction')
        normalized.append(line)
    require(not pages, 'unconsumed constant page')
    require(not callback or indirect == 1, 'missing reviewed callback')
    result = {'instructions': len(lines), 'branches': branches, 'calls': calls,
            'constants': len(constants), 'text_sha256': hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest(),
            'encoding_sha256': hashlib.sha256(encoded).hexdigest()}
    if callback:
        result['indirect_calls'] = indirect
    if tail_calls:
        result['tail_calls'] = tails
    return result, constants, normalized


def check(lines, raw, row, image, targets, role, compiler, policy=None, *, panic='abort'):
    policy = json.loads(POLICY.read_text()) if policy is None else policy
    require(set(policy) == {'schema', 'target', 'profile', 'review', 'compilers'}
            and policy['schema'] == 1 and policy['target'] == 'aarch64-unknown-linux-gnu'
            and policy['profile'] == 'opt3-fat-lto-cgu1-overflow'
            and policy['review'] == 'docs/assurance/aes-aarch64-linked-review.md'
            and set(policy['compilers']) == {'1.90.0', '1.99.1'}, 'review scope changed')
    require(panic in ('abort', 'unwind') and compiler in policy['compilers'] and role in ROLES
            and all(set(rows) == set(ROLES) for rows in policy['compilers'].values()), 'unreviewed helper/compiler')
    require(set(targets) == set(target_roles(role)), 'call target population changed')
    if role in ROUND_ROLES:
        require(round_role(lines, row[0]) == role, 'round role mismatch')
    actual, _, _ = observe(lines, raw, row, image, targets)
    expected = policy['compilers'][compiler][role]
    # Only the MSRV expansion epilogue changes with the panic profile.
    if compiler == '1.90.0' and role.startswith('expand'):
        require(set(expected) == {'abort', 'unwind'}, 'missing expansion panic policies')
        expected = expected[panic]
    require(actual == expected, 'instruction/encoding/constant policy changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, row, image, targets, role, compiler, *, panic='abort'):
    check(lines, raw, row, image, targets, role, compiler, panic=panic)
    _, constants, _ = observe(lines, raw, row, image, targets)
    pos = mapped(segments(image), row[1], row[2], 5)
    altered_raw = bytes([raw[0] ^ 1]) + raw[1:]
    altered_image = image[:pos] + altered_raw + image[pos + len(raw):]
    text = list(lines); text[0] = 'eor w0, w0, w1'
    cases = [(lines[:-1], raw, image, targets), (text, raw, image, targets),
             (lines, altered_raw, image, targets), (lines, raw, altered_image, targets),
             (lines, altered_raw, altered_image, targets)]
    branch = next((i for i, line in enumerate(lines) if re.match(r'(?:b\.|cbn?z |tbn?z |b )', line)), None)
    if branch is not None:
        changed = list(lines)
        changed[branch] = re.sub(r'0x[0-9a-f]+', '0x0', changed[branch], count=1)
        cases.append((changed, raw, image, targets))
    for role_name, (name, address, extent) in targets.items():
        changed_targets = dict(targets)
        changed_targets[role_name] = (name, address + 4, extent)
        cases.append((lines, raw, image, changed_targets))
    if role in ROUND_ROLES:
        clear = next(i for i, line in enumerate(lines) if line.endswith('<' + targets['zeroize'][0] + '>'))
        pointer = max(i for i in range(clear) if lines[i] == ('sub x0, x29, #4' if role.startswith('expand') else 'add x0, sp, #16'))
        length = max(i for i in range(clear) if lines[i] == ('mov w1, #4' if role.startswith('expand') else 'mov w1, #16'))
        bound = next(i for i, line in enumerate(lines) if i > 1 and line.startswith(('cmp ', 'adds ')))
        for index, replacement in ((clear, 'nop'), (pointer, 'mov x0, x3'),
                                   (length, 'mov w1, #0'), (bound, 'cmp x0, #0')):
            changed = list(lines); changed[index] = replacement
            cases.append((changed, raw, image, targets))
    if constants:
        pos, _ = constants[0]
        changed = image[:pos] + bytes([image[pos] ^ 1]) + image[pos + 1:]
        cases.append((lines, raw, changed, targets))
        changed = list(lines)
        index = next(i for i, line in enumerate(lines) if line.startswith('adrp '))
        changed[index] = re.sub(r'0x[0-9a-f]+', '0x0', changed[index], count=1)
        cases.append((changed, raw, image, targets))
    for changed_lines, changed_raw, changed_image, changed_targets in cases:
        try:
            check(changed_lines, changed_raw, row, changed_image, changed_targets, role, compiler, panic=panic)
        except ValueError:
            pass
        else:
            raise ValueError('AES ARM linked mutation accepted: ' + role)
    return len(cases)
