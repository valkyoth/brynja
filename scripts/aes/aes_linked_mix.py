"""Bounded final-linked mix review, including actual ELF constant-pool bytes.

RIP displacements are masked in the encoding digest, after validating
their encoding, decoded destination and read-only file-backed mapping. Constants
replace those operands in the text digest. The substitution checker additionally
uses explicitly bound direct-call targets; mix itself admits no calls through
its pinned policy. No automatic policy refresh.
"""
import hashlib
import re
import struct


def require(condition, message):
    if not condition:
        raise ValueError('AES linked mix: ' + message)


def segments(image):
    require(len(image) >= 64 and image[:7] == b'\x7fELF\x02\x01\x01', 'unsupported ELF header')
    kind, machine, version = struct.unpack_from('<HHI', image, 16)
    phoff = struct.unpack_from('<Q', image, 32)[0]
    ehsize, entsize, count = struct.unpack_from('<HHH', image, 52)
    require(kind in (2, 3) and machine == 62 and version == 1 and ehsize == 64
            and entsize == 56 and 0 < count < 65535 and phoff >= 64
            and phoff + count * entsize <= len(image), 'invalid ELF program table')
    loads = []
    for index in range(count):
        ptype, flags, offset, address, _, filesz, memsz, _ = struct.unpack_from(
            '<IIQQQQQQ', image, phoff + index * entsize)
        if ptype != 1:
            continue
        require(filesz <= memsz and offset + filesz <= len(image)
                and address + memsz < 2**64, 'invalid ELF load extent')
        loads.append((address, memsz, offset, filesz, flags))
    loads.sort()
    require(loads and all(a[0] + a[1] <= b[0] for a, b in zip(loads, loads[1:])),
            'missing/overlapping ELF loads')
    return loads


def file_offset(loads, address, size, flags):
    require(type(address) is int and type(size) is int and address >= 0 and size > 0
            and address + size < 2**64, 'invalid mapped range')
    matches = [offset + address - base for base, _, offset, filesz, mode in loads
               if base <= address and address + size <= base + filesz and mode == flags]
    require(len(matches) == 1, 'range lacks unique file-backed mapping with required permissions')
    return matches[0]


def observe(lines, raw, sizes, symbol, start, image, call_targets=None, indirect_callback=None):
    require(len(lines) == len(sizes) and lines and all(type(n) is int and 1 <= n <= 15 for n in sizes)
            and sum(sizes) == len(raw), 'invalid instruction partition')
    loads = segments(image)
    offset = file_offset(loads, start, len(raw), 5)
    require(image[offset:offset + len(raw)] == raw, 'decoded bytes differ from executable')
    targets = call_targets or {}
    # Only the separately pinned caller-cleanup fixture may admit one opaque
    # callback, loaded from its public function-pointer argument. All AES helper
    # reviews leave this disabled. The exact caller stream binds that dataflow.
    callback_encodings = {'callq *(%rsp)': b'\xff\x14\x24',
                          'callq *8(%rsp)': b'\xff\x54\x24\x08'}
    require(indirect_callback is None or indirect_callback in callback_encodings,
            'unsupported callback operand')
    callbacks = 0
    for name, address, size in targets.values():
        require(isinstance(name, str) and name and type(size) is int and size > 0,
                'invalid call target')
        file_offset(loads, address, size, 5)
        require(address + size <= start or start + len(raw) <= address, 'overlapping call target')
    require(len({row[0] for row in targets.values()}) == len(targets), 'ambiguous call targets')
    boundaries, cursor = set(), 0
    for length in sizes:
        boundaries.add(cursor)
        cursor += length
    normalized, encoded, constants, calls, cursor = [], bytearray(raw), [], 0, 0
    for line, length in zip(lines, sizes):
        instruction = raw[cursor:cursor + length]
        if '%rip' in line:
            match = re.fullmatch(r'(movdqa|movd|pand|pxor) (-?\d+)\(%rip\), %xmm(\d+) # 0x([0-9a-f]+) <[^>]+>', line)
            require(match is not None, 'unsupported RIP operand')
            op, displacement, register, target = match.groups()
            register, target = int(register), int(target, 16)
            require(register < 16, 'invalid vector register')
            # These exact SSE encodings have a final signed disp32, no immediate.
            opcode = {'movdqa': 0x6f, 'movd': 0x6e, 'pand': 0xdb, 'pxor': 0xef}[op]
            prefix = b'\x66' + (b'\x44' if register >= 8 else b'')
            prefix += bytes((0x0f, opcode, 5 | ((register % 8) << 3)))
            require(instruction[:-4] == prefix and length == len(prefix) + 4,
                    'RIP encoding/operand mismatch')
            delta = int.from_bytes(instruction[-4:], 'little', signed=True)
            require(delta == int(displacement) and target == start + cursor + length + delta,
                    'RIP destination mismatch')
            width = 4 if op == 'movd' else 16
            pos = file_offset(loads, target, width, 4)
            constant = image[pos:pos + width].hex()
            constants.append((pos, width))
            normalized.append(f'{op} @constant[{constant}], %xmm{register}')
            encoded[cursor + length - 4:cursor + length] = b'\0' * 4
        elif line.startswith(('je ', 'jne ', 'ja ', 'jbe ', 'jb ', 'jae ', 'jmp ')):
            match = re.fullmatch(r'(je|jne|ja|jbe|jb|jae|jmp) 0x([0-9a-f]+) <' + re.escape(symbol) + r'\+0x([0-9a-f]+)>', line)
            require(match is not None, 'unsupported branch annotation')
            op = match[1]
            target, relative = int(match[2], 16), int(match[3], 16)
            short, near = {'je': (b'\x74', b'\x0f\x84'), 'jne': (b'\x75', b'\x0f\x85'),
                           'ja': (b'\x77', b'\x0f\x87'), 'jbe': (b'\x76', b'\x0f\x86'),
                           'jb': (b'\x72', b'\x0f\x82'), 'jae': (b'\x73', b'\x0f\x83'),
                           'jmp': (b'\xeb', b'\xe9')}[op]
            width, prefix = (1, short) if length == 2 else (4, near)
            require(instruction[:-width] == prefix and length == len(prefix) + width
                    and target == start + relative and relative in boundaries
                    and target == start + cursor + length + int.from_bytes(instruction[-width:], 'little', signed=True),
                    'branch destination mismatch')
            normalized.append(f'{op} @+{relative:x}')
        elif indirect_callback is not None and line == indirect_callback:
            require(instruction == callback_encodings[line], 'callback encoding/operand mismatch')
            normalized.append(line)
            callbacks += 1
        elif line.startswith('call'):
            match = re.fullmatch(r'callq 0x([0-9a-f]+) <([^>]+)>', line)
            require(match is not None and instruction[:1] == b'\xe8' and length == 5,
                    'unsupported call encoding/operand')
            target, name = int(match[1], 16), match[2]
            matches = [role for role, row in targets.items() if row[0] == name and row[1] == target]
            require(len(matches) == 1 and target == start + cursor + length
                    + int.from_bytes(instruction[1:], 'little', signed=True), 'call destination mismatch')
            normalized.append('callq @' + matches[0])
            encoded[cursor + 1:cursor + length] = b'\0' * 4
            calls += 1
        else:
            normalized.append(line)
        cursor += length
    actual = {'instructions': len(lines), 'symbol_bytes': len(raw), 'constant_loads': len(constants),
              'text_sha256': hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest(),
              'encoding_sha256': hashlib.sha256(encoded).hexdigest()}
    if call_targets is not None:
        actual['calls'] = calls
    if indirect_callback is not None:
        require(callbacks == 1, 'callback population changed')
        actual['indirect_calls'] = callbacks
    return actual, constants


# Explicitly inspected streams: see docs/assurance/aes-linked-review.md.
POLICY = {
    '1.90.0': {'instructions': 303, 'symbol_bytes': 1381, 'constant_loads': 13,
               'text_sha256': '663c16e6328f407ca7d35a8b00ffe8a5e24655c52284f117f95ed2692ed8e32d',
               'encoding_sha256': '850cf6a6c966410cb7eb2267bd3529499088e06ebac21500feada143a0973f8e'},
    '1.99.1': {'instructions': 275, 'symbol_bytes': 1271, 'constant_loads': 6,
               'text_sha256': '0f358899854427517a1316abb77f8c7cd3f6374283dd87c449c2b504c5299150',
               'encoding_sha256': '57b08132f2f5d157431610e5cd5aae652ed2bcd9aa0045b7d169f040325d972e'},
}


def check(lines, raw, sizes, symbol, start, image, compiler):
    require(compiler in POLICY, 'unreviewed compiler')
    actual, _ = observe(lines, raw, sizes, symbol, start, image)
    require(actual == POLICY[compiler], 'reviewed mix changed; explicit re-review required')
    return {'role': 'mix', **actual}


def mutations(lines, raw, sizes, symbol, start, image, compiler):
    _, constants = observe(lines, raw, sizes, symbol, start, image)
    require(constants, 'missing constants')
    changed = list(lines)
    changed[0] = 'movb (%rdi,%rax), %al'
    rip = next(i for i, line in enumerate(lines) if '%rip' in line)
    bad_target = list(lines)
    bad_target[rip] = re.sub(r'# 0x[0-9a-f]+', '# 0x0', bad_target[rip])
    branch = next(i for i, line in enumerate(lines) if line.startswith('je '))
    bad_branch = list(lines)
    bad_branch[branch] = re.sub(r'0x[0-9a-f]+', '0x0', bad_branch[branch], count=1)
    constant_image = bytearray(image)
    constant_image[constants[0][0]] ^= 1
    code_image = bytearray(image)
    pos = file_offset(segments(image), start, len(raw), 5)
    code_image[pos] ^= 1
    cases = [(changed, raw, image, 'reviewed mix changed'),
             (bad_target, raw, image, 'RIP destination mismatch'),
             (bad_branch, raw, image, 'branch destination mismatch'),
             (lines, raw, bytes(constant_image), 'reviewed mix changed'),
             (lines, raw, bytes(code_image), 'decoded bytes differ'),
             (lines, bytes([raw[0] ^ 1]) + raw[1:], image, 'decoded bytes differ'),
             (lines, bytes([raw[0] ^ 1]) + raw[1:], bytes(code_image), 'reviewed mix changed')]
    for text, code, executable, reason in cases:
        try:
            check(text, code, sizes, symbol, start, executable, compiler)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES linked mix mutation accepted')
    return len(cases)
