"""Exact ELF kernel instruction/encoding review, not whole-consumer CT proof.

Templates are reviewed instruction by instruction in the accompanying assurance
note. No instruction, register, loop bound, branch target or erasure is wildcarded.
Only the public schedule extent differs between the three concrete widths.
"""
import hashlib
import re
import struct

TARGETS = {'x86_64-unknown-linux-gnu': (62, 'elf64-x86-64', '3x86'),
           'aarch64-unknown-linux-musl': (183, 'elf64-littleaarch64', '7aarch64')}


def require(condition, message):
    if not condition:
        raise ValueError('AES accelerated linked kernels: ' + message)


def template(target, bits):
    require(target in TARGETS and bits in (128, 192, 256), 'unreviewed target/width')
    last = {128: 160, 192: 192, 256: 224}[bits]
    if target.startswith('x86'):
        rows = [
            ('89d1', 'movl %edx, %ecx'),
            ('ba' + last.to_bytes(4, 'little').hex(), f'movl ${last}, %edx'),
            ('f30f6f07', 'movdqu (%rdi), %xmm0'),
            ('4885c9', 'testq %rcx, %rcx'), ('752e', 'jne @+3e'),
            ('f30f6f0e', 'movdqu (%rsi), %xmm1'), ('660fefc1', 'pxor %xmm1, %xmm0'),
            ('48c7c010000000', 'movq $16, %rax'),
            ('f30f6f0c06', 'movdqu (%rsi,%rax), %xmm1'), ('660f38dcc1', 'aesenc %xmm1, %xmm0'),
            ('4883c010', 'addq $16, %rax'), ('4839d0', 'cmpq %rdx, %rax'), ('75ed', 'jne @+1f'),
            ('f30f6f0c06', 'movdqu (%rsi,%rax), %xmm1'), ('660f38ddc1', 'aesenclast %xmm1, %xmm0'),
            ('eb2e', 'jmp @+6c'), ('4889d0', 'movq %rdx, %rax'),
            ('f30f6f0c06', 'movdqu (%rsi,%rax), %xmm1'), ('660fefc1', 'pxor %xmm1, %xmm0'),
            ('4883e810', 'subq $16, %rax'), ('f30f6f0c06', 'movdqu (%rsi,%rax), %xmm1'),
            ('660f38dbc9', 'aesimc %xmm1, %xmm1'), ('660f38dec1', 'aesdec %xmm1, %xmm0'),
            ('4883f810', 'cmpq $16, %rax'), ('75e7', 'jne @+4a'),
            ('f30f6f0e', 'movdqu (%rsi), %xmm1'), ('660f38dfc1', 'aesdeclast %xmm1, %xmm0'),
            ('f30f7f07', 'movdqu %xmm0, (%rdi)'), ('660fefc0', 'pxor %xmm0, %xmm0'),
            ('660fefc9', 'pxor %xmm1, %xmm1'), ('31c0', 'xorl %eax, %eax'), ('c3', 'retq')]
    else:
        words = [
            (0x2a0203e8, 'mov w8, w2'), (0x5280000b | (last << 5), f'mov w11, #{last}'),
            (0x3dc00000, 'ldr q0, [x0]'), (0xb50001c8, 'cbnz x8, @+44'),
            (0xd2800009, 'mov x9, #0'), (0xd100416a, 'sub x10, x11, #16'),
            (0x3ce96821, 'ldr q1, [x1, x9]'), (0x4e284820, 'aese v0.16b, v1.16b'),
            (0x4e286800, 'aesmc v0.16b, v0.16b'), (0x91004129, 'add x9, x9, #16'),
            (0xeb0a013f, 'cmp x9, x10'), (0x54ffff61, 'b.ne @+18'),
            (0x3ce96821, 'ldr q1, [x1, x9]'), (0x4e284820, 'aese v0.16b, v1.16b'),
            (0x3ceb6821, 'ldr q1, [x1, x11]'), (0x6e211c00, 'eor v0.16b, v0.16b, v1.16b'),
            (0x1400000f, 'b @+7c'), (0xaa0b03e9, 'mov x9, x11'),
            (0x3ce96821, 'ldr q1, [x1, x9]'), (0x4e285820, 'aesd v0.16b, v1.16b'),
            (0x4e287800, 'aesimc v0.16b, v0.16b'), (0xd1004129, 'sub x9, x9, #16'),
            (0x3ce96821, 'ldr q1, [x1, x9]'), (0x4e287821, 'aesimc v1.16b, v1.16b'),
            (0x4e285820, 'aesd v0.16b, v1.16b'), (0xf100413f, 'cmp x9, #16'),
            (0x54000060, 'b.eq @+74'), (0x4e287800, 'aesimc v0.16b, v0.16b'),
            (0x17fffff9, 'b @+54'), (0x3dc00021, 'ldr q1, [x1]'),
            (0x6e211c00, 'eor v0.16b, v0.16b, v1.16b'), (0x3d800000, 'str q0, [x0]'),
            (0x4f00e400, 'movi v0.16b, #0'), (0x4f00e401, 'movi v1.16b, #0'),
            (0xd2800009, 'mov x9, #0'), (0xd280000a, 'mov x10, #0'),
            (0xd51b421f, 'msr NZCV, xzr'), (0xd65f03c0, 'ret')]
        rows = [(word.to_bytes(4, 'little').hex(), text) for word, text in words]
    return [text for _, text in rows], b''.join(bytes.fromhex(raw) for raw, _ in rows), [len(raw) // 2 for raw, _ in rows]


def mapped(image, target, address, size):
    require(target in TARGETS and len(image) >= 64 and image[:7] == b'\x7fELF\x02\x01\x01', 'wrong ELF format')
    kind, machine, version = struct.unpack_from('<HHI', image, 16)
    offset = struct.unpack_from('<Q', image, 32)[0]
    header, stride, count = struct.unpack_from('<HHH', image, 52)
    require(kind in (2, 3) and machine == TARGETS[target][0] and version == 1 and header == 64
            and stride == 56 and 0 < count < 65535 and offset >= 64
            and offset + stride * count <= len(image), 'invalid ELF program table')
    require(address >= 0 and size > 0 and address + size < 2**64, 'invalid symbol extent')
    loads, matches = [], []
    for i in range(count):
        kind, flags, pos, base, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', image, offset + i * stride)
        if kind != 1:
            continue
        require(filesz <= memsz and pos + filesz <= len(image) and base + memsz < 2**64, 'invalid ELF load extent')
        loads.append((base, memsz))
        if base <= address and address + size <= base + filesz and flags == 5:
            matches.append(pos + address - base)
    loads.sort()
    require(loads and all(a + n <= b for (a, n), (b, _) in zip(loads, loads[1:])), 'overlapping ELF loads')
    require(len(matches) == 1, 'kernel lacks unique read/execute file mapping')
    return matches[0]


def select(nm, target):
    require(target in TARGETS, 'unsupported target')
    rows = []
    architecture = TARGETS[target][2]
    pattern = (r'(?:_ZN17brynja_crypto_cpu3aes' + architecture + r'9transform17h[0-9a-f]{16}E|'
               r'_RINvNtNtC\w+_17brynja_crypto_cpu3aes' + architecture + r'9transformKj[bdf]_EB\w+_)')
    for line in nm.splitlines():
        if '17brynja_crypto_cpu3aes' not in line or 'transform' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (' + pattern + ')', line)
        require(match is not None, 'unrecognized or wrong-architecture kernel symbol')
        rows.append((match[3], int(match[1], 16), int(match[2], 16)))
    require(len(rows) == 3 and len({s for s, _, _ in rows}) == 3, 'missing/duplicate/extra kernel')
    rows.sort(key=lambda r: r[1])
    require(all(n > 0 for _, _, n in rows)
            and all(a + n <= b for (_, a, n), (_, b, _) in zip(rows, rows[1:])), 'invalid/overlapping kernels')
    return rows


def decode(assembly, row, target):
    symbol, start, size = row
    require(re.findall(r'file format (\S+)', assembly) == [TARGETS[target][1]], 'wrong disassembly target')
    headers = list(re.finditer(r'^([0-9a-f]+) <([^>]+)>:\n', assembly, re.M))
    chosen = [i for i, m in enumerate(headers) if m[2] == symbol]
    require(len(chosen) == 1, 'missing/duplicate kernel disassembly')
    index = chosen[0]
    require(int(headers[index][1], 16) == start, 'symbol address mismatch')
    end = headers[index + 1].start() if index + 1 < len(headers) else len(assembly)
    lines, raw, sizes = [], bytearray(), []
    arm = target.startswith('aarch64')
    for line in assembly[headers[index].end():end].splitlines():
        if not line.strip() or len(raw) == size:
            # Full disassembly includes alignment after the nm-defined extent;
            # never include it, nor truncate at the first return inside extent.
            continue
        pattern = (r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)' if arm else
                   r'\s*([0-9a-f]+): ((?:[0-9a-f]{2} )*[0-9a-f]{2}) *\t(.+)')
        match = re.fullmatch(pattern, line)
        require(match is not None, 'unrecognized disassembly row')
        data = int(match[2], 16).to_bytes(4, 'little') if arm else bytes.fromhex(match[2])
        require(int(match[1], 16) == start + len(raw) and 0 < len(data) <= (4 if arm else 15)
                and len(raw) + len(data) <= size, 'noncontiguous/out-of-extent bytes')
        text = match[3].split('//', 1)[0] if arm else match[3]
        lines.append(' '.join(text.split()))
        raw.extend(data)
        sizes.append(len(data))
    require(len(raw) == size, 'incomplete disassembly extent')
    return lines, bytes(raw), sizes


def check(lines, raw, sizes, row, image, target):
    symbol, start, size = row
    pos = mapped(image, target, start, size)
    require(len(raw) == size and sum(sizes) == size and len(sizes) == len(lines)
            and image[pos:pos + size] == raw, 'decoded bytes differ from executable')
    normalized = []
    offsets, cursor = set(), 0
    for n in sizes:
        offsets.add(cursor)
        cursor += n
    for line in lines:
        if re.match(r'(?:jne |jmp |cbnz |b(?:\.ne|\.eq)? )', line):
            match = re.fullmatch(r'(jne|jmp|cbnz x8,|b|b.ne|b.eq) 0x([0-9a-f]+) <'
                                 + re.escape(symbol) + r'\+0x([0-9a-f]+)>', line)
            require(match is not None, 'unmodeled kernel branch')
            relative = int(match[3], 16)
            require(relative in offsets and start + relative == int(match[2], 16), 'branch target/annotation mismatch')
            normalized.append(f'{match[1]} @+{relative:x}')
        else:
            normalized.append(line)
    matches = [bits for bits in (128, 192, 256) if template(target, bits) == (normalized, raw, sizes)]
    require(len(matches) == 1, 'kernel instruction/encoding template changed; explicit re-review required')
    return {'bits': matches[0], 'instructions': len(lines), 'symbol_bytes': size,
            'bytes_sha256': hashlib.sha256(raw).hexdigest()}


def mutations(lines, raw, sizes, row, image, target, checker=None):
    # Expansion bodies share the byte/text corruption machinery, not templates.
    validate = check if checker is None else checker
    validate(lines, raw, sizes, row, image, target)
    pos = mapped(image, target, row[1], row[2])
    count = 0
    for index in range(len(raw)):
        altered = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        replaced = image[:pos] + altered + image[pos + len(raw):]
        try:
            validate(lines, altered, sizes, row, replaced, target)
        except ValueError as error:
            require('template changed' in str(error), 'encoding control rejected for unrelated reason')
            count += 1
        else:
            raise ValueError('kernel encoded mutation accepted')
    for index in range(len(lines)):
        altered = list(lines)
        altered[index] = 'unreviewed-instruction'
        try:
            validate(altered, raw, sizes, row, image, target)
        except ValueError as error:
            require('template changed' in str(error), 'instruction control rejected for unrelated reason')
            count += 1
        else:
            raise ValueError('kernel textual mutation accepted')
    return count


def inspect(nm, assembly, image, target):
    results = []
    rejected = 0
    for row in select(nm, target):
        lines, raw, sizes = decode(assembly, row, target)
        results.append(check(lines, raw, sizes, row, image, target))
        rejected += mutations(lines, raw, sizes, row, image, target)
    require(sorted(r['bits'] for r in results) == [128, 192, 256], 'kernel width population mismatch')
    require(rejected == (465 if target.startswith('x86') else 570), 'mutation population mismatch')
    return {'kernels': results, 'rejected_mutations': rejected,
            'scope': 'three complete round-kernel bodies only; callers, dispatch, expansion and cleanup outside these bodies unreviewed'}
