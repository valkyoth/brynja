"""Exact hardware expansion bodies; admission and caller cleanup are separate.

These instruction/encoding templates are reviewed in
docs/assurance/aes-accelerated-linked-expansion.md. They are not learned from
the binary being checked. Only the three public key/schedule extents vary.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('expansion_kernel_helpers',
    Path(__file__).with_name('aes_accelerated_linked_kernels.py'))
kernels = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernels)
require = kernels.require
TARGETS = kernels.TARGETS


def template(target, bits):
    require(target in TARGETS and bits in (128, 192, 256), 'unreviewed expansion target/width')
    key = bits // 8
    size = {128: 176, 192: 208, 256: 240}[bits]
    if target.startswith('x86'):
        rows = [
            ('31c0', 'xorl %eax, %eax'), ('8b1407', 'movl (%rdi,%rax), %edx'),
            ('891406', 'movl %edx, (%rsi,%rax)'), ('4883c004', 'addq $4, %rax'),
            (f'4883f8{key:02x}', f'cmpq ${key}, %rax'), ('75f0', 'jne @+2'),
            ('4531c0', 'xorl %r8d, %r8d'), ('b901000000', 'movl $1, %ecx'),
            ('8b5406fc', 'movl -4(%rsi,%rax), %edx'), ('4d85c0', 'testq %r8, %r8'),
            ('7412', 'je @+35'), ('41ba' + key.to_bytes(4, 'little').hex(), f'movl ${key}, %r10d'),
            ('4183fa20', 'cmpl $32, %r10d'), ('752a', 'jne @+59'),
            ('4983f810', 'cmpq $16, %r8'), ('7524', 'jne @+59'),
            ('660f6ec2', 'movd %edx, %xmm0'),
            ('660f70c000', 'pshufd $0, %xmm0, %xmm0 # xmm0 = xmm0[0,0,0,0]'),
            ('660f3adfc000', 'aeskeygenassist $0, %xmm0, %xmm0'),
            ('660f7ec2', 'movd %xmm0, %edx'), ('4d85c0', 'testq %r8, %r8'),
            ('750c', 'jne @+59'), ('c1ca08', 'rorl $8, %edx'), ('31ca', 'xorl %ecx, %edx'),
            ('00c9', 'addb %cl, %cl'), ('7303', 'jae @+59'), ('80f11b', 'xorb $27, %cl'),
            ('4989c2', 'movq %rax, %r10'), (f'4983ea{key:02x}', f'subq ${key}, %r10'),
            ('42331416', 'xorl (%rsi,%r10), %edx'), ('891406', 'movl %edx, (%rsi,%rax)'),
            ('4883c004', 'addq $4, %rax'), ('4983c004', 'addq $4, %r8'),
            (f'4983f8{key:02x}', f'cmpq ${key}, %r8'), ('7503', 'jne @+78'),
            ('4531c0', 'xorl %r8d, %r8d'),
            ('483d' + size.to_bytes(4, 'little').hex(), f'cmpq ${size}, %rax'), ('759a', 'jne @+1a'),
            ('660fefc0', 'pxor %xmm0, %xmm0'), ('31c0', 'xorl %eax, %eax'),
            ('31c9', 'xorl %ecx, %ecx'), ('31d2', 'xorl %edx, %edx'),
            ('4531c0', 'xorl %r8d, %r8d'), ('4531d2', 'xorl %r10d, %r10d'), ('c3', 'retq')]
    else:
        words = [
            (0xd2800009, 'mov x9, #0'), (0x4f00e401, 'movi v1.16b, #0'),
            (0xb869680c, 'ldr w12, [x0, x9]'), (0xb829682c, 'str w12, [x1, x9]'),
            (0x91001129, 'add x9, x9, #4'), (0xf100013f | key << 10, f'cmp x9, #{key}'),
            (0x54ffff81, 'b.ne @+8'), (0xd280000a, 'mov x10, #0'), (0x5280002b, 'mov w11, #1'),
            (0xd100112e, 'sub x14, x9, #4'), (0xb86e682c, 'ldr w12, [x1, x14]'),
            (0xb40000ca, 'cbz x10, @+44'), (0xd280000e | key << 5, f'mov x14, #{key}'),
            (0xf10081df, 'cmp x14, #32'), (0x540001c1, 'b.ne @+70'),
            (0xf100415f, 'cmp x10, #16'), (0x54000181, 'b.ne @+70'),
            (0x4e040d80, 'dup v0.4s, w12'), (0x4e284820, 'aese v0.16b, v1.16b'),
            (0x0e043c0c, 'mov w12, v0.s[0]'), (0xb500010a, 'cbnz x10, @+70'),
            (0x138c218c, 'ror w12, w12, #8'), (0x4a0b018c, 'eor w12, w12, w11'),
            (0x531f796e, 'lsl w14, w11, #1'), (0x3638006b, 'tbz w11, #7, @+6c'),
            (0x5280036b, 'mov w11, #27'), (0x4a0b01ce, 'eor w14, w14, w11'),
            (0x12001dcb, 'and w11, w14, #0xff'),
            (0xd100012e | key << 10, f'sub x14, x9, #{key}'),
            (0xb86e682d, 'ldr w13, [x1, x14]'), (0x4a0d018c, 'eor w12, w12, w13'),
            (0xb829682c, 'str w12, [x1, x9]'), (0x91001129, 'add x9, x9, #4'),
            (0x9100114a, 'add x10, x10, #4'), (0xf100015f | key << 10, f'cmp x10, #{key}'),
            (0x54000041, 'b.ne @+94'), (0xd280000a, 'mov x10, #0'),
            (0xf100013f | size << 10, f'cmp x9, #{size}'), (0x54fffc61, 'b.ne @+24'),
            (0x4f00e400, 'movi v0.16b, #0'), (0x4f00e401, 'movi v1.16b, #0'),
            (0xd2800009, 'mov x9, #0'), (0xd280000a, 'mov x10, #0'),
            (0xd280000b, 'mov x11, #0'), (0xd280000c, 'mov x12, #0'),
            (0xd280000d, 'mov x13, #0'), (0xd280000e, 'mov x14, #0'),
            (0xd51b421f, 'msr NZCV, xzr'), (0xd65f03c0, 'ret')]
        rows = [(word.to_bytes(4, 'little').hex(), text) for word, text in words]
    return [text for _, text in rows], b''.join(bytes.fromhex(raw) for raw, _ in rows), [len(raw) // 2 for raw, _ in rows]


def select(nm, target):
    require(target in TARGETS, 'unsupported expansion target')
    architecture = '10x86_expand' if target.startswith('x86') else '14aarch64_expand'
    pattern = (r'(?:_ZN17brynja_crypto_cpu3aes' + architecture + r'6expand17h[0-9a-f]{16}E|'
               r'_RINvNtNtC\w+_17brynja_crypto_cpu3aes' + architecture +
               r'6expandKj(?:10_Kjb0|18_Kjd0|20_Kjf0)_EB\w+_)')
    rows = []
    for line in nm.splitlines():
        if '17brynja_crypto_cpu3aes' not in line or '_expand' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (' + pattern + ')', line)
        require(match is not None, 'unrecognized or wrong-architecture expansion symbol')
        rows.append((match[3], int(match[1], 16), int(match[2], 16)))
    rows.sort(key=lambda r: r[1])
    require(len(rows) == 3 and len({s for s, _, _ in rows}) == 3, 'expansion population changed')
    require(all(n > 0 for _, _, n in rows)
            and all(a + n <= b for (_, a, n), (_, b, _) in zip(rows, rows[1:])), 'overlapping/invalid expansion extent')
    return rows


def check(lines, raw, sizes, row, image, target):
    symbol, start, size = row
    pos = kernels.mapped(image, target, start, size)
    require(len(raw) == size and sum(sizes) == size and len(sizes) == len(lines)
            and image[pos:pos + size] == raw, 'decoded bytes differ from executable')
    offsets, cursor = set(), 0
    for n in sizes:
        offsets.add(cursor)
        cursor += n
    normalized = []
    for line in lines:
        if re.match(r'(?:j\w+ |b\.\w+ |cbn?z |tbz )', line):
            match = re.fullmatch(r'(jne|je|jae|b.ne|cbz x10,|cbnz x10,|tbz w11, #7,) 0x([0-9a-f]+) <'
                                 + re.escape(symbol) + r'\+0x([0-9a-f]+)>', line)
            require(match is not None, 'unmodeled expansion branch')
            offset = int(match[3], 16)
            require(offset in offsets and start + offset == int(match[2], 16), 'branch target/annotation mismatch')
            normalized.append(f'{match[1]} @+{offset:x}')
        else:
            normalized.append(line)
    matches = [bits for bits in (128, 192, 256) if template(target, bits) == (normalized, raw, sizes)]
    require(len(matches) == 1, 'expansion instruction/encoding template changed; explicit re-review required')
    return {'bits': matches[0], 'instructions': len(lines), 'symbol_bytes': size,
            'bytes_sha256': hashlib.sha256(raw).hexdigest()}


def inspect(nm, assembly, image, target):
    results, rejected = [], 0
    for row in select(nm, target):
        lines, raw, sizes = kernels.decode(assembly, row, target)
        results.append(check(lines, raw, sizes, row, image, target))
        rejected += kernels.mutations(lines, raw, sizes, row, image, target, checker=check)
    require(sorted(r['bits'] for r in results) == [128, 192, 256], 'expansion width population mismatch')
    require(rejected == (570 if target.startswith('x86') else 735), 'expansion mutation population mismatch')
    return {'expansions': results, 'rejected_mutations': rejected,
            'scope': 'three complete hardware expansion bodies only; caller admission, ownership and cleanup remain separate'}
