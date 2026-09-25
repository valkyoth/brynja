"""Reviewed normal-return leaf contracts for the retained Linux x86/Arm builds."""
import re

from debug_reader_primitives import require

COPY_X86 = '''movq %rdx, %r8
movq %rdi, -24(%rsp)
movq %rsi, -16(%rsp)
movq %r8, -8(%rsp)
BRYNJA_COPY_BEGIN
xorl %ecx, %ecx
movq %r8, %rdx
cmpq $8, %rdx
jb B1
B0:
movq (%rsi,%rcx), %rax
movq %rax, (%rdi,%rcx)
addq $8, %rcx
subq $8, %rdx
cmpq $8, %rdx
jae B0
B1:
testq %rdx, %rdx
je B3
B2:
movzbl (%rsi,%rcx), %eax
movb %al, (%rdi,%rcx)
incq %rcx
decq %rdx
jne B2
B3:
BRYNJA_COPY_ERASE
xorl %eax, %eax
xorl %ecx, %ecx
xorl %edx, %edx
BRYNJA_COPY_END
retq'''
COPY_ARM = '''sub sp, sp, #32
mov x8, x0
str x8, [sp, #8]
mov x8, x1
str x8, [sp, #16]
str x2, [sp, #24]
BRYNJA_COPY_BEGIN
mov x5, xzr
mov x6, x2
cmp x6, #8
b.lo B1
B0:
ldr x4, [x1, x5]
str x4, [x0, x5]
add x5, x5, #8
sub x6, x6, #8
cmp x6, #8
b.hs B0
B1:
cbz x6, B3
B2:
ldrb w4, [x1, x5]
strb w4, [x0, x5]
add x5, x5, #1
sub x6, x6, #1
cbnz x6, B2
B3:
BRYNJA_COPY_ERASE
mov x4, xzr
mov x5, xzr
mov x6, xzr
cmp xzr, xzr
BRYNJA_COPY_END
add sp, sp, #32
ret'''
MASK_X86 = '''movb %sil, %cl
movq %rdi, -16(%rsp)
movb %cl, -2(%rsp)
movb %dl, -1(%rsp)
BRYNJA_MASK_BEGIN
movzbl (%rdi), %eax
andb %cl, %al
orb %dl, %al
movb %al, (%rdi)
BRYNJA_MASK_ERASE
xorl %eax, %eax
BRYNJA_MASK_END
retq'''
MASK_ARM = '''sub sp, sp, #48
str x0, [sp, #16]
str w2, [sp, #24]
str x0, [sp, #32]
strb w1, [sp, #44]
strb w2, [sp, #45]
strb w1, [sp, #47]
and w8, w1, #0xff
str w8, [sp, #28]
b B0
B0:
ldr w8, [sp, #24]
strb w8, [sp, #46]
and w8, w8, #0xff
str w8, [sp, #12]
b B1
B1:
ldr w10, [sp, #12]
ldr w9, [sp, #28]
ldr x8, [sp, #16]
BRYNJA_MASK_BEGIN
ldrb w4, [x8]
and w4, w4, w9
orr w4, w4, w10
strb w4, [x8]
BRYNJA_MASK_ERASE
mov x4, xzr
cmp xzr, xzr
BRYNJA_MASK_END
add sp, sp, #48
ret'''


def normalized(body):
    lines = [re.sub(r'\s+', ' ', line.strip()) for line in body.splitlines()[1:]]
    references = set()
    for line in lines:
        if re.match(r'(?:j\w+|b(?:\.\w+)?|cbz|cbnz) ', line):
            references.add(line.rsplit(' ', 1)[-1])
    labels = [line[:-1] for line in lines if line.endswith(':') and line[:-1] in references]
    require(len(labels) == len(set(labels)) and set(labels) == references, 'all primitive branches target unique local labels')
    mapping = {label: 'B' + str(i) for i, label in enumerate(labels)}
    result = []
    for line in lines:
        if marker := re.fullmatch(r'(?:#|//) (BRYNJA_(?:COPY|MASK)_(?:BEGIN|ERASE|END))', line):
            result.append(marker[1])
            continue
        if not line or line.startswith(('#', '//')):
            continue
        if line.endswith(':') and line[:-1] in mapping:
            result.append(mapping[line[:-1]] + ':')
            continue
        if re.fullmatch(r'\.L(?:tmp|func_begin|func_end)\d+:', line):
            continue
        if re.fullmatch(r'\.loc \d+ \d+ \d+(?: (?:is_stmt [01]|prologue_end|epilogue_begin))*', line) or re.fullmatch(
                r'\.file \d+ "[^";\n]+" "[^";\n]+"', line) or re.fullmatch(
                r'\.cfi_(?:startproc|endproc|def_cfa_offset \d+)', line):
            continue
        if mapping:
            pattern = r'(?<![\w.$])(?:' + '|'.join(re.escape(label) for label in mapping) + r')(?![\w.$])'
            line = re.sub(pattern, lambda m: mapping[m[0]], line)
        result.append(line.replace(', ', ','))
    return result


def inspect(body, arm, role):
    expected = {('COPY', False): COPY_X86, ('COPY', True): COPY_ARM,
                ('MASK', False): MASK_X86, ('MASK', True): MASK_ARM}[(role, arm)]
    require(normalized(body) == [line.replace(', ', ',') for line in expected.splitlines()],
            'exact retained primitive ABI, control flow, memory operands and normal-return erasure')
