"""Manually reviewed retained debug iterator lowering contracts, not templates inferred at runtime."""

X86_ITER = '''movq %rdi, -80(%rsp)
movq %rsi, -72(%rsp)
movq %rdi, -56(%rsp)
movq %rsi, -48(%rsp)
movq %rsi, -40(%rsp)
movq %rdi, -32(%rsp)
movq %rsi, -24(%rsp)
movq %rdi, -16(%rsp)
movq -72(%rsp), %rcx
movq -80(%rsp), %rax
movq %rax, -8(%rsp)
addq %rcx, %rax
movq %rax, -64(%rsp)
movq -80(%rsp), %rax
movq -64(%rsp), %rdx
retq'''

ARM_ITER = '''sub sp, sp, #80
str x0, [sp]
str x1, [sp, #8]
str x0, [sp, #24]
str x1, [sp, #32]
str x1, [sp, #40]
str x0, [sp, #48]
str x1, [sp, #56]
str x0, [sp, #64]
b B0
B0:
ldr x8, [sp]
ldr x9, [sp, #8]
str x8, [sp, #72]
add x8, x8, x9
str x8, [sp, #16]
b B1
B1:
ldr x0, [sp]
ldr x1, [sp, #16]
add sp, sp, #80
ret'''

X86_NEXT_190 = '''movq %rdi, -104(%rsp)
movq %rdi, -56(%rsp)
movq $1, -48(%rsp)
movq $1, -40(%rsp)
movq (%rdi), %rax
movq %rax, -80(%rsp)
movq 8(%rdi), %rax
movq %rax, -96(%rsp)
movq %rax, -32(%rsp)
movq -96(%rsp), %rax
leaq -80(%rsp), %rcx
movq %rcx, -24(%rsp)
movq %rax, -72(%rsp)
leaq -72(%rsp), %rax
movq %rax, -16(%rsp)
movq -80(%rsp), %rax
cmpq -72(%rsp), %rax
je B0
movq -104(%rsp), %rax
movq -80(%rsp), %rcx
addq $1, %rcx
movq %rcx, (%rax)
jmp B1
B0:
movq $0, -88(%rsp)
jmp B3
B1:
movq -80(%rsp), %rax
movq %rax, -64(%rsp)
leaq -64(%rsp), %rax
movq %rax, -8(%rsp)
movq -64(%rsp), %rax
movq %rax, -88(%rsp)
B2:
movq -88(%rsp), %rax
retq
B3:
jmp B2'''

X86_NEXT_198 = '''movq %rdi, -72(%rsp)
movq %rdi, -40(%rsp)
movq $1, -32(%rsp)
movq $1, -24(%rsp)
movq (%rdi), %rax
movq %rax, -64(%rsp)
movq %rax, -16(%rsp)
movq 8(%rdi), %rax
movq %rax, -56(%rsp)
movq %rax, -8(%rsp)
movq -64(%rsp), %rax
movq -56(%rsp), %rcx
cmpq %rcx, %rax
je B0
movq -72(%rsp), %rax
movq -64(%rsp), %rcx
addq $1, %rcx
movq %rcx, (%rax)
jmp B1
B0:
movq $0, -48(%rsp)
jmp B3
B1:
movq -64(%rsp), %rax
movq %rax, -48(%rsp)
B2:
movq -48(%rsp), %rax
retq
B3:
jmp B2'''

ARM_NEXT_190 = '''sub sp, sp, #112
str x0, [sp, #8]
mov x8, x0
str x8, [sp, #56]
mov w8, #1
str x8, [sp, #64]
str x8, [sp, #72]
ldr x8, [x0]
str x8, [sp, #32]
ldr x8, [x0, #8]
str x8, [sp, #16]
str x8, [sp, #80]
b B0
B0:
ldr x9, [sp, #16]
add x8, sp, #32
str x8, [sp, #88]
add x8, sp, #40
str x9, [sp, #40]
str x8, [sp, #96]
ldr x8, [sp, #32]
ldr x9, [sp, #40]
subs x8, x8, x9
b.eq B2
b B1
B1:
ldr x9, [sp, #8]
ldr x8, [sp, #32]
add x8, x8, #1
str x8, [x9]
b B3
B2:
str xzr, [sp, #24]
b B5
B3:
ldr x9, [sp, #32]
add x8, sp, #48
str x9, [sp, #48]
str x8, [sp, #104]
ldr x8, [sp, #48]
str x8, [sp, #24]
b B4
B4:
ldr x0, [sp, #24]
add sp, sp, #112
ret
B5:
b B4'''

ARM_NEXT_198 = '''sub sp, sp, #80
str x0, [sp, #8]
mov x8, x0
str x8, [sp, #40]
mov w8, #1
str x8, [sp, #48]
str x8, [sp, #56]
ldr x8, [x0]
str x8, [sp, #16]
str x8, [sp, #64]
ldr x8, [x0, #8]
str x8, [sp, #24]
str x8, [sp, #72]
b B0
B0:
ldr x8, [sp, #16]
ldr x9, [sp, #24]
subs x8, x8, x9
b.eq B2
b B1
B1:
ldr x9, [sp, #8]
ldr x8, [sp, #16]
add x8, x8, #1
str x8, [x9]
b B3
B2:
str xzr, [sp, #32]
b B5
B3:
ldr x8, [sp, #16]
str x8, [sp, #32]
b B4
B4:
ldr x0, [sp, #32]
add sp, sp, #80
ret
B5:
b B4'''


def iterator(arm, compiler):
    if compiler not in ('1.90.0', '1.98.1'):
        raise ValueError('unreviewed debug iterator compiler')
    return {'ITER': ARM_ITER if arm else X86_ITER,
            'NEXT': (ARM_NEXT_190 if compiler == '1.90.0' else ARM_NEXT_198) if arm
            else (X86_NEXT_190 if compiler == '1.90.0' else X86_NEXT_198)}
