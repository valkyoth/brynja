"""Reviewed KMAC cleanup normal-return assembly, not inferred from input artifacts."""

X86_DEBUG_WIPE = '''subq $24, %rsp
movq %rdi, 8(%rsp)
movq %rdi, 16(%rsp)
addq $64, %rdi
movl $1, %esi
callq *CLEAR@GOTPCREL(%rip)
movq 8(%rsp), %rdi
movl $64, %esi
callq *CLEAR@GOTPCREL(%rip)
movq 8(%rsp), %rdi
addq $65, %rdi
movl $1, %esi
callq *CLEAR@GOTPCREL(%rip)
addq $24, %rsp
retq'''
X86_DEBUG_DROP = '''pushq %rax
movq %rdi, (%rsp)
callq *WIPE@GOTPCREL(%rip)
popq %rax
retq'''
X86_DEBUG_CLEAR = '''subq $40, %rsp
movq %rdi, (%rsp)
movq %rsi, 8(%rsp)
movq %rdi, 24(%rsp)
movq %rsi, 32(%rsp)
callq *EMPTY@GOTPCREL(%rip)
testb $1, %al
jne B0
movq 8(%rsp), %rsi
movq (%rsp), %rdi
callq ZERO
movb $RESULT, 23(%rsp)
jmp B1
B0:
movb $0, 23(%rsp)
B1:
movb 23(%rsp), %al
addq $40, %rsp
retq'''
X86_EMPTY = '''movq %rdi, -16(%rsp)
movq %rsi, -8(%rsp)
cmpq $0, %rsi
sete %al
andb $1, %al
retq'''
X86_RELEASE_WIPE = '''pushq %r14
pushq %rbx
pushq %rax
movq %rdi, %rbx
addq $64, %rdi
movq CLEAR@GOTPCREL(%rip), %r14
movl $1, %esi
callq *%r14
movl $64, %esi
movq %rbx, %rdi
callq *%r14
addq $65, %rbx
movl $1, %esi
movq %rbx, %rdi
movq %r14, %rax
addq $8, %rsp
popq %rbx
popq %r14
jmpq *%rax'''
X86_RELEASE_CLEAR = '''testq %rsi, %rsi
je B0
pushq %rax
callq ZERO
movb $RESULT, %al
addq $8, %rsp
retq
B0:
xorl %eax, %eax
retq'''
ARM_DEBUG_WIPE = '''sub sp, sp, #48
stp x29, x30, [sp, #32]
add x29, sp, #32
str x0, [sp, #16]
stur x0, [x29, #-8]
add x0, x0, #64
mov w8, #1
mov w1, w8
str x1, [sp, #8]
bl CLEAR
ldr x0, [sp, #16]
mov w8, #64
mov w1, w8
bl CLEAR
ldr x1, [sp, #8]
ldr x0, [sp, #16]
add x0, x0, #65
bl CLEAR
ldp x29, x30, [sp, #32]
add sp, sp, #48
ret'''
ARM_DEBUG_DROP = '''sub sp, sp, #32
stp x29, x30, [sp, #16]
add x29, sp, #16
mov x8, x0
str x8, [sp, #8]
bl WIPE
ldp x29, x30, [sp, #16]
add sp, sp, #32
ret'''
ARM_DEBUG_CLEAR = '''sub sp, sp, #64
stp x29, x30, [sp, #48]
add x29, sp, #48
str x0, [sp, #8]
str x1, [sp, #16]
mov x8, x0
stur x8, [x29, #-16]
stur x1, [x29, #-8]
bl EMPTY
tbnz w0, #0, B1
b B0
B0:
ldr x1, [sp, #16]
ldr x0, [sp, #8]
bl ZERO
mov w8, #RESULT
sturb w8, [x29, #-17]
b B2
B1:
sturb wzr, [x29, #-17]
b B2
B2:
ldurb w0, [x29, #-17]
ldp x29, x30, [sp, #48]
add sp, sp, #64
ret'''
ARM_EMPTY = '''sub sp, sp, #16
str x0, [sp]
str x1, [sp, #8]
subs x8, x1, #0
cset w0, eq
add sp, sp, #16
ret'''
ARM_RELEASE_WIPE = '''stp x29, x30, [sp, #-32]!
str x19, [sp, #16]
mov x29, sp
mov x19, x0
add x0, x0, #64
mov w1, #1
bl CLEAR
mov x0, x19
mov w1, #64
bl CLEAR
add x0, x19, #65
mov w1, #1
ldr x19, [sp, #16]
ldp x29, x30, [sp], #32
b CLEAR'''
ARM_RELEASE_CLEAR = '''cbz x1, B0
stp x29, x30, [sp, #-16]!
mov x29, sp
bl ZERO
mov w0, #RESULT
ldp x29, x30, [sp], #16
ret
B0:
mov w0, wzr
ret'''


def contracts(arm, profile, compiler):
    if profile == 'debug':
        wipe = ARM_DEBUG_WIPE if arm else X86_DEBUG_WIPE
        drop = ARM_DEBUG_DROP if arm else X86_DEBUG_DROP
        guard = (drop.replace('bl WIPE', 'ldr x0, [x0]\nbl WIPE') if arm else
                 drop.replace('callq *WIPE', 'movq (%rdi), %rdi\ncallq *WIPE'))
        clear = ARM_DEBUG_CLEAR if arm else X86_DEBUG_CLEAR
    else:
        wipe = ARM_RELEASE_WIPE if arm else X86_RELEASE_WIPE
        drop = wipe
        guard = (wipe.replace('mov x19, x0\nadd x0, x0, #64\nmov w1, #1',
                              'ldr x19, [x0]\nmov w1, #1\nadd x0, x19, #64') if arm else
                 wipe.replace('movq %rdi, %rbx\naddq $64, %rdi', 'movq (%rdi), %rbx\nleaq 64(%rbx), %rdi'))
        clear = ARM_RELEASE_CLEAR if arm else X86_RELEASE_CLEAR
    # Both result bytes are compiler-private enum layouts, not stable API values.
    result = '4' if compiler == '1.90.0' else '255' if arm else '-1'
    selected = {'WIPE': wipe, 'DROP': drop, 'GUARD': guard, 'CLEAR': clear.replace('RESULT', result)}
    if profile == 'debug':
        selected['EMPTY'] = ARM_EMPTY if arm else X86_EMPTY
    return {role: text.splitlines() for role, text in selected.items()}
