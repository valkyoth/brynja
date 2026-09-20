"""Reviewed normal-return assembly contracts for the alignment-one caller."""

X86_POPCOUNT = '''movq %rcx, %rax
shrq %rax
movabsq $6148914691236517205, %rdx
andq %rdx, %rax
subq %rax, %rcx
movabsq $3689348814741910323, %rdx
movq %rcx, %rax
andq %rdx, %rax
shrq $2, %rcx
andq %rdx, %rcx
addq %rcx, %rax
movq %rax, %rcx
shrq $4, %rcx
addq %rcx, %rax
movabsq $1085102592571150095, %rcx
andq %rcx, %rax
movabsq $72340172838076673, %rcx
imulq %rcx, %rax
shrq $56, %rax'''

X86_OLD = '''subq $200, %rsp
movq %rsi, %rcx
movq %rdi, (%rsp)
movq %rcx, 8(%rsp)
movq %rdx, 16(%rsp)
movq %rdi, 136(%rsp)
movq %rcx, 144(%rsp)
leaq .Lalloc_c848f501c9a24e1e115677405b6cf8e4(%rip), %rax
movq %rax, 152(%rsp)
movq $215, 160(%rsp)
leaq .Lalloc_e92e94d0ff530782b571cfd99ec66aef(%rip), %rax
movq %rax, 168(%rsp)
movq %rdi, 176(%rsp)
''' + X86_POPCOUNT + '''
movl %eax, 188(%rsp)
cmpl $1, 188(%rsp)
jne B0
movq (%rsp), %rax
movq 8(%rsp), %rcx
subq $1, %rcx
andq %rcx, %rax
cmpq $0, %rax
je B1
jmp B2'''

ARM_OLD = '''sub sp, sp, #224
stp x29, x30, [sp, #208]
add x29, sp, #208
str x0, [sp, #8]
str x1, [sp, #16]
str x2, [sp, #24]
stur x0, [x29, #-64]
stur x1, [x29, #-56]
adrp x8, .Lalloc_c848f501c9a24e1e115677405b6cf8e4
add x8, x8, :lo12:.Lalloc_c848f501c9a24e1e115677405b6cf8e4
stur x8, [x29, #-48]
mov w8, #215
stur x8, [x29, #-40]
adrp x8, .Lalloc_e92e94d0ff530782b571cfd99ec66aef
add x8, x8, :lo12:.Lalloc_e92e94d0ff530782b571cfd99ec66aef
stur x8, [x29, #-32]
stur x0, [x29, #-24]
fmov d0, x1
cnt v0.8b, v0.8b
uaddlv h0, v0.8b
stur s0, [x29, #-12]
ldur w8, [x29, #-12]
subs w8, w8, #1
b.ne B1
b B0'''

X86_ALIGN = '''subq $56, %rsp
movq %rsi, %rcx
movq %rdi, 8(%rsp)
movq %rcx, 16(%rsp)
movq %rdi, 24(%rsp)
movq %rcx, 32(%rsp)
''' + X86_POPCOUNT + '''
cmpl $1, %eax
jne B0
movq 8(%rsp), %rax
movq 16(%rsp), %rcx
subq $1, %rcx
andq %rcx, %rax
cmpq $0, %rax
sete %al
andb $1, %al
addq $56, %rsp
retq'''

ARM_ALIGN = '''sub sp, sp, #64
stp x29, x30, [sp, #48]
add x29, sp, #48
str x0, [sp]
str x1, [sp, #8]
str x0, [sp, #16]
str x1, [sp, #24]
fmov d0, x1
cnt v0.8b, v0.8b
uaddlv h0, v0.8b
fmov w8, s0
subs w8, w8, #1
b.ne B1
b B0'''

X86_WRAPPER = '''subq $56, %rsp
movq %rdx, (%rsp)
movq %rdi, 16(%rsp)
movq %rsi, 24(%rsp)
movq %rdi, 32(%rsp)
movq ALIGN@GOTPCREL(%rip), %rax
callq *%rax
movb %al, 15(%rsp)
jmp B1'''

ARM_WRAPPER = '''sub sp, sp, #80
stp x29, x30, [sp, #64]
add x29, sp, #64
str x2, [sp, #8]
mov x8, x0
str x8, [sp, #24]
str x1, [sp, #32]
mov x8, x0
stur x8, [x29, #-24]
bl ALIGN
str w0, [sp, #20]
b B1'''


def contracts(compiler, arm):
    """Return exact normal blocks plus total block counts, including exclusions."""
    if compiler == '1.90.0':
        if arm:
            return {'CHECK': (6, {'entry': ARM_OLD,
                                 'B0': 'ldr x8, [sp, #8]\nldr x9, [sp, #16]\nsubs x9, x9, #1\nand x8, x8, x9\ncbz x8, B2\nb B3',
                                 'B2': 'ldp x29, x30, [sp, #208]\nadd sp, sp, #224\nret'})}
        return {'CHECK': (5, {'entry': X86_OLD, 'B1': 'addq $200, %rsp\nretq'})}
    if compiler != '1.98.1':
        raise ValueError('unreviewed byte-precondition assembly compiler')
    if arm:
        return {'CHECK': (4, {'entry': ARM_WRAPPER,
                             'B1': 'ldr w8, [sp, #20]\ntbnz w8, #0, B3\nb B2',
                             'B3': 'ldp x29, x30, [sp, #64]\nadd sp, sp, #80\nret'}),
                'ALIGN': (2, {'entry': ARM_ALIGN,
                              'B0': 'ldr x8, [sp]\nldr x9, [sp, #8]\nsubs x9, x9, #1\nands x8, x8, x9\ncset w0, eq\nldp x29, x30, [sp, #48]\nadd sp, sp, #64\nret'})}
    return {'CHECK': (4, {'entry': X86_WRAPPER,
                         'B1': 'movb 15(%rsp), %al\ntestb $1, %al\njne B3\njmp B2',
                         'B3': 'addq $56, %rsp\nretq'}),
            'ALIGN': (1, {'entry': X86_ALIGN})}
