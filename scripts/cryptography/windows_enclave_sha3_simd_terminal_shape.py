"""Saved final-health, error bridge, size admission and report contracts."""
import windows_enclave_sha3_simd_scalar_shape as scalar
import windows_enclave_sha3_simd_reject_shape as reject
life,s,L=scalar.life,scalar.s,scalar.L


def names(bodies):
    return scalar.names(bodies)|{key:s.one(bodies,p) for key,p in (
        ('check',r'^[^?].*hardened_batch.*Executor5check$'),
        ('validate',r'hardened_batch6output8validate$'),
        ('panic',r'panicking11panic_const24panic_const_add_overflow$'))}


def bridges(n):
    return L(f'''.B207:|xorl %r14d, %r14d|.B208:|movb $14, %r13b|.B209:|
        movq 976(%rbp), %rsi|movq 1104(%rbp), %rbx|jmp .B75|.B210:|
        movq $9, (%r12)|movq $0, 8(%r12)|.B211:|xorl %r14d, %r14d|
        movb $14, %r13b|movq 1104(%rbp), %rbx|jmp .B75|.B212:|
        movb $14, %r13b|xorl %r14d, %r14d|movq 976(%rbp), %rsi|jmp .B75|
        .B213:|xorl %r14d, %r14d|movb $14, %r13b|jmp .B75|.B214:|
        movb $14, %sil|jmp .B228|.B216:|movq 1104(%rbp), %rbx|jmp .B72|
        .B215:|movb $0, 16(%rax)|movb $2, %r13b|xorl %r14d, %r14d|jmp .B209|
        .B217:|movb $12, %al|movq %rax, 944(%rbp)|movq 1104(%rbp), %rbx|jmp .B72|
        .B218:|xorl %r14d, %r14d|movq 976(%rbp), %rsi|movq 1104(%rbp), %rbx|
        movb $4, %r13b|jmp .B75|.B219:|movq 928(%rbp), %rcx|vzeroupper|
        callq *912(%rbp)|nop|testb %al, %al|movq 1104(%rbp), %rbx|jne .B72|
        movq %rdi, %rcx|callq {n['check']}|nop|movq %r15, %r12|movq %rdi, %r14|
        cmpb $-1, %al|je .B230|.B223:|movq 976(%rbp), %rsi|movq %r14, %rdi|
        movq %r12, %r15|movq %rax, %r13|jmp .B8|.B224:|movb $13, %sil|jmp .B227|
        .B225:|movb $12, %sil|jmp .B227|.B226:|movl %eax, %esi|.B227:|
        movq 1104(%rbp), %rbx|.B228:|movl %esi, %r13d|movq 976(%rbp), %rsi|jmp .B8''')


def preflight(n):
    return L(f'''.B230:|cmpb $-1, 991(%rbp)|je .B234|leaq 592(%rbp), %rdx|
        movq 968(%rbp), %rcx|callq {n['validate']}|cmpb $-1, %al|jne .B223|
        movq %r13, %rsi|shrq $8, %rsi|xorl %ecx, %ecx|xorl %eax, %eax|
        .B236:|movq %rcx, %rdx|.B237:|cmpq $448, %rdx|je .B240|
        leaq 112(%rdx), %rcx|movq 968(%rbp), %r8|cmpb $-1, 104(%r8,%rdx)|
        movq %rcx, %rdx|je .B237|movq 968(%rbp), %rdx|movq -16(%rdx,%rcx), %rdx|
        movq %rdx, %r8|shrq $3, %r8|andl $7, %edx|addq %rax, %r8|cmpq $1, %rdx|
        sbbq $-1, %r8|movb $11, %dl|movq %rdx, 944(%rbp)|cmpq %rax, %r8|
        movq %r8, %rax|movq %r14, %rdi|movq %r12, %r15|movq 1104(%rbp), %rbx|
        jae .B236|jmp .B72|.B233:|vzeroupper|callq {n['panic']}|ud2|.B234:|
        movq 976(%rbp), %rsi|movq %r14, %rdi|movq %r12, %r15|jmp .B8|
        .B240:|movb $9, %cl|movq %rcx, 944(%rbp)|cmpq $1024, %rax|
        movq %r14, %rdi|movq %r12, %r15|movq 1104(%rbp), %rbx|ja .B72|movb $0, 472(%rbp)''')


def report(n):
    code=L(f'''.B270:|movq 1104(%rbp), %rcx|callq {n['workspace_wipe']}|
        movl $1024, %edx|movq %r12, %rcx|callq {life.ZERO}|cmpb $-1, 991(%rbp)|je .B280''')
    for i,label in enumerate((273,275,277,279)):
        code+=L(f'''movq 968(%rbp), %rax|movzbl {104+112*i}(%rax), %eax|cmpb $-1, %al|
            je .B{label}|incb %al|movb %al, {688+i}(%rbp)|movq 968(%rbp), %rax|
            movq {96+112*i}(%rax), %rax|movq %rax, {656+8*i}(%rbp)|.B{label}:''')
    return code+L('''movq 688(%rbp), %rax|movq 976(%rbp), %rcx|movq %rax, 96(%rcx)|
        vmovups 592(%rbp), %ymm0|vmovups 624(%rbp), %ymm1|vmovups 656(%rbp), %xmm2|
        vmovups %xmm2, 64(%rcx)|movq 672(%rbp), %rax|movq %rax, 80(%rcx)|
        movq 680(%rbp), %rax|movq %rax, 88(%rcx)|vmovups %ymm1, 32(%rcx)|vmovups %ymm0, (%rcx)|
        movl %esi, 105(%rcx)|movq %rsi, %rax|shrq $48, %rax|movb %al, 111(%rcx)|
        shrq $32, %rsi|movw %si, 109(%rcx)|movq 744(%rbp), %rax|movq %rax, 112(%rcx)|
        movq 808(%rbp), %rax|movq %rax, 120(%rcx)|movq 856(%rbp), %rax|movb %al, 128(%rcx)|
        movb %r13b, 104(%rcx)|movzbl 991(%rbp), %eax|movb %al, 129(%rcx)|jmp .B85|
        .B280:|movq 976(%rbp), %rsi|jmp .B79''')


def check_shape():
    return L('''pushq %rbp|subq $48, %rsp|leaq 48(%rsp), %rbp|movq $-2, -8(%rbp)|
        movb $4, %al|cmpb $0, 16(%rcx)|jne .B7|movq (%rcx), %rdx|
        movb $-1, %al|testq %rdx, %rdx|je .B7|cmpb $0, 16(%rdx)|je .B3|
        movzbl 17(%rdx), %ecx|movq %rdx, -16(%rbp)|callq *8(%rdx)|nop|
        testb %al, %al|movb $-1, %al|movq -16(%rbp), %rdx|jne .B7|
        .B3:|movb $0, 16(%rdx)|movb $2, %al|.B7:|addq $48, %rsp|popq %rbp|retq''')


def rejection_entry(n):
    entry=reject.entry(n)
    # Already-bound entry blocks route all bridge classifications to the
    # already-bound complete normal rejection path. Do not invent replacements.
    return entry[entry.index('.B1:'):entry.index('.B2:')]+entry[entry.index('.B8:'):entry.index('.B10:')]
