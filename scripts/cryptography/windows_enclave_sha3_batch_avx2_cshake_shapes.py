"""Independent saved cSHAKE initialization/prefix/failure instruction contracts.

Retained-prefix staging blocks are intentionally not included in this checkpoint.
"""
import windows_enclave_sha3_batch_avx2_start as direct
import windows_enclave_sha3_batch_storage as storage

life,s,L=direct.life,direct.s,direct.L
ENCODE='_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018516left_encode_u128'
ABSORB='_RNvMs0_NtCscBEH4D3OuJh_22sha3_accelerated_state6engineNtB5_6Engine6absorb'
PREFIX='_RNvMNtCscBEH4D3OuJh_22sha3_accelerated_state23sha3_accelerated_prefixNtB2_6Prefix'


def parts():
    return [L('.B18:|movb $7, %r8b|movl $136, %eax|jmp .B23'),
        L('.B22:|movb $6, %r8b|movl $168, %eax'),
        L(f'''.B23:|movq %rax, 64(%rsp)|movq 2224(%rsi), %rdx|leaq 1696(%rsp), %rcx
        callq {direct.initial.NAME}|movq 2640(%rsp), %r12|cmpq $2, %r12|je .B51
        movzbl 1696(%rsp), %r13d|leaq 1697(%rsp), %rdx|leaq 705(%rsp), %rcx
        movl $943, %r8d|callq memcpy|vmovdqu 2648(%rsp), %ymm0|vmovdqu %ymm0, 1656(%rsp)
        movq 2680(%rsp), %rax|movq %rax, 1688(%rsp)|movb %r13b, 704(%rsp)|movq %r12, 1648(%rsp)
        xorl %r12d, %r12d|leaq 2718(%rsp), %rcx|movq 64(%rsp), %rdx|xorl %r8d, %r8d
        vzeroupper|callq {ENCODE}|movzwl 2974(%rsp), %r13d|leaq 304(%rsp), %rcx
        movq %rbx, %rdx|movq 4864(%rbp), %r8|callq {ENCODE}
        movq %r14, %rdx|movzwl 560(%rsp), %r14d|leaq 1696(%rsp), %rcx
        movq 4880(%rbp), %r8|callq {ENCODE}
        cmpl $257, %r13d|cmovael %r12d, %r13d|movzwl 1952(%rsp), %eax
        cmpl $257, %r14d|cmovael %r12d, %r14d|addl %r13d, %r14d
        cmpl $257, %eax|cmovbl %eax, %r12d|addl %r14d, %r12d
        movq 4880(%rbp), %r14|shll $3, %r12d|movzwl %r12w, %eax
        addq %rbx, %rax|movq 4864(%rbp), %r12|adcq $0, %r12|jb .B44
        addq 4872(%rbp), %rax|adcq %r14, %r12|jb .B44
        movq %r12, %rcx|shldq $61, %rax, %rcx|shrq $3, %r12|xorl %r13d, %r13d
        testb $7, %al|setne %r13b|addq %rcx, %r13|adcq $0, %r12
        movq 64(%rsp), %r14|movq %r14, 192(%rsp)|movq %r13, 208(%rsp)
        movq %r12, 216(%rsp)|movq $0, 200(%rsp)|leaq 208(%rsp), %rcx|leaq 192(%rsp), %rdx
        callq __umodti3|vpextrq $1, %xmm0, %rdx|vmovq %xmm0, %rcx|xorl %r10d, %r10d
        movq %r14, %rax|subq %rcx, %rax|movl $0, %ecx|sbbq %rdx, %rcx
        vptest %xmm0, %xmm0|cmoveq %r10, %rcx|cmoveq %r10, %rax
        addq %r13, %rax|adcq %r12, %rcx|movq 4872(%rbp), %r11
        movq %r11, %rdx|orq %rbx, %rdx|movq 4880(%rbp), %r13|movq %r13, %r8
        movq 4864(%rbp), %r12|orq %r12, %r8|movq %rdx, %r9|orq %r8, %r9
        sete %r9b|addb %r9b, %r9b|orq %rdx, %r8|cmoveq %r10, %rcx|cmoveq %r10, %rax
        movw $0, 376(%rsp)|movq %rbx, 304(%rsp)|movq %r12, 312(%rsp)
        movq %r11, 184(%rsp)|movq %r11, 320(%rsp)|movq %r13, 328(%rsp)
        vpxor %xmm0, %xmm0, %xmm0|vmovdqa %xmm0, 336(%rsp)
        movq %rax, 352(%rsp)|movq %rcx, 360(%rsp)|movq %r14, 368(%rsp)|movb %r9b, 378(%rsp)
        je .B27|movq %r14, %rdx|leaq 1696(%rsp), %rcx|xorl %r8d, %r8d|xorl %r14d, %r14d
        callq {ENCODE}|movzwl 1952(%rsp), %eax|cmpl $257, %eax|movl $1, %r13d|movl $1, %edx
        leaq 1696(%rsp), %rcx|cmovbq %rcx, %rdx|cmovbl %eax, %r14d
        leaq 704(%rsp), %rcx|movq %r14, %r8|callq {ABSORB}|cmpb $-1, %al|je .B35'''),
        L(f'''.B34:|movb $1, 1563(%rsp)|movq $0, 1320(%rsp)|leaq 1328(%rsp), %rcx
        callq {storage.MEMORY_WIPE}'''),
        L(f'.B43:|leaq 376(%rsp), %rcx|movl $1, %edx|callq {life.ZERO}'),
        L(f'''.B44:|movb $1, 1563(%rsp)|movq $0, 1320(%rsp)|leaq 1328(%rsp), %rdi
        movq %rdi, %rcx|vzeroupper|callq {storage.MEMORY_WIPE}|cmpb $-1, 1642(%rsp)
        leaq 1024(%rsi), %r13|je .B46|leaq 1640(%rsp), %rcx|movl $1, %edx|callq {life.ZERO}
        movb $0, 1641(%rsp)|vpxor %xmm0, %xmm0, %xmm0
        vmovdqa %ymm0, 1568(%rsp)|vmovdqa %ymm0, 1600(%rsp)'''),
        L(f'''.B46:|movb $-1, 1642(%rsp)|movb $3, 1666(%rsp)|movq %rdi, %rcx|vzeroupper
        callq {storage.MEMORY_WIPE}|leaq 704(%rsp), %rcx|callq {storage.SCRATCH_WIPE}
        cmpb $-1, 1642(%rsp)|je .B51|leaq 1640(%rsp), %rcx|movl $1, %edx
        callq {life.ZERO}|jmp .B51'''),
        L(f'''.B35:|movzwl %r14w, %eax|movq %rax, 336(%rsp)|movq $0, 344(%rsp)
        leaq 1696(%rsp), %rcx|movzbl 377(%rsp), %eax|movb %al, 64(%rsp)
        movq %rbx, %rdx|movq %r12, %r8|callq {ENCODE}|movzwl 1952(%rsp), %eax
        xorl %r12d, %r12d|cmpl $257, %eax|leaq 1696(%rsp), %rcx|cmovbq %rcx, %r13
        cmovbl %eax, %r12d|cmpb $0, 64(%rsp)|je .B39|testw %r12w, %r12w
        movq 4880(%rbp), %r14|je .B37'''),
        L(f'''.B42:|leaq 304(%rsp), %rcx|leaq 704(%rsp), %rdx|movq %r13, %r8
        movb $8, %r9b|callq {PREFIX}4bits|cmpb $-1, %al|jne .B43|incq %r13|decq %r12
        jne .B42|jmp .B37'''),
        L(f'''.B39:|leaq 704(%rsp), %rcx|movq %r13, %rdx|movq %r12, %r8|callq {ABSORB}
        cmpb $-1, %al|jne .B34|addl %r12d, %r14d|movzwl %r14w, %eax
        movq %rax, 336(%rsp)|movq $0, 344(%rsp)|movq 4880(%rbp), %r14'''),
        L(f'''.B37:|leaq 304(%rsp), %rcx|leaq 704(%rsp), %rdx|callq {PREFIX}7advance
        cmpb $-1, %al|jne .B43|movzbl 378(%rsp), %r12d|movzbl 304(%rsp), %r13d
        vmovups 305(%rsp), %ymm0|vmovaps %ymm0, 96(%rsp)
        vmovups 337(%rsp), %ymm0|vmovaps %ymm0, 128(%rsp)
        vmovdqu 346(%rsp), %ymm0|vmovdqu %ymm0, 137(%rsp)
        movl 379(%rsp), %eax|movl %eax, 88(%rsp)|movzbl 383(%rsp), %eax
        movb %al, 92(%rsp)|cmpb $-1, %r12b|jne .B28|jmp .B44''')]


def check(bodies,assembly):
    name,_,before=direct.check_shapes(bodies,assembly);lines=life.code(bodies[name]);covered=set()
    for part in parts():
        at=lines.index(part[0]);end=next((i for i in range(at+1,len(lines)) if lines[i].endswith(':')),len(lines))
        s.require(lines[at:end]==part,'complete AVX2 cSHAKE initial/prefix/failure block')
        covered.update(range(at,end))
    pred=direct.predecessors(lines);dispatch=lines.index('jmpq *%rcx')
    for label in (18,22):
        s.require(pred[lines.index(f'.B{label}:')]=={dispatch},'cSHAKE only entered from admitted descriptor')
    for at in covered:
        s.require(pred[at]<=covered|{dispatch},'no unreviewed entry into initialized cSHAKE paths')
    for before_label,after_label in ((22,23),(23,34),(34,43),(43,44),(44,46),(35,42),(39,37)):
        at=lines.index(f'.B{before_label}:');end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[end]==f'.B{after_label}:','actual prefix/cleanup fallthrough')
    return name,sorted(covered),sorted(covered|set(before))
