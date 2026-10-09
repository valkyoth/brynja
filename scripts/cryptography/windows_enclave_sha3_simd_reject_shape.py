"""Saved executor admission and normal rejection, excluding its inner loop."""
import windows_enclave_sha3_simd_digest as digest
life,s,L=digest.life,digest.s,digest.L


def entry(n):
    return ['pushq %'+r for r in digest.shape.SAVES]+L(f'''subq $1128, %rsp|
        leaq 128(%rsp), %rbp|movq $-2, 992(%rbp)|movq %rdx, %rdi|
        movq %rcx, %rsi|movq 1112(%rbp), %r15|movq 1104(%rbp), %rbx|
        vxorps %xmm0, %xmm0, %xmm0|vmovups %ymm0, 656(%rbp)|
        vmovups (%r9), %ymm0|vmovups 32(%r9), %ymm1|
        vmovups %ymm0, 592(%rbp)|vmovups %ymm1, 624(%rbp)|
        movl $0, 688(%rbp)|movq %rdx, 440(%rbp)|movq %rbx, 448(%rbp)|
        movq %r15, 456(%rbp)|movq $1024, 464(%rbp)|movb $0, 472(%rbp)|
        movb $4, %r13b|cmpb $0, 16(%rdx)|je .B2|.B1:|
        xorl %r14d, %r14d|jmp .B75|.B2:|movq (%rdi), %rax|
        testq %rax, %rax|je .B6|cmpb $1, 16(%rax)|jne .B10|
        movq %r8, %r14|movzbl 17(%rax), %ecx|movq %rax, 968(%rbp)|
        vzeroupper|callq *8(%rax)|nop|testb %al, %al|movq %r14, %r8|
        movq 968(%rbp), %rax|je .B10|.B6:|leaq 592(%rbp), %rdx|
        movq %r8, %r14|movq %r8, %rcx|vzeroupper|callq {n['validate']}|
        cmpb $-1, %al|je .B11|movl %eax, %r13d|.B8:|cmpb $4, %r13b|
        jb .B1|movq %rsi, 976(%rbp)|movq %r13, 944(%rbp)|jmp .B72|
        .B10:|movb $0, 16(%rax)|movb $2, %r13b|xorl %r14d, %r14d|jmp .B75''')


def eligibility():
    return L('''cmpq $1024, %r8|jbe .B66|movb $9, %al|movq %rax, 944(%rbp)|
        jmp .B72|.B66:|movq (%rdi), %r8|testq %r8, %r8|je .B69|
        movzbl 17(%r8), %eax|xorl $1, %eax|leaq 2(,%rax,2), %r9|
        cmpb $2, 17(%rdi)|movq %r9, 936(%rbp)|jne .B70|xorl %eax, %eax|
        cmpb $1, 5252(%rbx)|sete %al|xorl %ecx, %ecx|cmpb $1, 5253(%rbx)|
        sete %cl|addl %ecx, %eax|xorl %ecx, %ecx|cmpb $1, 5254(%rbx)|
        sete %cl|xorl %edx, %edx|cmpb $1, 5255(%rbx)|sete %dl|
        addl %ecx, %edx|addl %eax, %edx|movb $10, %al|movq %rax, 944(%rbp)|
        cmpl %r9d, %edx|jae .B70|jmp .B72|.B69:|movb $10, %al|
        movq %rax, 944(%rbp)|cmpb $2, 17(%rdi)|je .B72|.B70:|
        movq %r8, 800(%rbp)|movq 1120(%rbp), %r12|movq (%r12), %rcx|
        movq 8(%r12), %rax|movq 32(%rax), %rax|movq %rcx, 928(%rbp)|
        movq %rax, 912(%rbp)|callq *%rax|nop|movq 968(%rbp), %r14|
        movb $13, %cl|movq %rcx, 944(%rbp)|movq 1104(%rbp), %rbx|
        testb %al, %al|je .B86''')


def cleanup(n):
    return L(f'''.B72:|movq 944(%rbp), %r13|leal -6(%r13), %ecx|
        cmpb $8, %cl|setb %al|movb $-3, %dl|shrb %cl, %dl|
        testb %dl, %al|movq 976(%rbp), %rsi|je .B74|shlb $3, %cl|
        movabsq $940138559942688774, %r13|shrq %cl, %r13|movb $1, %r14b|
        jmp .B75|.B74:|xorl %r14d, %r14d|.B75:|movq %rbx, %rcx|
        vzeroupper|callq {n['workspace_wipe']}|movl $1024, %edx|
        movq %r15, %rcx|callq {life.ZERO}|testb %r14b, %r14b|jne .B78|
        .B76:|movb $1, 16(%rdi)|movq (%rdi), %rax|testq %rax, %rax|
        je .B78|movb $0, 16(%rax)|.B78:|.B79:|leaq 656(%rbp), %rdi|
        leaq 688(%rbp), %rbx|movb %r13b, (%rsi)|movb $-1, 129(%rsi)|
        xorl %esi, %esi|cmpq $64, %rsi|jne .B81|jmp .B84|.B80:|
        addq $16, %rsi|cmpq $64, %rsi|je .B84|.B81:|
        movq 592(%rbp,%rsi), %rcx|testq %rcx, %rcx|je .B80|
        movq 600(%rbp,%rsi), %rdx|testq %rdx, %rdx|je .B80|
        callq {life.ZERO}|addq $16, %rsi|cmpq $64, %rsi|jne .B81|
        .B84:|movl $4, %edx|movq %rbx, %rcx|callq {life.ZERO}|
        movl $32, %edx|movq %rdi, %rcx|callq {life.ZERO}|nop|.B85:|
        addq $1128, %rsp''')+['popq %'+r for r in reversed(digest.shape.SAVES)]+L('vzeroupper|retq|.B86:')
