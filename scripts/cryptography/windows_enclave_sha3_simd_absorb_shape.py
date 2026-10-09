"""Reviewed saved absorption loop, including all nine framing-part targets."""
import windows_enclave_sha3_simd_squeeze as squeeze
life,s,L=squeeze.life,squeeze.s,squeeze.L
TARGETS=(103,103,112,103,107,118,110,108,119)


def names(bodies):
    return squeeze.names(bodies)|{role:s.one(bodies,pattern) for role,pattern in (
        ('xor',r'secret_memory20xor_secret_byte_bits$'),('xor_leaf',r'secret_memory_xor8xor_bits$'))}


def shape(n):
    return L(f'''imulq $156, %r9, %r12|movq 824(%rbp), %rcx|
        movq 16(%rcx,%r12), %r10|testq %r10, %r10|movq 976(%rbp), %rsi|je .B213|
        addq %rcx, %r12|imulq $200, %r9, %r11|addq 960(%rbp), %r11|decq %r10|
        movzbl %al, %eax|leaq switch.table.{n['executor']}.104(%rip), %rcx|
        movq (%rcx,%rax,8), %rax|addq %r11, %rax|movq %rax, 576(%rbp)|
        movq (%r12), %rbx|movq 8(%r12), %rcx|movq 96(%r12), %rax|
        movq %rax, 528(%rbp)|leaq 155(%r12), %rax|movq %rax, 568(%rbp)|
        movq (%r14,%r8), %rax|movq %rax, 536(%rbp)|movq 8(%r14,%r8), %rax|
        movq %rax, 544(%rbp)|movq 64(%r14,%r8), %rax|movq %rax, 552(%rbp)|
        movq 72(%r14,%r8), %rax|movq %rax, 560(%rbp)|movq 32(%r14,%r8), %rax|
        movq %rax, 816(%rbp)|movq 40(%r14,%r8), %rax|movq %rax, 760(%rbp)|
        leaq 104(%r12), %rax|movq %rax, 512(%rbp)|.B96:|movq $0, 952(%rbp)|
        .B97:|cmpq $8, %rbx|ja .B211|movq %rcx, %r14|movq 32(%r12,%rbx,8), %rax|
        movq %rax, %rcx|subq %r14, %rcx|jb .B211|jne .B104|.B100:|
        cmpq $8, %rbx|je .B210|movq (%rdx,%rbx,8), %rax|incq %rbx|testq %rax, %rax|
        je .B100|movq %r8, 832(%rbp)|movq %rbx, (%r12)|movq $0, 8(%r12)|
        movl $8, %r8d|subq 952(%rbp), %r8|cmpq %rax, %r8|cmovaeq %rax, %r8|
        leaq .LJTI30_1(%rip), %rcx|movslq (%rcx,%rbx,4), %rax|addq %rcx, %rax|
        movq %r8, %rcx|movq %r8, 872(%rbp)|xorl %r14d, %r14d|movq 816(%rbp), %rsi|
        movq 760(%rbp), %r8|movq %r8, 840(%rbp)|movq 872(%rbp), %r8|jmpq *%rax|
        .B103:|xorl %eax, %eax|cmpq $1, %rbx|setne %al|incq %rax|testq %rbx, %rbx|
        cmoveq %rbx, %rax|movl %eax, %esi|shll $4, %esi|orq %rax, %rsi|
        addq 512(%rbp), %rsi|movl $17, %eax|jmp .B111|.B104:|
        movq %r10, 904(%rbp)|movq %r11, %r10|movl $8, %r11d|subq 952(%rbp), %r11|
        cmpq %rcx, %r11|cmovaeq %rcx, %r11|movq %r11, %rcx|addq %r14, %rcx|jb .B211|
        movq %r14, 920(%rbp)|movq %r11, 872(%rbp)|movq %r10, %r11|
        movq 904(%rbp), %r10|movq %r8, 832(%rbp)|cmpq %rax, %rcx|ja .B207|
        movq %rcx, %r8|leaq .LJTI30_1(%rip), %rcx|movslq (%rcx,%rbx,4), %rax|
        addq %rcx, %rax|movq 816(%rbp), %rsi|movq 760(%rbp), %rcx|
        movq %rcx, 840(%rbp)|movq %r8, %rcx|movq 872(%rbp), %r8|
        movq 920(%rbp), %r14|jmpq *%rax|.B107:|movq 552(%rbp), %rsi|
        movq 560(%rbp), %rax|jmp .B111|.B108:|movq %rcx, 920(%rbp)|
        movq %r10, 904(%rbp)|movq %r12, 880(%rbp)|cmpq $255, %r14|ja .B207|
        movq %r8, %rax|movq %r9, %r12|movq %rdx, %rsi|movq 952(%rbp), %rcx|
        movb %cl, 32(%rsp)|movq %r11, %rcx|movq 568(%rbp), %rdx|
        movl %r14d, %r8d|movq %rax, %r14|movl %r14d, %r9d|movq %r11, 848(%rbp)|
        vzeroupper|callq {n['xor']}|movq %r14, %r8|movq 848(%rbp), %r11|
        testb %al, %al|movq %rsi, %rdx|movq %r12, %r9|movq 880(%rbp), %r12|
        movq 904(%rbp), %r10|movq 920(%rbp), %rcx|jne .B207|jmp .B118|
        .B110:|movq 536(%rbp), %rsi|movq 544(%rbp), %rax|.B111:|movq %rax, 840(%rbp)|
        .B112:|movq %rsi, 768(%rbp)|movq %rcx, 920(%rbp)|movq %r12, 880(%rbp)|
        movq %r10, 904(%rbp)|movq %rdx, 896(%rbp)|movq %r9, 864(%rbp)|movq %r8, %rax|
        movl %r14d, %r8d|andl $7, %r8d|movl $8, %r12d|subq %r8, %r12|
        cmpq %rax, %r12|movq %rax, 872(%rbp)|movq %rax, %r9|cmovbq %r12, %r9|
        shrq $3, %r14|movq 840(%rbp), %rax|cmpq %rax, %r14|jae .B207|
        movq %rax, %rsi|movq 768(%rbp), %rax|leaq (%rax,%r14), %rdx|
        movq 952(%rbp), %rax|movb %al, 32(%rsp)|movq %r11, 848(%rbp)|
        movq %r11, %rcx|movq %r9, 584(%rbp)|vzeroupper|callq {n['xor']}|
        testb %al, %al|jne .B207|movq 872(%rbp), %r8|cmpq %r8, %r12|
        movq 896(%rbp), %rdx|movq 864(%rbp), %r9|movq 904(%rbp), %r10|jae .B117|
        incq %r14|cmpq %rsi, %r14|movq 880(%rbp), %r12|movq 848(%rbp), %rcx|jae .B207|
        movq 768(%rbp), %rdx|addq %r14, %rdx|movl %r8d, %r9d|movq 584(%rbp), %r8|
        subl %r8d, %r9d|movq 952(%rbp), %rax|addl %r8d, %eax|movb %al, 32(%rsp)|
        xorl %r14d, %r14d|xorl %r8d, %r8d|callq {n['xor']}|movq 872(%rbp), %r8|
        movq 848(%rbp), %r11|testb %al, %al|movq 896(%rbp), %rdx|movq 864(%rbp), %r9|
        movq 904(%rbp), %r10|movq 920(%rbp), %rcx|jne .B208|jmp .B118|.B117:|
        movq 880(%rbp), %r12|movq 848(%rbp), %r11|movq 920(%rbp), %rcx|.B118:|
        movq %rcx, 8(%r12)|movq 952(%rbp), %rax|addq %r8, %rax|movq %rax, 952(%rbp)|
        cmpq $8, %rax|movq 976(%rbp), %rsi|movq 832(%rbp), %r8|jb .B97|jmp .B120|
        .B119:|movq %r10, 904(%rbp)|movq %rcx, 920(%rbp)|movq %r9, 864(%rbp)|
        movq %r12, 880(%rbp)|movq %rdx, 896(%rbp)|leal -1(%r8), %ecx|
        movb $1, %al|shlb %cl, %al|xorl %r14d, %r14d|movq 920(%rbp), %rcx|
        cmpq 528(%rbp), %rcx|movzbl %al, %eax|cmovnel %r14d, %eax|
        movb %al, 176(%rbp)|movq 952(%rbp), %rax|movb %al, 32(%rsp)|
        movq %r11, %rcx|leaq 176(%rbp), %rdx|movq %r8, %rsi|xorl %r8d, %r8d|
        movl %esi, %r9d|movq %r11, %r12|vzeroupper|callq {n['xor']}|
        movq %rsi, %r8|movq 920(%rbp), %rcx|movq %r12, %r11|movq 904(%rbp), %r10|
        movq 864(%rbp), %r9|movq 880(%rbp), %r12|movq 896(%rbp), %rdx|
        testb %al, %al|jne .B208|jmp .B118|.B120:|incq %r11|cmpq 576(%rbp), %r11|
        jne .B96|movq %r10, 16(%r12)|testq %r10, %r10|movq 1104(%rbp), %rbx|
        setne 5256(%rbx,%r9)|movb $1, %al|jmp .B90''')
