"""Reviewed complete SIMD receiver instruction contract, not learned from input."""
import windows_enclave_sha3_simd_worker as worker

life,s,L=worker.life,worker.s,worker.L
ZERO88='alloc_ae5b617db873af5884b308d1de3f7f98'


def shape(n):
    saves=['r15','r14','r13','r12','rsi','rdi','rbp','rbx']
    code=['pushq %'+r for r in saves]+L('''subq $1512, %rsp|movq %rdx, %rsi|
        movq %rcx, %rdi|callq PublicKeccakSimdSource|leaq 12288(%rsi), %r14|
        xorl %ebx, %ebx|movl $384, %r9d|xorl %ecx, %ecx|movq %r14, %rdx|
        movq %rax, %r8|callq PublicKeccakSimdInput|testl %eax, %eax|jne .B49|
        leaq 368(%rsp), %rcx|movl $384, %r8d|movq %r14, %rdx|callq memcpy|
        cmpq $22, 368(%rsp)|jne .B48|movq 376(%rsp), %rax|testq %rax, %rax|
        je .B48|cmpq $2, 392(%rsp)|jne .B48|leaq -101(%rdi), %rcx|
        cmpq $2, %rcx|jae .B7|cmpq $0, 384(%rsp)|jne .B48|
        xorl %ecx, %ecx|jmp .B9|.B7:|cmpq $100, %rdi|jne .B48|
        movq 384(%rsp), %rcx|.B9:|vxorps %xmm0, %xmm0, %xmm0''')
    code += [f'vmovups %ymm0, {at}(%rsp)' for at in (332,320,288,256)]
    code += L('movq %rax, 144(%rsp)|movq %rcx, 152(%rsp)')
    for at in range(80,144,16):code+=L(f'movq $256, {at}(%rsp)|movb $1, {at+8}(%rsp)')
    code += [f'vmovups %ymm0, {at}(%rsp)' for at in (160,192,224)]
    code += L(f'''movl $274, %r14d|movl $8, %r15d|xorl %r12d, %r12d|
        leaq {ZERO88}(%rip), %rbx|leaq switch.table.{n['receive']}(%rip), %r13|
        .B10:|leaq (%rsp,%r12), %rcx|addq $400, %rcx|cmpq $102, %rdi|
        jne .B13|movl $88, %r8d|movq %rbx, %rdx|vzeroupper|callq memcmp|
        testl %eax, %eax|jne .B48|.B12:|addq $3, %r14|addq $16, %r15|
        addq $88, %r12|cmpq $352, %r12|jne .B10|jmp .B43|.B13:|
        movq (%rcx), %rcx|leaq -1(%rcx), %rax|cmpq $7, %rax|ja .B48|
        movq 408(%rsp,%r12), %rdx|cmpq $2048, %rdx|ja .B48|
        cmpq $3, %rax|ja .B17|cmpq %rdx, -8(%r13,%rcx,8)|jne .B48|
        .B17:|movq %rdx, 72(%rsp,%r15)|movb %al, 80(%rsp,%r15)|
        cmpq $101, %rdi|je .B24|movq 416(%rsp,%r12), %rcx|
        testq %rcx, %rcx|je .B24|cmpq $1024, %rcx|ja .B48|
        movq 432(%rsp,%r12), %rdx|movq %rdx, %r8|addq %rcx, %r8|jb .B48|
        testq %rdx, %rdx|je .B48|movq 424(%rsp,%r12), %r8|
        leaq -9(%r8), %r9|cmpq $-8, %r9|jb .B48|
        movq %rcx, -2032(%rsp,%r14,8)|movb %r8b, 78(%rsp,%r14)|
        movq %rdx, -1936(%rsp,%r14,8)|jmp .B25|.B24:|
        movq 416(%rsp,%r12), %rcx|orq 432(%rsp,%r12), %rcx|
        orq 424(%rsp,%r12), %rcx|jne .B48|.B25:|andb $6, %al|
        cmpq $101, %rdi|je .B33|movq 440(%rsp,%r12), %rcx|
        testq %rcx, %rcx|je .B33|cmpq $1024, %rcx|ja .B48|
        cmpb $6, %al|jne .B48|movq 456(%rsp,%r12), %rdx|
        testq %rdx, %rdx|je .B48|movq 448(%rsp,%r12), %r8|
        leaq -1(%r8), %r9|cmpq $7, %r9|ja .B48|movq %rdx, %r9|
        notq %r9|cmpq %r9, %rcx|ja .B48|movq %rcx, -2024(%rsp,%r14,8)|
        movb %r8b, 79(%rsp,%r14)|movq %rdx, -1928(%rsp,%r14,8)|jmp .B34|
        .B33:|movq 440(%rsp,%r12), %rcx|orq 456(%rsp,%r12), %rcx|
        orq 448(%rsp,%r12), %rcx|jne .B48|.B34:|cmpq $101, %rdi|je .B42|
        movq 464(%rsp,%r12), %rcx|testq %rcx, %rcx|je .B42|
        cmpq $1024, %rcx|ja .B48|cmpb $6, %al|jne .B48|
        movq 480(%rsp,%r12), %rax|testq %rax, %rax|je .B48|
        movq 472(%rsp,%r12), %rdx|leaq -1(%rdx), %r8|cmpq $7, %r8|ja .B48|
        movq %rax, %r8|notq %r8|cmpq %r8, %rcx|ja .B48|
        movq %rcx, -2016(%rsp,%r14,8)|movb %dl, 80(%rsp,%r14)|
        movq %rax, -1920(%rsp,%r14,8)|jmp .B12|.B42:|
        movq 464(%rsp,%r12), %rax|orq 480(%rsp,%r12), %rax|
        orq 472(%rsp,%r12), %rax|je .B12|jmp .B48|.B43:|
        movzbl 80(%rsp), %ebp|movl 81(%rsp), %eax|movl %eax, 48(%rsp)|
        movl 84(%rsp), %eax|movl %eax, 51(%rsp)|movzbl 88(%rsp), %ebx|
        leaq 89(%rsp), %rdx|leaq 784(%rsp), %rcx|movl $279, %r8d|
        vzeroupper|callq memcpy|cmpb $-1, %bl|je .B48|
        movb %bpl, 368(%rsp)|movl 48(%rsp), %eax|movl 51(%rsp), %ecx|
        movl %eax, 369(%rsp)|movl %ecx, 372(%rsp)|movb %bl, 376(%rsp)|
        leaq 377(%rsp), %rcx|leaq 784(%rsp), %rdx|movl $279, %r8d|callq memcpy|
        cmpq $102, %rdi|je .B57|cmpq $101, %rdi|je .B55|
        cmpq $100, %rdi|jne .B48|movl $22, %edi|xorl %ebx, %ebx|jmp .B51|
        .B50:|addq $1024, %rbx|incq %rdi|cmpq $12288, %rbx|je .B72|
        .B51:|movq 272(%rsp,%rdi,8), %r9|cmpq $1024, %r9|ja .B48|
        testq %r9, %r9|je .B50|leaq (%rsi,%rbx), %rdx|leaq -21(%rdi), %rcx|
        movq 368(%rsp,%rdi,8), %r8|callq PublicKeccakSimdInput|
        testl %eax, %eax|je .B50|jmp .B48|.B55:|movq 432(%rsp), %r8|
        movq 368(%rsp), %r14|movq 384(%rsp), %r13|movzbl 392(%rsp), %esi|
        movq 400(%rsp), %r15|movzbl 408(%rsp), %r12d|
        movq 416(%rsp), %rdi|movzbl 424(%rsp), %eax|movb %al, 47(%rsp)|
        movq {n['live']}+16(%rip), %rdx|leaq 80(%rsp), %rcx|
        movb $1, %r9b|callq {n['operation']}|movzbl 88(%rsp), %ebp|
        cmpb $2, %bpl|je .B48|movq %rdi, %rcx|movq 80(%rsp), %rdi|
        movzbl 8(%rdi), %eax|cmpb $-1, %al|je .B70|
        cmpb %bl, %al|jne .B70|cmpq %r14, (%rdi)|jne .B70|
        cmpb %sil, 24(%rdi)|jne .B70|cmpq %r13, 16(%rdi)|jne .B70|
        cmpb %r12b, 40(%rdi)|jne .B70|cmpq %r15, 32(%rdi)|jne .B70|
        movzbl 47(%rsp), %eax|cmpb %al, 56(%rdi)|jne .B70|
        cmpq %rcx, 48(%rdi)|jne .B70|leaq 72(%rdi), %rsi|
        movl $1024, %edx|movq %rsi, %rcx|callq PublicKeccakSimdOutput|
        testl %eax, %eax|jne .B70|movq 64(%rdi), %rcx|callq {n['check']}|
        cmpb $-1, %al|je .B82|.B70:|testb $1, %bpl|jne .B48''')
    code += worker.owner.clear('rdi')+L('.B48:|xorl %ebx, %ebx|.B49:|movl %ebx, %eax|addq $1512, %rsp')
    code += ['popq %'+r for r in reversed(saves)]+L(f'''vzeroupper|retq|
        .B57:|movq 432(%rsp), %rdx|movq {n['live']}+16(%rip), %rcx|
        callq {n['cancel']}|cmpb $-1, %al|sete %bl|jmp .B49|.B72:|
        movq $1, 752(%rsp)|vxorps %xmm0, %xmm0, %xmm0|vmovups %xmm0, 760(%rsp)|
        movb $0, 776(%rsp)|leaq 1064(%rsp), %rcx|leaq 368(%rsp), %rdx|
        leaq 752(%rsp), %r8|callq {n['array']}|leaq 112(%rsp), %rbx|
        addq $2048, %rsi|movl $64, %r14d|movl $274, %r15d|
        leaq 784(%rsp), %rdi|.B73:|movq -1744(%rsp,%r15,8), %r8|
        cmpq $1024, %r8|ja .B48|leaq -2048(%rsi), %rdx|
        movzbl 366(%rsp,%r15), %r9d|movq %rdi, %rcx|vzeroupper|
        callq {n['bits']}|cmpq $0, 784(%rsp)|je .B48|vmovups 784(%rsp), %ymm0|
        vmovups %ymm0, 80(%rsp)|movq -1736(%rsp,%r15,8), %r8|
        cmpq $1024, %r8|ja .B48|leaq -1024(%rsi), %rdx|
        movzbl 367(%rsp,%r15), %r9d|movq %rdi, %rcx|vzeroupper|
        callq {n['bits']}|cmpq $0, 784(%rsp)|je .B48|vmovups 784(%rsp), %ymm0|
        vmovups %ymm0, 48(%rsp)|vmovups %ymm0, (%rbx)|
        movq -1728(%rsp,%r15,8), %r8|cmpq $1024, %r8|ja .B48|
        movzbl 368(%rsp,%r15), %r9d|movq %rdi, %rcx|movq %rsi, %rdx|
        vzeroupper|callq {n['bits']}|cmpq $0, 784(%rsp)|je .B48|
        leaq (%rsp,%r14), %rax|addq $1000, %rax|vmovups 784(%rsp), %ymm0|
        vmovups %ymm0, 48(%rsp)|vmovups %ymm0, 32(%rbx)|
        vmovups 80(%rsp), %ymm0|vmovups %ymm0, (%rax)|
        vmovups (%rbx), %ymm0|vmovups %ymm0, 1032(%rsp,%r14)|
        vmovups 32(%rbx), %ymm0|vmovups %ymm0, 1064(%rsp,%r14)|
        addq $112, %r14|addq $3, %r15|addq $3072, %rsi|
        cmpq $512, %r14|jne .B73|movq 432(%rsp), %r8|movq 440(%rsp), %rax|
        movq {n['live']}+16(%rip), %rdx|movq %rax, 32(%rsp)|
        leaq 80(%rsp), %rcx|leaq 1064(%rsp), %r9|vzeroupper|callq {n['digest']}|
        cmpb $-1, 105(%rsp)|setne %bl|jmp .B49|.B82:|movl $1024, %edx|
        movq %rsi, %rcx|callq {life.ZERO}|movb $-1, 8(%rdi)|
        movb $0, 1104(%rdi)|movb $1, %bl|jmp .B49''')
    return code
