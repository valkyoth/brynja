"""Saved inner-loop setup and one lane's bounded squeeze/ready transition."""
import windows_enclave_sha3_simd_digest as digest
life,s,L=digest.life,digest.s,digest.L


def setup():
    code=L('.B86:|leaq 5248(%rbx), %r11')
    for offset,slot in ((1920,960),(2720,776),(4208,496),(4256,704),(4960,488),
                        (5000,712),(5040,720),(2920,728),(3120,736),(3320,752)):
        code+=L(f'leaq {offset}(%rbx), %rax|movq %rax, {slot}(%rbp)')
    return code+L('''leaq 3624(%rbx), %rsi|movb $2, 991(%rbp)|movq $0, 856(%rbp)|
        xorl %eax, %eax|movq $0, 744(%rbp)|xorl %r13d, %r13d|
        movq %r11, 888(%rbp)|movq %rsi, 504(%rbp)|.B87:|
        movq %rax, 808(%rbp)|movl $0, (%r11)|movq %rsi, %rdx|
        xorl %r8d, %r8d|xorl %r9d, %r9d|jmp .B92''')


def ready():
    return L('''.B88:|movq 1104(%rbp), %rbx|.B89:|cmpq $1, %r10|
        sbbq $-1, %rsi|cmpq %rsi, %r11|setb %al|.B90:|
        movq 888(%rbp), %r11|movb %al, (%r11,%r9)|movq 968(%rbp), %r14|
        movq 1120(%rbp), %r12|.B91:|addq $112, %r8|incq %r9|addq $156, %rdx|
        cmpq $448, %r8|je .B131|.B92:|movzbl 104(%r14,%r8), %eax|
        cmpq $255, %rax|je .B91|cmpb $1, 5256(%rbx,%r9)|jne .B122''')


def squeeze(n):
    return L(f'''.B122:|movq 3552(%rbx,%r9,8), %r11|movq 96(%r14,%r8), %r10|
        movq %r10, %rsi|shrq $3, %rsi|xorl %ebx, %ebx|andq $7, %r10|
        setne %bl|addq %rsi, %rbx|movq %rbx, %r12|subq %r11, %r12|
        jb .B207|leaq switch.table.{n['executor']}(%rip), %rcx|
        movq (%rcx,%rax,8), %rax|cmpq %r12, %rax|cmovbq %rax, %r12|
        cmpq %r11, %rbx|je .B88|movq 1104(%rbp), %rax|
        movq 3520(%rax,%r9,8), %r14|addq %r11, %r14|jb .B207|
        movq %r14, %rax|addq %r12, %rax|setb %cl|cmpq $1025, %rax|
        setae %al|orb %cl, %al|jne .B207|movq %r11, 816(%rbp)|
        movq %r10, 952(%rbp)|movq %r8, 832(%rbp)|movq %rdx, 896(%rbp)|
        addq %r15, %r14|imulq $200, %r9, %r8|addq 960(%rbp), %r8|
        movq %r14, %rcx|movq %r12, %rdx|movq %r9, 864(%rbp)|movq %r12, %r9|
        vzeroupper|callq {n['copy']}|cmpb $-1, %al|jne .B207|
        movq 816(%rbp), %r11|addq %r12, %r11|movq 1104(%rbp), %rax|
        movq 864(%rbp), %r9|movq %r11, 3552(%rax,%r9,8)|movq 952(%rbp), %r10|
        testq %r10, %r10|movq 896(%rbp), %rdx|movq 832(%rbp), %r8|je .B88|
        cmpq %rbx, %r11|movq 1104(%rbp), %rbx|jne .B89|
        leaq (%r14,%r12), %rax|decq %rax|leal (,%r10,8), %ecx|addb $-8, %cl|
        movabsq $35816724670907137, %rdx|shrq %cl, %rdx|movq %rax, %rcx|
        movq %r9, %r14|callq {n['mask']}|movq 952(%rbp), %r10|
        movq %r14, %r9|movq 832(%rbp), %r8|movq 896(%rbp), %rdx|
        movq 3552(%rbx,%r14,8), %r11|jmp .B89''')
