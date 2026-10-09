"""Saved four-lane public framing preparation, before any secret absorption."""
import windows_enclave_sha3_simd_digest as digest
life,s,L=digest.life,digest.s,digest.L
TARGETS=(44,18,43,45,19,18,19,18)


def encode(label,slot,first):
    code=L('''movq %r8, 800(%rbp)|movq %r8, %rax|bswapq %rax|
        movq %rax, 792(%rbp)|movq $0, 784(%rbp)|movl $8, %r8d|testb $-1, %al''') if first else L(
        '''movq %r13, %rax|bswapq %rax|movq 800(%rbp), %rcx|movq %rcx, 48(%r14)|
        movq %rax, 792(%rbp)|movq $0, 784(%rbp)|testb $-1, %al|movl $8, %r8d''')
    code+=L(f'''jne .B{label}|movl $9, %r8d|testl $65280, %eax|jne .B{label}|
        movl $10, %r8d|testl $16711680, %eax|jne .B{label}''')
    for shift,width in ((24,11),(32,12),(40,13)):
        code+=L(f'movq %rax, %rcx|shrq ${shift}, %rcx|movl ${width}, %r8d|testb %cl, %cl|jne .B{label}')
    code+=L(f'''movabsq $71776119061217280, %rcx|andq %rcx, %rax|cmpq $1, %rax|
        movl $0, %r8d|adcq $14, %r8|.B{label}:|movl $16, %ebx|subq %r8, %rbx|
        leaq (%r8,%rbp), %r14|addq $784, %r14|addq $239, %r8|
        leaq (%rbx,%rbp), %rcx|addq $-80, %rcx|xorl %edx, %edx|callq memset|
        leaq -80(%rbp), %rcx|movq %r14, %rdx|movq %rbx, %r8|callq memcpy|movb %bl, 176(%rbp)''')
    for i in range(4):code+=[f'vmovups {-80+32*i}(%rbp), %ymm{i}']
    code+=['leaq 177(%rbp), %rax']
    for i in range(4):code+=[f'vmovups %ymm{i}, {str(32*i) if i else ""}(%rax)']
    for source,offset in ((48,128),(80,160),(112,192),(143,223)):
        code+=L(f'vmovups {source}(%rbp), %ymm0|vmovups %ymm0, {offset}(%rax)')
    code+=L(f'''leal 1(%rbx), %r8d|movw %r8w, 432(%rbp)|movq 936(%rbp), %r14|
        leaq {slot}(%r14), %rcx|leaq 176(%rbp), %rdx|vzeroupper|callq memcpy|
        leal 8(,%rbx,8), %eax''')
    return code


def shape(n):
    code=L(f'''.B11:|movq %r14, 968(%rbp)|movq %rsi, 976(%rbp)|movq %rbx, %rcx|
        callq {n['workspace_wipe']}|leaq 3584(%rbx), %rax|movq %rax, 824(%rbp)|
        leaq 5252(%rbx), %rax|movq %rax, 480(%rbp)|xorl %r12d, %r12d|
        xorl %esi, %esi|xorl %r8d, %r8d|.B12:|movq 968(%rbp), %rcx|.B13:|
        cmpq $448, %rsi|je .B63|movq %r12, %rax|cmpq $-1, %r12|je .B233|
        leaq 1(%rax), %r12|movzbl 104(%rcx,%rsi), %r13d|addq $112, %rsi|
        cmpl $255, %r13d|je .B13|cmpq $3, %rax|ja .B212|movq %r8, 928(%rbp)|
        movq %rdi, 960(%rbp)|imulq $156, %rax, %rdi|movq 824(%rbp), %r15|
        leaq (%r15,%rdi), %rbx|leaq (%r15,%rdi), %rcx|addq $32, %rcx|
        movl $72, %edx|movq %rcx, 944(%rbp)|callq {life.ZERO}|
        leaq (%r15,%rdi), %r14|addq $104, %r14|movl $51, %edx|movq %r14, %rcx|
        callq {life.ZERO}|movl $32, %edx|movq %rbx, 936(%rbp)|movq %rbx, %rcx|
        callq {life.ZERO}|leaq (%r15,%rdi), %rcx|addq $155, %rcx|movl $1, %edx|
        callq {life.ZERO}|movl %r13d, %eax|leaq .LJTI30_0(%rip), %rcx|
        movslq (%rcx,%rax,4), %rax|addq %rcx, %rax|jmpq *%rax|
        .B18:|movl $136, %ecx|jmp .B20|.B19:|movl $168, %ecx|.B20:|
        leal (,%rcx,8), %r9d|movl %r13d, %eax|notb %al|testb $6, %al|
        movq 960(%rbp), %rdi|movq %rcx, 912(%rbp)|jne .B41|
        movq 968(%rbp), %rax|movq -64(%rax,%rsi), %r8|movq -32(%rax,%rsi), %rdx|
        movq %r8, %rax|orq %rdx, %rax|movq 1112(%rbp), %r15|je .B42|
        movq %rdx, %r13|movq %r9, 952(%rbp)|movl %ecx, %eax|shll $8, %eax|
        incl %eax|movw %ax, (%r14)|movq 944(%rbp), %rax|movq $16, (%rax)''')
    code+=encode(29,121,True)+L('movq %rax, 944(%rbp)|movq %rax, 40(%r14)')
    code+=encode(36,138,False)+L('''movq %rax, 56(%r14)|movq %r13, 64(%r14)|
        movq 944(%rbp), %rdx|addq $16, %rdx|movb $11, %cl|movq %rcx, 944(%rbp)|
        movq 800(%rbp), %rcx|addq %rdx, %rcx|jb .B216|addq %rcx, %rax|
        movq 1104(%rbp), %rbx|movq 968(%rbp), %r8|
        movabsq $4611686014132420608, %r10|movq 928(%rbp), %r11|
        movq 952(%rbp), %r9|jb .B72|addq %rax, %r13|jb .B72|
        movq %r13, %rax|shrq $32, %rax|je .B60|movq %r13, %rax|
        xorl %edx, %edx|divq %r9|jmp .B61|.B41:|movq 1112(%rbp), %r15|
        .B42:|movq 1104(%rbp), %rbx|movq 968(%rbp), %rax|
        movabsq $4611686014132420608, %r10|movq 928(%rbp), %r11|jmp .B47|
        .B43:|movl $104, %ecx|jmp .B46|.B44:|movl $144, %ecx|jmp .B46|
        .B45:|movl $72, %ecx|.B46:|movq 960(%rbp), %rdi|
        movq 968(%rbp), %rax|movabsq $4611686014132420608, %r10|
        movq 928(%rbp), %r11|movq %rcx, 912(%rbp)|leal (,%rcx,8), %r9d|
        movq 1112(%rbp), %r15|movq 1104(%rbp), %rbx|.B47:|
        movq 936(%rbp), %r14|movq -96(%rax,%rsi), %rcx|movq %rcx, 80(%r14)|
        xorl %eax, %eax|cmpb $4, %r13b|movl $31, %edx|movl $6, %r8d|
        cmovbl %r8d, %edx|setae %al|leaq 3(,%rax,2), %rax|
        movb %dl, 155(%r14)|movq %rax, 88(%r14)|.B48:|
        movb $11, %dl|movq %rdx, 944(%rbp)|addq %rax, %rcx|jb .B72|
        movq %rcx, %rax|shrq $32, %rax|movq 968(%rbp), %r8|je .B51|
        movq %rcx, %rax|xorl %edx, %edx|divq %r9|jmp .B52|
        .B51:|movl %ecx, %eax|xorl %edx, %edx|divl %r9d|.B52:|
        movq %r9, %rax|subq %rdx, %rax|movq %rax, 96(%r14)|
        addq %rcx, %rax|jb .B72|movq %rax, %rcx|shrq $32, %rcx|je .B55|
        xorl %edx, %edx|divq %r9|movq %rax, %rcx|jmp .B56|.B55:|
        xorl %edx, %edx|divl %r9d|movl %eax, %ecx|.B56:|
        movq -16(%r8,%rsi), %rax|movq %rax, %r8|shrq $3, %r8|
        xorl %r9d, %r9d|testb $7, %al|setne %r9b|leaq (%r8,%r9), %rax|
        cmpq $1, %rax|adcq $-1, %rax|testq %r10, %rax|je .B58|
        xorl %edx, %edx|divq 912(%rbp)|jmp .B59|.B58:|
        xorl %edx, %edx|divl 912(%rbp)|.B59:|addq %rcx, %rax|
        movq %rcx, 16(%r14)|movq %rax, 24(%r14)|cmpq 8(%rdi), %rax|
        setae 5251(%rbx,%r12)|movb $1, 5255(%rbx,%r12)|
        movq %r11, 3512(%rbx,%r12,8)|addq %r11, %r8|addq %r9, %r8|
        cmpq %r11, %r8|jae .B12|jmp .B72|.B60:|movl %r13d, %eax|
        xorl %edx, %edx|divl %r9d|.B61:|movq %r9, %rcx|subq %rdx, %rcx|
        cmpq %r9, %rcx|movl $0, %eax|cmovaeq %r9, %rax|subq %rax, %rcx|
        movq %rcx, 72(%r14)|addq %r13, %rcx|jb .B72|
        movq -96(%r8,%rsi), %rdx|movq %rdx, 80(%r14)|movb $4, 155(%r14)|
        movq $3, 88(%r14)|movl $3, %eax|addq %rdx, %rcx|jae .B48|jmp .B72|.B63:''')
    return code
