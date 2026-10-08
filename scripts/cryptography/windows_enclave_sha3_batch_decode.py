"""Complete accelerated wire decoder and eight-descriptor equality helper."""
import windows_enclave_sha3_batch_receive_scalar as scalar

L=scalar.L


def equality():
    out=[]
    for i in range(8):
        for off,byte in ((24*i,False),(24*i+16,True),(24*i+8,False)):
            at=str(off) if off else ''
            out += [('movzbl' if byte else 'movq')+f' {at}(%rcx), '+('%eax' if byte else '%rax'),
                ('cmpb' if byte else 'cmpq')+f' {at}(%rdx), '+('%al' if byte else '%rax')]
            if i==7 and off==176:out+=['sete %al','retq']
            else:out+=['jne .B24']
    return out+['.B24:','xorl %eax, %eax','retq']


def shape(n):
    out=scalar.frame(776)+L('''movq %r8, %rax|movq %rdx, %rdi|movq %rcx, %rsi
        leaq 472(%rsp), %rcx|movl $304, %r8d|movq %rax, %rdx|callq memcpy
        movq 472(%rsp), %r8|movq 480(%rsp), %rax|movq %rax, 72(%rsp)
        movq 488(%rsp), %rax|movq %rax, 48(%rsp)|movq 496(%rsp), %r12|movq 504(%rsp), %rbx
        movq 512(%rsp), %rax|movq %rax, 40(%rsp)|movq 520(%rsp), %rax|movq %rax, 64(%rsp)
        movq 528(%rsp), %rdx|movq 536(%rsp), %rax|movq %rax, 56(%rsp)
        movq 552(%rsp), %r15|movq 544(%rsp), %r14|movq 560(%rsp), %r13''')
    out+=scalar.empty_plan(80,True)+L('''xorl %ecx, %ecx|leaq TABLE0(%rip), %r9|.B1:
        movq 584(%rsp,%rcx), %r10|movb $4, %al|cmpq $255, %r10|ja .B43
        movq 568(%rsp,%rcx), %rbp|movq 576(%rsp,%rcx), %r11|movq %rbp, 80(%rsp,%rcx)
        movq %r11, 88(%rsp,%rcx)|movb %r10b, 96(%rsp,%rcx)|cmpq $8, %rbp|ja .B42
        movslq (%r9,%rbp,4), %rbp|addq %r9, %rbp|jmpq *%rbp|.B37:|cmpq $8, %r10|ja .B43
        cmpq $1024, %r11|jbe .B39|jmp .B43|.B34:|movl $64, %ebp|jmp .B35
        .B32:|movl $32, %ebp|jmp .B35|.B33:|movl $48, %ebp|jmp .B35
        .B41:|orq %r10, %r11|je .B40|jmp .B42|.B31:|movl $28, %ebp|.B35:
        movb $3, %al|cmpq $8, %r10|jne .B43|cmpq %rbp, %r11|jne .B43|.B39:
        testq %r11, %r11|sete %al|testq %r10, %r10|sete %r10b|xorb %al, %r10b
        movb $4, %al|jne .B43|.B40:|addq $24, %rcx|cmpq $192, %rcx|jne .B1
        leaq -92(%rdi), %rcx|cmpq $5, %rcx|setb %r9b|movb $27, %r10b|shrb %cl, %r10b
        movb $3, %al|cmpq $1, 760(%rsp)|jne .B43|cmpq $0, 768(%rsp)|jne .B43
        cmpq $17, %r8|jne .B43|cmpq $8, %rbx|ja .B43|cmpq $1024, %r12|ja .B43
        leaq -100(%rdi), %rcx|cmpq $-10, %rcx|jb .B43|cmpq $0, 72(%rsp)|je .B43
        testq %rdx, %rdx|jne .B43|andb %r10b, %r9b|movq %rbx, %rcx|orq %r12, %rcx
        sete %cl|orb %r9b, %cl|cmpb $1, %cl|jne .B43|testq %r12, %r12|sete %cl
        cmpq $0, 40(%rsp)|sete %dl|xorb %cl, %dl|jne .B43|testq %r12, %r12|sete %cl
        testq %rbx, %rbx|sete %dl|xorb %cl, %dl|testb %r9b, %dl|jne .B43
        leaq -91(%rdi), %rcx|cmpq $4, %rcx|jae .B16|.B20:|cmpq $7, 48(%rsp)|ja .B43
        .B21:|cmpq $90, %rdi|je .B23|cmpq $0, 64(%rsp)|jne .B43|.B23:
        cmpq $91, %rdi|je .B25|movq %r15, %rcx|orq 56(%rsp), %rcx
        movq %r13, %rdx|orq %r14, %rdx|orq %rcx, %rdx|jne .B43|.B25:
        leaq -90(%rdi), %rax|testq $-9, %rax|je .B27''')
    out+=scalar.empty_plan(272,True)+['leaq 80(%rsp), %rcx','leaq 272(%rsp), %rdx','callq '+n['equal']]+L('''
        movl %eax, %ecx|movq 40(%rsp), %rax|notq %rax|cmpq %rax, %r12|setbe %dl
        movb $3, %al|testb %dl, %cl|je .B43|jmp .B29|.B42:|xorl %eax, %eax
        .B43:|movb %al, 1(%rsi)|movb $1, %al|.B30:|movb %al, (%rsi)''')
    out+=scalar.frame(776,True)[:-1]+L('''vzeroupper|retq|.B16:|cmpq $96, %rdi|je .B20
        cmpq $95, %rdi|movq 48(%rsp), %rdx|jne .B19|xorl %ecx, %ecx|testq %r12, %r12
        setne %cl|shll $3, %ecx|cmpq %rcx, %rbx|setne %cl|cmpq $8, %rdx|setae %dl
        orb %cl, %dl|je .B21|jmp .B43|.B19:|testq %rdx, %rdx|jne .B43|jmp .B21
        .B27:|leaq 80(%rsp), %rcx''')+['callq '+n['validate_plan']]+L('''cmpb $-1, %al
        jne .B43|movq 40(%rsp), %rcx|movb $3, %al|addq %r12, %rcx|jb .B43|.B29:
        vmovups 240(%rsp), %ymm0|vmovups %ymm0, 176(%rsi)
        vmovups 208(%rsp), %ymm0|vmovups %ymm0, 144(%rsi)''')
    out += [f'vmovups {80+32*i}(%rsp), %ymm{i}' for i in range(4)]
    out += [f'vmovups %ymm{i}, {16+32*i}(%rsi)' for i in range(3,-1,-1)]
    return out+L('''movq 56(%rsp), %rax|movq %rax, 208(%rsi)|movq %r14, 216(%rsi)
        movq %r15, 224(%rsi)|movq %r13, 232(%rsi)|movq %rdi, 240(%rsi)
        movq 72(%rsp), %rax|movq %rax, 248(%rsi)|movq 48(%rsp), %rax|movq %rax, 256(%rsi)
        movq %r12, 264(%rsi)|movq 40(%rsp), %rax|movq %rax, 272(%rsi)
        movq 64(%rsp), %rax|movq %rax, 280(%rsi)|movb %bl, 288(%rsi)
        xorl %eax, %eax|jmp .B30''')
