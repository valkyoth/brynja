"""Complete saved resident digest caller; executor internals are separate."""
import windows_enclave_sha3_simd_worker as worker
life,s,L=worker.life,worker.s,worker.L
VTABLE='anon.bd63e62fb48b7ff6de420100fc540033.0'
SAVES=['rbp','r15','r14','r13','r12','rsi','rdi','rbx']


def retire(n):
    return L(f'''leaq 5200(%rbp), %rcx|movl $1024, %edx|callq {life.ZERO}|
        leaq 7120(%rbp), %rcx|movl $1024, %edx|callq {life.ZERO}|
        leaq -64(%rbp), %rcx|callq {n['workspace_drop']}''')


def shape(n):
    code=['pushq %'+r for r in SAVES]+L(f'''movl $9112, %eax|callq __chkstk|
        subq %rax, %rsp|leaq 128(%rsp), %rbp|movq $-2, 8976(%rbp)|
        movq %r9, %rdi|movq %rcx, %rsi|leaq -64(%rbp), %rcx|
        xorl %r9d, %r9d|callq {n['operation']}|movzbl -56(%rbp), %eax|
        cmpb $2, %al|jne .B2|movzbl -64(%rbp), %eax|movb %al, (%rsi)|
        movb $-1, 25(%rsi)|jmp .B22|.B2:|movb %al, 8975(%rbp)|
        movq -64(%rbp), %rax|movq %rax, 8960(%rbp)''')
    for i in range(4):code+=L(f'''movq {96+112*i}(%rdi), %rax|movq %rax, {8912+8*i}(%rbp)|
        movzbl {104+112*i}(%rdi), %eax|movb %al, {8970+i}(%rbp)''')
    code += [f'movb $-1, {8248+112*i}(%rbp)' for i in range(4)]
    code += L('''movl $104, %eax|leaq -33(%rbp), %rcx|leaq TABLE(%rip), %rdx|
        jmp .B5|.B3:|movq %r15, %r9|orq %r8, %r9|jne .B17|.B4:|
        leaq (%rdi,%rax), %r13|addq $-72, %r13|
        vmovups -31(%r13), %xmm0|vmovups -16(%r13), %xmm1|
        vmovups %xmm1, -49(%rbp)|vmovaps %xmm0, -64(%rbp)|
        vmovups (%r13), %xmm0|vmovups %xmm0, (%rcx)|movq -48(%rbp), %r9|
        vmovups -49(%rbp), %xmm0|vmovups %xmm0, 5215(%rbp)|movq %r9, 5216(%rbp)|
        movl -40(%rbp), %r9d|movl %r9d, 5224(%rbp)|movzwl -36(%rbp), %r9d|
        movw %r9w, 5228(%rbp)|movzbl -34(%rbp), %r9d|movb %r9b, 5230(%rbp)|
        movzbl -33(%rbp), %r9d|vmovups -33(%rbp), %xmm0|
        vmovups %xmm0, 5231(%rbp)|movb %r9b, 5231(%rbp)|movb %bl, 8040(%rbp,%rax)|
        vmovups -64(%rbp), %xmm0|vmovups %xmm0, 5200(%rbp)|
        vmovups 5200(%rbp), %ymm0|vmovups 5215(%rbp), %ymm1|
        vmovups %ymm0, 8041(%rbp,%rax)|vmovups %ymm1, 8056(%rbp,%rax)|
        movq %r8, 8088(%rbp,%rax)|movq %r14, 8096(%rbp,%rax)|
        vmovups 32(%r13), %xmm0|vmovups %xmm0, 8104(%rbp,%rax)|
        movq %r15, 8120(%rbp,%rax)|movq %r12, 8128(%rbp,%rax)|
        movq %r10, 8136(%rbp,%rax)|movb %r11b, 8144(%rbp,%rax)|
        addq $112, %rax|cmpq $552, %rax|je .B23|.B5:|
        cmpq $8192, -88(%rdi,%rax)|ja .B18|movq -56(%rdi,%rax), %r8|
        cmpq $8193, %r8|jae .B18|movq -24(%rdi,%rax), %r15|
        cmpq $8192, %r15|ja .B18|movq -8(%rdi,%rax), %r10|
        cmpq $2048, %r10|ja .B18|movzbl (%rdi,%rax), %r11d|
        movzbl -104(%rdi,%rax), %ebx|movq -48(%rdi,%rax), %r14|
        movq -16(%rdi,%rax), %r12|cmpq $7, %r11|ja .B3|
        movslq (%rdx,%r11,4), %r13|addq %rdx, %r13|jmpq *%r13|
        .B11:|movl $224, %r13d|jmp .B15|.B12:|movl $512, %r13d|jmp .B15|
        .B13:|movl $256, %r13d|jmp .B15|.B14:|movl $384, %r13d|.B15:|
        movq %r15, %r9|orq %r8, %r9|jne .B17|cmpq %r10, %r13|je .B4|
        .B17:|movb $2, (%rsi)|jmp .B19|.B18:|movb $3, (%rsi)|.B19:|
        movb $-1, 25(%rsi)|.B20:|movzbl 8975(%rbp), %eax|testb $1, %al|
        jne .B22|movq 8960(%rbp), %rsi|leaq 72(%rsi), %rcx|
        movl $1024, %edx|vzeroupper''')+['callq '+life.ZERO]+L('''movb $-1, 8(%rsi)|
        movb $2, 1104(%rsi)|movq 64(%rsi), %rax|movb $0, 16(%rax)|.B22:|addq $9112, %rsp''')
    code+=['popq %'+r for r in reversed(SAVES)]+L('''vzeroupper|retq|.B23:|
        movq 8960(%rbp), %rax|movq 64(%rax), %r8|cmpb $1, 16(%r8)|jne .B43|
        movzbl 17(%r8), %ecx|movq %r8, 8944(%rbp)|vzeroupper|callq *8(%r8)|nop|
        testb %al, %al|movq 8944(%rbp), %r8|je .B43|cmpb $1, 16(%r8)|jne .B43|
        movzbl 17(%r8), %ecx|callq *8(%r8)|nop|testb %al, %al|
        movq 8944(%rbp), %r8|je .B43|movl %r8d, %eax|movq %r8, %rcx|shrq $8, %rcx|
        movq %r8, %rdx|shrq $56, %rdx|movb %dl, 8895(%rbp)|shrq $40, %r8|
        movw %r8w, 8893(%rbp)|movl %ecx, 8889(%rbp)|movq $1, 8896(%rbp)|
        movw $512, 8904(%rbp)|movb %al, 8888(%rbp)|vxorps %xmm0, %xmm0, %xmm0''')
    code += [f'vmovups %ymm0, {i}(%rbp)' for i in range(7120,7920,32)]
    code += L('''leaq 5200(%rbp), %rbx|leaq 7120(%rbp), %rdi|movl $800, %r8d|
        movq %rbx, %rcx|movq %rdi, %rdx|vzeroupper|callq memcpy|
        leaq 6320(%rbp), %rcx|vxorps %xmm0, %xmm0, %xmm0''')
    code += [f'vmovups %ymm0, {i}(%rbp)' for i in range(6000,6320,32)]
    code += L('''movl $800, %r8d|movq %rdi, %rdx|vzeroupper|callq memcpy|
        leaq 1856(%rbp), %rcx|movl $3340, %r8d|xorl %edx, %edx|callq memset|
        leaq -64(%rbp), %r14|movl $1920, %r8d|movq %r14, %rcx|movq %rbx, %rdx|callq memcpy|
        movl $1024, %r8d|movq %rdi, %rcx|xorl %edx, %edx|callq memset|
        leaq 5200(%rbp), %r15|movl $1024, %r8d|movq %r15, %rcx|xorl %edx, %edx|callq memset''')
    for i,(source,dest,temp) in enumerate((('rcx','rax','rcx'),('rdx','rcx','edx'),('r8','rdx','r8d'),('r9','r8','r9d'))):
        code+=L(f'''movq {8912+8*i}(%rbp), %{source}|movq %{source}, %{dest}|shrq $3, %{dest}|
            andl $7, %{temp if i else 'ecx'}|cmpq $1, %{source}|sbbq $-1, %{dest}|
            cmpq ${257 if i in (0,3) else 256}, %{dest}|{'jae' if i in (0,3) else 'ja'} .B44''')
    code+=L(f'''leaq 7376(%rbp), %r9|leaq 7632(%rbp), %r10|leaq 7888(%rbp), %r11|
        movq 9088(%rbp), %rbx|movq %rbx, 8768(%rbp)|movq $0, 8776(%rbp)|
        leaq 8959(%rbp), %rbx|movq %rbx, 8752(%rbp)|leaq {VTABLE}(%rip), %rbx|
        movq %rbx, 8760(%rbp)|movq %rdi, 8784(%rbp)|movq %rax, 8792(%rbp)|
        movq %r9, 8800(%rbp)|movq %rcx, 8808(%rbp)|movq %r10, 8816(%rbp)|
        movq %rdx, 8824(%rbp)|movq %r11, 8832(%rbp)|movq %r8, 8840(%rbp)|
        leaq 8752(%rbp), %rax|movq %rax, 48(%rsp)|movq %r15, 40(%rsp)|
        movq %r14, 32(%rsp)|leaq 8608(%rbp), %rcx|leaq 8888(%rbp), %rdx|
        leaq 8144(%rbp), %r8|leaq 8784(%rbp), %r9|callq {n['executor']}|nop|
        movzbl 8737(%rbp), %eax|cmpb $-1, %al|je .B47|movzbl 8608(%rbp), %edx|
        movq 8704(%rbp), %rcx|movq %rcx, 8880(%rbp)|
        vmovups 8673(%rbp), %ymm0|vmovups %ymm0, 8849(%rbp)|
        vmovups 8641(%rbp), %ymm0|vmovups %ymm0, 8817(%rbp)|
        vmovups 8609(%rbp), %ymm0|vmovups %ymm0, 8785(%rbp)|movq 8712(%rbp), %rbx|
        vmovups 8720(%rbp), %xmm0|vmovaps %xmm0, 8592(%rbp)|
        movzbl 8736(%rbp), %ecx|movl 8738(%rbp), %r8d|movl %r8d, 8952(%rbp)|
        movzwl 8742(%rbp), %r8d|movw %r8w, 8956(%rbp)|movb %dl, 8784(%rbp)|
        movb $5, %dil|cmpb $2, %al|je .B41|testb %al, %al|jne .B41|
        testq %rbx, %rbx|je .B41|cmpb $15, %cl|jne .B41|
        movq 8960(%rbp), %rax|movq 64(%rax), %rcx|movb $1, 8974(%rbp)|
        vzeroupper|callq {n['check']}|nop|movl %eax, %edi|cmpb $-1, %al|je .B48|
        .B41:|movb %dil, (%rsi)|movb $-1, 25(%rsi)|leaq 8784(%rbp), %rcx|
        vzeroupper|callq {n['output_drop']}|jmp .B46|.B43:|movb $0, 16(%r8)|
        movb $5, (%rsi)|jmp .B19|.B44:|movb $3, (%rsi)|.B45:|
        movb $-1, 25(%rsi)|.B46:''')+retire(n)+L('''jmp .B20|.B47:|
        movb $6, (%rsi)|jmp .B45|.B48:|movq 8784(%rbp), %r8|
        movb $2, %dil|testq %r8, %r8|je .B41|movq 8792(%rbp), %rdx|
        cmpq $256, %rdx|jbe .B51|.B50:|movb $3, %dil|jmp .B41|.B51:|
        movq 8960(%rbp), %rax|leaq 72(%rax), %rcx|movq %rdx, %r9''')
    code+=L(f'''callq {n['copy']}|cmpb $-1, %al|je .B53|.B52:|
        movb $7, %dil|jmp .B41|.B53:''')
    for i in range(1,4):
        code+=L(f'''movq {8784+16*i}(%rbp), %r8|testq %r8, %r8|je .B41|
            movq {8792+16*i}(%rbp), %rdx''')
        if i==3:code+=['movb $3, %dil']
        code+=L(f'''cmpq $256, %rdx|ja {'.B41' if i==3 else '.B50'}|
            movq 8960(%rbp), %rax|leaq {72+256*i}(%rax), %rcx|
            movq %rdx, %r9|callq {n['copy']}''')
        if i==3:code+=['movb $7, %dil']
        code+=['cmpb $-1, %al','jne '+('.B41' if i==3 else '.B52')]
    code+=L(f'''movq 8880(%rbp), %rax|movq %rax, 8704(%rbp)|
        vmovups 8784(%rbp), %ymm0|vmovups 8816(%rbp), %ymm1|vmovups 8848(%rbp), %ymm2|
        vmovups %ymm2, 8672(%rbp)|vmovups %ymm1, 8640(%rbp)|vmovups %ymm0, 8608(%rbp)|
        leaq 8608(%rbp), %rcx|vzeroupper|callq {n['output_drop']}|
        movq 8960(%rbp), %rax|movq 64(%rax), %rcx|movb $0, 8974(%rbp)|
        callq {n['check']}|nop|cmpb $-1, %al|je .B67|movb %al, (%rsi)|jmp .B45|
        .B67:|movq 8960(%rbp), %rax''')
    for i in range(4):code+=L(f'''movq {8912+8*i}(%rbp), %rcx|
        movq %rcx, {str(16*i) if i else ''}(%rax)|movzbl {8970+i}(%rbp), %ecx|movb %cl, {8+16*i}(%rax)''')
    return code+L('''movb $1, 1104(%rax)|movq %rbx, (%rsi)|vmovaps 8592(%rbp), %xmm0|
        vmovups %xmm0, 8(%rsi)|movw $15, 24(%rsi)|movl 8952(%rbp), %eax|
        movl %eax, 26(%rsi)|movzwl 8956(%rbp), %eax|movw %ax, 30(%rsi)''')+retire(n)+['jmp .B22']
