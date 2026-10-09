"""Saved vector selection, checked charge, gather/session/scatter and counters."""
import windows_enclave_sha3_simd_absorb_shape as absorb
life,s,L=absorb.life,absorb.s,absorb.L


def names(bodies):
    return absorb.names(bodies)|{'session':s.one(bodies,r'^[^?].*keccak_hardened_batch.*Session13permute_bytes$')}


def selection():
    return L('''.B131:|cmpb $0, 5248(%rbx)|jne .B135|cmpb $0, 5249(%rbx)|jne .B135|
        cmpb $0, 5250(%rbx)|jne .B135|cmpb $0, 5251(%rbx)|je .B219|.B135:|
        cmpq $0, 800(%rbp)|je .B190|.B136:|vxorps %xmm0, %xmm0, %xmm0|
        vmovups %ymm0, 176(%rbp)|xorl %eax, %eax|xorl %r8d, %r8d|xorl %ecx, %ecx|
        jmp .B138|.B137:|movq %rdx, %r8|.B138:|cmpq $3, %rax|ja .B141|
        cmpq $-1, %r8|je .B233|leaq 1(%rax), %r10|movq 480(%rbp), %rdx|
        leaq (%rdx,%rax), %r9|addq %r11, %rax|leaq 1(%r8), %rdx|
        movq %rax, -80(%rbp)|movq %r10, %rax|movq %r8, 520(%rbp)|
        leaq 784(%rbp), %r8|jmp .B142|.B141:|movq %r8, %rdx|
        leaq -80(%rbp), %r8|xorl %r9d, %r9d|.B142:|movq %r9, (%r8)|
        movq -80(%rbp), %r8|testq %r8, %r8|je .B147|cmpb $1, (%r8)|jne .B137|
        movq 784(%rbp), %r8|cmpb $1, (%r8)|jne .B137|cmpq $4, %rcx|jae .B214|
        movq 520(%rbp), %r8|movq %r8, 176(%rbp,%rcx,8)|incq %rcx|
        cmpq 936(%rbp), %rcx|jne .B137|jmp .B148|.B147:|cmpq 936(%rbp), %rcx|
        jne .B190|.B148:|movb $14, %sil|cmpq $0, (%rdi)|je .B227|
        movq 928(%rbp), %rcx|vzeroupper|callq *912(%rbp)|nop|testb %al, %al|jne .B224|
        movq 16(%r12), %rax|movq 936(%rbp), %rbx|subq %rbx, %rax|jb .B225|
        movq 24(%r12), %rcx|addq %rbx, %rcx|jb .B227|
        movq %rax, 16(%r12)|movq %rcx, 24(%r12)''')


def gather(n):
    code=L(f'''movl $800, %edx|movq 776(%rbp), %r14|movq %r14, %rcx|callq {life.ZERO}''')
    for i,slot in enumerate((None,728,736,752)):
        if i==2:code+=L('cmpq $2, %rbx|je .B163')
        if i==3:code+=L('cmpq $3, %rbx|je .B163')
        code+=L(f'movq {176+8*i}(%rbp), %rax|cmpq ${4 if i==0 else 3}, %rax|'+
            ('jae' if i==0 else 'ja')+f''' .B227|imulq $200, %rax, %r8|addq 960(%rbp), %r8|
            movl $200, %edx|movl $200, %r9d|''')
        code+=L('movq %r14, %rcx' if slot is None else f'movq {slot}(%rbp), %rcx')
        code+=L(f'callq {n["copy"]}|cmpb $-1, %al|jne .B227')
    return code+L(f'''.B163:|movq (%rdi), %rcx|movq (%rcx), %rbx|movq 776(%rbp), %rdx|
        movq 1104(%rbp), %r8|callq {n['session']}|nop|cmpb $-1, %al|jne .B226|
        cmpq $-1, %rbx|je .B227|incq %rbx|movq (%rdi), %rax|
        cmpq %rbx, (%rax)|jne .B227''')


def scatter(n):
    code=L('movq 176(%rbp), %rbx|cmpq $4, %rbx|movq 776(%rbp), %r8|jae .B227')
    for i,slot in enumerate((None,728,736,752)):
        if i==2:code+=L('.B173:')
        if i==3:code+=L('.B177:')
        if i:code+=L(f'movq {176+8*i}(%rbp), %rbx|cmpq $3, %rbx|ja .B227')
        code+=L('imulq $200, %rbx, %rcx|addq 960(%rbp), %rcx|movl $200, %edx|movl $200, %r9d')
        if slot is not None:code+=[f'movq {slot}(%rbp), %r8']
        code+=L(f'callq {n["copy"]}|cmpb $-1, %al|jne .B227')
        if i==0:code+=L('movb $1, %r14b|movl %ebx, %ecx|shlb %cl, %r14b')
        else:
            code+=L('movb $1, %al|movl %ebx, %ecx|shlb %cl, %al')
            if i<3:code+=L('orb %al, %r14b')
        if i==1:code+=L('''movq 856(%rbp), %rax|orb %r14b, %al|movq %rax, %r14|
            cmpq $2, 936(%rbp)|jne .B173|movq %r14, 856(%rbp)|movq 968(%rbp), %r14|jmp .B180''')
        if i==2:code+=L('''movq %r14, 856(%rbp)|cmpq $3, 936(%rbp)|jne .B177|
            movq 968(%rbp), %r14|jmp .B180''')
        if i==3:code+=L('''movq 856(%rbp), %rcx|orb %al, %cl|movq %rcx, 856(%rbp)|
            movq 968(%rbp), %r14|movq 1120(%rbp), %r12''')
    return code


def retirement():
    code=L('''.B180:|incq %r13|movq 1104(%rbp), %rbx|je .B228|
        movq 936(%rbp), %rax|addq %rax, 744(%rbp)|jb .B228|
        movq 176(%rbp), %rax|cmpq $4, %rax|jae .B228|movq (%rdi), %rcx|
        movzbl 17(%rcx), %ecx|movb %cl, 991(%rbp)|movq 888(%rbp), %rcx|
        movb $0, (%rcx,%rax)''')
    for i in range(1,4):
        code+=L(f'movq {176+8*i}(%rbp), %rax|cmpq $3, %rax|ja .B228')
        if i>1:code+=L('movq 888(%rbp), %rcx')
        code+=L('movb $0, (%rcx,%rax)')
        if i<3:code+=L(f'cmpq ${i+1}, 936(%rbp)|je .B189')
    return code+L('.B189:|movq 888(%rbp), %r11|jmp .B136')


def shape(n):return selection()+gather(n)+scatter(n)+retirement()
