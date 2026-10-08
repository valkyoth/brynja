"""Complete accelerated receiver and inlined fixed-output export contracts."""
import windows_enclave_sha3_batch_receive_scalar as scalar

L,life=scalar.L,scalar.life


def prefix(n,live):
    return scalar.frame(680)+L('''movq %rdx, %rdi|movq %rcx, %r14|callq PublicSha3BatchSource
        leaq 1024(%rdi), %r15|xorl %ebx, %ebx|movl $304, %r9d|xorl %ecx, %ecx
        movq %r15, %rdx|movq %rax, %r8|callq PublicSha3BatchInput|testl %eax, %eax
        jne .B54|leaq 368(%rsp), %rcx|movq %r14, %rdx|movq %r15, %r8''')+[
        'callq '+n['decode']]+L('''cmpb $1, 368(%rsp)|je .B53|movq 632(%rsp), %rbx
        cmpq $1024, %rbx|ja .B53|testq %rbx, %rbx|je .B4|movq 640(%rsp), %r8
        movl $1, %ecx|movq %rdi, %rdx|movq %rbx, %r9|callq PublicSha3BatchInput
        testl %eax, %eax|je .B4|.B53:|xorl %ebx, %ebx|.B54:|movl %ebx, %eax''')+scalar.frame(680,True)+[
        '.B4:',f'movq {live}+16(%rip), %rsi','leaq 368(%rsp), %rcx','movq %r14, %rdx',
        'movq %r15, %r8','callq '+n['decode']]+L('''cmpb $1, 368(%rsp)|je .B44
        cmpq 632(%rsp), %rbx|jne .B44|movq 608(%rsp), %rax|leaq -90(%rax), %rcx
        cmpq $9, %rcx|ja .B44|movq 384(%rsp), %r15|movq 392(%rsp), %r11
        movzbl 400(%rsp), %r10d|movq 408(%rsp), %rbp|movq 416(%rsp), %r14
        movzbl 424(%rsp), %r13d|movq 432(%rsp), %rdx|movq %rdx, 144(%rsp)
        movq 440(%rsp), %rdx|movq %rdx, 136(%rsp)|movzbl 448(%rsp), %edx|movb %dl, 71(%rsp)
        movq 456(%rsp), %rdx|movq %rdx, 128(%rsp)|movq 464(%rsp), %rdx|movq %rdx, 120(%rsp)
        movzbl 472(%rsp), %edx|movb %dl, 70(%rsp)|movq 480(%rsp), %rdx|movq %rdx, 152(%rsp)
        movq 488(%rsp), %rdx|movq %rdx, 112(%rsp)|movzbl 496(%rsp), %edx|movb %dl, 69(%rsp)
        movzbl 520(%rsp), %edx|movb %dl, 68(%rsp)|leaq TABLE0(%rip), %rdx
        movslq (%rdx,%rcx,4), %r9|addq %rdx, %r9|movzbl 544(%rsp), %ecx|movb %cl, 67(%rsp)
        movzbl 568(%rsp), %ecx|movb %cl, 66(%rsp)|movzbl 656(%rsp), %ecx
        movq 504(%rsp), %r12|movq 512(%rsp), %rdx|movq %rdx, 104(%rsp)
        movq 528(%rsp), %rdx|movq %rdx, 96(%rsp)|movq 536(%rsp), %rdx
        movq 552(%rsp), %r8|movq %r8, 80(%rsp)|movq 560(%rsp), %r8|movq %r8, 88(%rsp)
        movq 616(%rsp), %r8|movq %r8, 72(%rsp)|movq 624(%rsp), %r8|jmpq *%r9''')


def begin_plan():
    out=L('''movq %r15, 176(%rsp)|movq %r11, 184(%rsp)|movb %r10b, 192(%rsp)
        leaq 401(%rsp), %rax|movl (%rax), %ecx|movl %ecx, 193(%rsp)
        movl 3(%rax), %ecx|movl %ecx, 196(%rsp)|movq %rbp, 200(%rsp)
        movq %r14, 208(%rsp)|movb %r13b, 216(%rsp)|movl 24(%rax), %ecx
        movl %ecx, 217(%rsp)|movl 27(%rax), %ecx|movl %ecx, 220(%rsp)''')
    fields=[('144(%rsp)','136(%rsp)',71),('128(%rsp)','120(%rsp)',70),
            ('152(%rsp)','112(%rsp)',69),('%r12','104(%rsp)',68),
            ('96(%rsp)','%rdx',67),('80(%rsp)','88(%rsp)',66)]
    for i,(ident,width,last) in enumerate(fields,2):
        for value,off in ((ident,176+24*i),(width,184+24*i)):
            if value.startswith('%'):out += [f'movq {value}, {off}(%rsp)']
            else:out += [f'movq {value}, %rcx',f'movq %rcx, {off}(%rsp)']
        out += [f'movzbl {last}(%rsp), %ecx',f'movb %cl, {192+24*i}(%rsp)']
        # Two overlapping four-byte transfers copy seven representation-padding
        # bytes. No public-data classification or individual erasure is claimed.
        order=(0,3) if i==2 else (3,0)
        for extra in order:
            reg='eax' if i==7 and extra==0 else 'ecx'
            out += [f'movl {24*i+extra}(%rax), %{reg}',f'movl %{reg}, {193+24*i+extra}(%rsp)']
    return out


def export(n):
    out=L('''.B15:|movl %r10d, %ebx|movq %r11, %rdi|movq %r12, 168(%rsp)
        movq 152(%rsp), %r12|movq %rdx, 160(%rsp)|leaq 176(%rsp), %rcx
        movq %rsi, %rdx|movq 72(%rsp), %r8|movb $4, %r9b''')+['callq '+n['operation']]+L('''
        movzbl 184(%rsp), %edx|cmpb $2, %dl|je .B44|movq 176(%rsp), %rcx''')
    fields=[('%r15','%rdi','%bl'),('%rbp','%r14','%r13b'),
        ('144(%rsp)','136(%rsp)',71),('128(%rsp)','120(%rsp)',70),
        ('%r12','112(%rsp)',69),('168(%rsp)','104(%rsp)',68),
        ('96(%rsp)','160(%rsp)',67),('80(%rsp)','88(%rsp)',66)]
    for i,(ident,width,last) in enumerate(fields):
        for value,off,byte in ((ident,1024+24*i,False),(last,1040+24*i,True),(width,1032+24*i,False)):
            if isinstance(value,int):out += [f'movzbl {value}(%rsp), %eax'];value='%al'
            elif not value.startswith('%'):out += [f'movq {value}, %rax'];value='%rax'
            out += [('cmpb' if byte else 'cmpq')+f' {off}(%rcx), {value}','jne .B43']
    return out+L('''movl %edx, %ebx|movl $1024, %edx|movq %rcx, %rdi
        callq PublicSha3BatchOutput|testl %eax, %eax|jne .B42|movq 2224(%rdi), %rcx''')+[
        'callq '+n['authority']]+L('''cmpb $-1, %al|je .B47|.B42:
        movq %rdi, %rcx|movl %ebx, %edx|.B43:''')+['callq '+n['guard'],'jmp .B44',
        '.B47:','movq %rdi, %rcx','callq '+n['clear']]+L('''movb $1, %bl|xorl %eax, %eax
        movb %al, 2249(%rdi)|jmp .B54''')


def shape(n,live):
    out=prefix(n,live)+L('''.B10:|cmpq $92, %rax|sete %r9b|movb %cl, 48(%rsp)
        movq %rbx, 40(%rsp)|movq %rdi, 32(%rsp)|movq %rsi, %rcx|movq 72(%rsp), %rdx''')+[
        'callq '+n['setup_chunk'],'jmp .B50','.B11:','movq %rsi, %rcx','movq 72(%rsp), %rdx',
        'callq '+n['finish_setup'],'jmp .B50','.B49:','movq %rsi, %rcx','movq 72(%rsp), %rdx',
        'callq '+n['cancel'],'jmp .B50','.B8:']+begin_plan()+L('''movq 648(%rsp), %r9
        leaq 176(%rsp), %r8|movq %rsi, %rcx|movq 72(%rsp), %rdx''')+[
        'callq '+n['begin'],'jmp .B50']+L('''.B9:|movq 584(%rsp), %rax|movq 576(%rsp), %r9
        movq 600(%rsp), %rcx|movq 592(%rsp), %r10|movq %rcx, 48(%rsp)|movq %r10, 40(%rsp)
        movq %rax, 32(%rsp)|movq %rsi, %rcx|movq 72(%rsp), %rdx''')+[
        'callq '+n['start'],'jmp .B50','.B14:','movq %rsi, %rcx','movq 72(%rsp), %rdx',
        'callq '+n['seal'],'jmp .B50']+L('''.B12:|movq %rbx, 32(%rsp)|movq %rsi, %rcx
        movq 72(%rsp), %rdx|movq %rdi, %r9''')+['callq '+n['update'],'jmp .B50']+L('''
        .B13:|movb %cl, 40(%rsp)|movq %rbx, 32(%rsp)|movq %rsi, %rcx
        movq 72(%rsp), %rdx|movq %rdi, %r9''')+['callq '+n['finish'],'.B50:',
        'cmpb $-1, %al','je .B51','.B44:']+life.clear('avx2')+L('''movq 2224(%rsi), %rcx
        movb $5, %al|cmpb $2, 8(%rcx)|je .B46|movb $2, 8(%rcx)|movq $3, (%rcx)
        .B46:|xorl %ebx, %ebx|movb %al, 2249(%rsi)|jmp .B54|.B51:|movb $1, %bl|jmp .B54''')
    return out+export(n)
