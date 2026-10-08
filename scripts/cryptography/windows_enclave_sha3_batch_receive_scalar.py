"""Reviewed complete scalar receiver, including decoding and explicit export."""
import windows_enclave_sha3_batch_resident as resident

life=resident.life
L=resident.lines
SLOTS=[(208,200,71),(192,184,70),(176,168,69),(160,152,68),
       (144,136,67),(128,120,66),(112,88,65),(96,104,64)]
REGS=('r15','r14','r13','r12','rsi','rdi','rbp','rbx')


def frame(size,end=False):
    if end:return [f'addq ${size}, %rsp']+[f'popq %{r}' for r in reversed(REGS)]+['retq']
    return [f'pushq %{r}' for r in REGS]+[f'subq ${size}, %rsp']


def empty_plan(offset,vector=False):
    out=['vxorps %xmm0, %xmm0, %xmm0' if vector else 'xorps %xmm0, %xmm0']
    for i in range(8):
        out += [('v' if vector else '')+('movaps' if i%2==0 else 'movups')+
                f' %xmm0, {offset+24*i}(%rsp)',f'movb $0, {offset+24*i+16}(%rsp)']
    return out


def prefix(n):
    out=frame(920)+L('''movq %r8, %rbx|movq %rdx, %r14|movq %rcx, %rsi
        callq PublicSha3BatchSource|leaq 1024(%rbx), %rdi|xorl %r15d, %r15d
        movl $288, %r9d|xorl %ecx, %ecx|movq %rdi, %rdx|movq %rax, %r8
        callq PublicSha3BatchInput|testl %eax, %eax|jne .B82|leaq 432(%rsp), %rcx
        movl $288, %r8d|movq %rdi, %rdx|callq memcpy|movq 432(%rsp), %rdx
        movq 440(%rsp), %rax|movq %rax, 72(%rsp)|movq 448(%rsp), %rax|movq %rax, 80(%rsp)
        movq 456(%rsp), %r13|movq 464(%rsp), %r15|movq 472(%rsp), %rdi
        movq 480(%rsp), %rax|movq %rax, 232(%rsp)|movq 488(%rsp), %rax
        movq 496(%rsp), %rcx|movq %rcx, 224(%rsp)|movq 512(%rsp), %rbp
        movq 504(%rsp), %rcx|movq %rcx, 216(%rsp)|movq 520(%rsp), %r12''')
    out+=empty_plan(240)+L('''xorl %ecx, %ecx|leaq TABLE0(%rip), %r8|.B2:
        movq 544(%rsp,%rcx), %r9|cmpq $255, %r9|ja .B81|movq 528(%rsp,%rcx), %r11
        movq 536(%rsp,%rcx), %r10|movq %r11, 240(%rsp,%rcx)|movq %r10, 248(%rsp,%rcx)
        movb %r9b, 256(%rsp,%rcx)|cmpq $8, %r11|ja .B81|movslq (%r8,%r11,4), %r11
        addq %r8, %r11|jmpq *%r11|.B31:|cmpq $8, %r9|ja .B81|cmpq $1024, %r10
        jbe .B33|jmp .B81|.B28:|movl $64, %r11d|jmp .B29|.B26:|movl $32, %r11d
        jmp .B29|.B27:|movl $48, %r11d|jmp .B29|.B34:|orq %r9, %r10|je .B35
        jmp .B81|.B25:|movl $28, %r11d|.B29:|cmpq $8, %r9|jne .B81
        cmpq %r11, %r10|jne .B81|.B33:|testq %r10, %r10|sete %r10b
        testq %r9, %r9|sete %r9b|xorb %r10b, %r9b|jne .B81|.B35:
        addq $24, %rcx|cmpq $192, %rcx|jne .B2|leaq -92(%r14), %rcx|cmpq $5, %rcx
        setb %r8b|movb $27, %r9b|shrb %cl, %r9b|cmpq $11, %rdx|jne .B81
        cmpq $8, %r15|ja .B81|cmpq $1024, %r13|ja .B81|leaq -100(%r14), %rcx
        cmpq $-10, %rcx|jb .B81|cmpq $0, 72(%rsp)|je .B81|testq %rax, %rax|jne .B81
        andb %r9b, %r8b|movq %r15, %rax|orq %r13, %rax|sete %al|orb %r8b, %al
        cmpb $1, %al|jne .B81|testq %r13, %r13|sete %al|testq %rdi, %rdi|sete %cl
        xorb %al, %cl|jne .B81|testq %r13, %r13|sete %al|testq %r15, %r15|sete %cl
        xorb %al, %cl|testb %r8b, %cl|jne .B81|leaq -91(%r14), %rax|cmpq $4, %rax
        jae .B15|.B18:|cmpq $7, 80(%rsp)|ja .B81|.B19:|cmpq $90, %r14|je .B21
        cmpq $0, 232(%rsp)|jne .B81|.B21:|cmpq $91, %r14|je .B23|movq %rbp, %rax
        orq 224(%rsp), %rax|movq %r12, %rcx|orq 216(%rsp), %rcx|orq %rax, %rcx
        jne .B81|.B23:|leaq -90(%r14), %rax|testq $-9, %rax|je .B37''')
    out+=empty_plan(720)+['leaq 240(%rsp), %rcx','leaq 720(%rsp), %rdx','callq '+n['equal']]+L('''
        movq %rdi, %rcx|notq %rcx|cmpq %rcx, %r13|setbe %cl|testb %cl, %al|je .B81
        jmp .B38|.B15:|cmpq $96, %r14|je .B18|cmpq $95, %r14|jne .B36
        xorl %eax, %eax|testq %r13, %r13|setne %al|shll $3, %eax|cmpq %rax, %r15
        setne %al|cmpq $8, 80(%rsp)|setae %cl|orb %al, %cl|je .B19|jmp .B81
        .B36:|cmpq $0, 80(%rsp)|jne .B81|jmp .B19|.B37:|leaq 240(%rsp), %rcx''')+[
        'callq '+n['validate_plan']]+L('''cmpb $-1, %al|setne %al|movq %rdi, %rcx
        addq %r13, %rcx|setb %cl|orb %al, %cl|jne .B81|.B38:''')
    for i,(ident,width,last) in enumerate(SLOTS[:5]):
        out += [f'movq {240+24*i}(%rsp), %rax',f'movq %rax, {ident}(%rsp)',
            f'movq {248+24*i}(%rsp), %rax',f'movq %rax, {width}(%rsp)',
            f'movzbl {256+24*i}(%rsp), %eax',f'movb %al, {last}(%rsp)']
    out+=L('''movq 360(%rsp), %rax|movq %rax, 128(%rsp)|movzbl 376(%rsp), %eax
        movb %al, 66(%rsp)|movzbl 400(%rsp), %eax|movb %al, 65(%rsp)
        movzbl 424(%rsp), %eax|movb %al, 64(%rsp)''')
    for src,dst in ((368,120),(384,112),(392,88),(408,96),(416,104)):
        out += [f'movq {src}(%rsp), %rax',f'movq %rax, {dst}(%rsp)']
    return out+L('''testq %r13, %r13|je .B39|movl $1, %ecx|movq %rbx, %rdx
        movq %rdi, %r8|movq %r13, %r9|callq PublicSha3BatchInput|testl %eax, %eax|je .B39
        .B81:|xorl %r15d, %r15d|.B82:|movl %r15d, %eax''')+frame(920,True)


def shape(n):
    out=prefix(n)+L('''.B39:|leaq -90(%r14), %rcx|cmpq $9, %rcx|ja .B75
        leaq TABLE1(%rip), %rax|movslq (%rax,%rcx,4), %rcx|addq %rax, %rcx|jmpq *%rcx
        .B43:|cmpq $92, %r14|sete %r9b|movb %r15b, 48(%rsp)|movq %r13, 40(%rsp)
        movq %rbx, 32(%rsp)|movq %rsi, %rcx|movq 72(%rsp), %rdx|movq 80(%rsp), %r8''')+[
        'callq '+n['setup_chunk'],'jmp .B78','.B44:','movq %rsi, %rcx',
        'movq 72(%rsp), %rdx','movq 80(%rsp), %r8','callq '+n['finish_setup'],'jmp .B78',
        '.B77:','movq %rsi, %rcx','movq 72(%rsp), %rdx','callq '+n['cancel'],'jmp .B78','.B41:']
    for i,(ident,width,last) in enumerate(SLOTS):
        out += [f'movq {ident}(%rsp), %rax',f'movq %rax, {432+24*i}(%rsp)',
                f'movq {width}(%rsp), %rax',f'movq %rax, {440+24*i}(%rsp)',
                f'movzbl {last}(%rsp), %eax',f'movb %al, {448+24*i}(%rsp)']
    out+=L('''leaq 432(%rsp), %r8|movq %rsi, %rcx|movq 72(%rsp), %rdx|movq 232(%rsp), %r9''')+[
        'callq '+n['begin'],'jmp .B78']+L('''.B42:|movq %r12, 48(%rsp)|movq %rbp, 40(%rsp)
        movq 216(%rsp), %rax|movq %rax, 32(%rsp)|movq %rsi, %rcx|movq 72(%rsp), %rdx
        movq 80(%rsp), %r8|movq 224(%rsp), %r9''')+['callq '+n['start'],'jmp .B78']+L('''
        .B47:|movq %rsi, %rcx|movq 72(%rsp), %rdx''')+['callq '+n['seal'],'jmp .B78']+L('''
        .B45:|movq %r13, 32(%rsp)|movq %rsi, %rcx|movq 72(%rsp), %rdx
        movq 80(%rsp), %r8|movq %rbx, %r9''')+['callq '+n['update'],'jmp .B78']+L('''
        .B46:|movb %r15b, 40(%rsp)|movq %r13, 32(%rsp)|movq %rsi, %rcx
        movq 72(%rsp), %rdx|movq 80(%rsp), %r8|movq %rbx, %r9''')+[
        'callq '+n['finish'],'.B78:','cmpb $-1, %al','je .B79','.B75:']+life.clear('scalar')+L('''
        movb $5, %al|xorl %r15d, %r15d|movb %al, 2384(%rsi)|jmp .B82
        .B79:|movb $1, %r15b|jmp .B82|.B48:|leaq 432(%rsp), %rcx|movq %rsi, %rdx
        movq 72(%rsp), %r8|movb $4, %r9b''')+['callq '+n['operation']]+L('''
        movzbl 440(%rsp), %ebx|cmpb $2, %bl|je .B75|movq 432(%rsp), %rdi''')
    for i,(ident,width,last) in enumerate(SLOTS):
        out += [f'movq {ident}(%rsp), %rax',f'cmpq {1152+24*i}(%rdi), %rax','jne .B74',
                f'movzbl {last}(%rsp), %eax',f'cmpb {1168+24*i}(%rdi), %al','jne .B74',
                f'movq {width}(%rsp), %rax',f'cmpq {1160+24*i}(%rdi), %rax','jne .B74']
    return out+L('''leaq 1344(%rdi), %rcx|movl $1024, %edx|callq PublicSha3BatchOutput
        testl %eax, %eax|je .B76|.B74:|movq %rdi, %rcx|movl %ebx, %edx''')+[
        'callq '+n['guard'],'jmp .B75','.B76:','movq %rdi, %rcx','callq '+n['clear']]+L('''
        movb $1, %r15b|xorl %eax, %eax|movb %al, 2384(%rdi)|jmp .B82''')
