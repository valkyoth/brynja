"""Independent full fixed-finalizer contract, including three inlined padders."""
from windows_enclave_sha3_batch_receive import L,life


def admission(n,label,width,partial,update):
    failure,overflow=(29,45) if width==32 else (26,140)
    return L(f'''.B{label}:|incq %r15|leaq 96(%rsp), %rcx|movl $1040, %r8d
        movq %r15, %rdx|callq memcpy|testq %rsi, %rsi|je .B25
        leaq 1136(%rsp), %rbx|movq %rbx, %rcx|movq %rsi, %rdx|callq {life.ZERO}
        cmpq ${width}, %rsi|jne .B{failure}|movq 16(%r14), %rax|shrq $3, %rax
        addq 96(%rsp), %rax|movq 104(%rsp), %rax|adcq $0, %rax
        movb $1, %r15b|jb .B{overflow}|movzbl 24(%r14), %ebp
        movq (%r14), %rdx|movq 8(%r14), %r8|testb $-9, %bpl
        jne .B{partial}|xorl %r14d, %r14d|jmp .B{update}''')


def update(n,partial,block,rate,empty,ready):
    lines=L(f'''.B{partial}:|cmpq $1, %r8|movq %r8, %rax|adcq $-1, %rax
        leaq (%rdx,%rax), %rcx|xorl %r14d, %r14d|cmpq %rax, %r8
        cmovneq %rcx, %r14|movq %rax, %r8|.B{block}:|leaq 96(%rsp), %rcx
        callq {n['update'+rate]}|testb %al, %al''')
    if rate=='88':return lines+L('jne .B45')
    return lines+L(f'''jne .B140|leaq 1128(%rsp), %rcx|movb $0, 1128(%rsp)
        testq %r14, %r14|je .B{empty}|movl $1, %edx|movl $1, %r9d
        movq %r14, %r8|callq {n['copy']}|movl %ebp, %eax|jmp .B{ready}''')


def absorb(n,rate,loop,final=False):
    lines=L(f'''movl ${rate}, %ebp|movq %r13, %r15|.B{loop}:
        leaq -368(%r15), %rcx|movb $0, 32(%rsp)|movq %r15, %rdx
        xorl %r8d, %r8d|movb $8, %r9b|callq {n['xor']}
        incq %r15|decq %rbp|jne .B{loop}''')
    if final:lines+=L('leaq 144(%rsp), %r15|movq %r15, %rcx')
    else:lines+=L('leaq 144(%rsp), %rcx')
    third='rbp' if final else 'r15'
    return lines+L(f'''movq %r12, %rdx|movq %r14, %r8|leaq 928(%rsp), %{third}
        movq %{third}, %r9|callq {n['permute']}
        movl $40, %edx|movq %r12, %rcx|callq {life.ZERO}
        movl $40, %edx|movq %r14, %rcx|callq {life.ZERO}
        movl $200, %edx|movq %{third}, %rcx|callq {life.ZERO}
        movl $168, %edx|movq %r13, %rcx|callq {life.ZERO}''')


def bit(n):
    return L(f'''movl %r15d, %eax|shrl $3, %eax|addq %r13, %rax
        movl %r15d, %ecx|andb $7, %cl|movb $1, %r8b|shlb %cl, %r8b
        movq %rax, %rcx|movb $-1, %dl|callq {n['mask']}''')


def initialize(n,width):
    return L(f'''movl ${width}, %r8d|movq %rbx, %rcx|movq %r14, %rdx
        callq {n['bytes']}|movq $1, 64(%rsp)|movq %rbx, 72(%rsp)
        movq ${width}, 80(%rsp)|movq ${width}, 88(%rsp)''')


def padding(n,base,rate,width):
    lines=L(f'''.B{base}:|xorl %eax, %eax|.B{base+1}:|movb %al, 1129(%rsp)
        movw $774, 1130(%rsp)|movzbl 1134(%rsp), %r12d|leaq 512(%rsp), %r13
        leaq 344(%rsp), %r8|cmpq $168, %r12|ja .B{base+3}
        movq %r13, %rcx|movq %r12, %rdx|movq %r12, %r9|callq {n['copy']}
        .B{base+3}:|leal (,%r12,8), %r15d|testq %r14, %r14|je .B{base+7}
        cmpb $-88, %r12b|jae .B{base+6}|addq %r13, %r12
        movl $1, %edx|movl $1, %r9d|movq %r12, %rcx|movq %r14, %r8
        callq {n['copy']}|xorl %eax, %eax|movb $8, %cl|subb %bpl, %cl
        movzbl %cl, %ecx|cmovbl %eax, %ecx|movb $-1, %dl|shrb %cl, %dl
        cmpb $8, %cl|movzbl %dl, %edx|cmovael %eax, %edx
        movq %r12, %rcx|xorl %r8d, %r8d|callq {n['mask']}
        .B{base+6}:|addq %rbp, %r15|.B{base+7}:|leaq 848(%rsp), %r12
        leaq 888(%rsp), %r14|cmpl ${rate*8}, %r15d|jne .B{base+11}''')
    lines+=absorb(n,rate,base+9)+L(f'''xorl %r15d, %r15d|.B{base+11}:
        incq %r15|cmpq ${rate*8}, %r15|jne .B{base+15}''')
    lines+=absorb(n,rate,base+13)+L(f'''xorl %r15d, %r15d|jmp .B{base+16}
        .B{base+15}:|cmpl $1343, %r15d|ja .B{base+17}|.B{base+16}:''')+bit(n)
    lines+=L(f'.B{base+17}:|incq %r15|cmpq ${rate*8}, %r15|jne .B{base+21}')
    lines+=absorb(n,rate,base+19)+L(f'''xorl %r15d, %r15d|jmp .B{base+22}
        .B{base+21}:|cmpl $1343, %r15d|ja .B{base+26}|.B{base+22}:''')+bit(n)
    lines+=L(f'cmpq ${rate*8-1}, %r15|jne .B{base+26}')+absorb(n,rate,base+24)
    lines+=L(f'''.B{base+26}:|leaq {512+rate-1}(%rsp), %rcx|movb $-1, %dl
        movb $-128, %r8b|callq {n['mask']}''')+absorb(n,rate,base+27,True)
    lines+=L(f'''movb $1, 1133(%rsp)|movb $0, 1135(%rsp)|movl $168, %edx
        leaq 344(%rsp), %rcx|callq {life.ZERO}|movb $0, 1134(%rsp)
        movl $168, %edx|movq %r13, %rcx|callq {life.ZERO}
        leaq 680(%rsp), %r14|movl $168, %edx|movq %r14, %rcx|callq {life.ZERO}
        movl $4, %edx|leaq 1128(%rsp), %rcx|callq {life.ZERO}
        movl ${width}, %edx|movl ${width}, %r9d|movq %r14, %rcx
        movq %r15, %r8|callq {n['copy']}|movb $4, %r15b|cmpb $-1, %al''')
    if width==28:return lines+L('je .B153')
    lines+=L('jne .B140|leaq 1136(%rsp), %rbx')+initialize(n,width)
    return lines+(L('jmp .B109') if width==48 else [])


def finish_result(n,wide):
    block=109 if wide else 147
    lines=L(f'''.B{block}:|leaq 40(%rsp), %rcx|leaq 64(%rsp), %rdx
        callq {n['finish']}|movq 40(%rsp), %r12|leaq 96(%rsp), %rcx
        callq {n['wipe']}|cmpq $2, %r12|je .B144|movq 48(%rsp), %r15
        movq 56(%rsp), %r14|testq %r15, %r15|setne %al|xorl %r9d, %r9d
        testb %al, %r12b''')
    if not wide:lines+=L('cmovneq %r14, %r9')
    lines+=L('movl $1, %r8d|cmovneq %r15, %r8')
    return lines+(L('cmovneq %r14, %r9|jmp .B149') if wide else [])


def shape(n):
    saves=['r15','r14','r13','r12','rsi','rdi','rbp','rbx']
    lines=[f'pushq %{r}' for r in saves]+L('''subq $3304, %rsp|movq %r9, %rsi
        movq %r8, %rdi|movq %rdx, %r14|movq %rcx, %r15|leaq 1136(%rsp), %rcx
        movl $1024, %r8d|xorl %edx, %edx|callq memset|movb $3, %bl
        cmpq $1024, %rsi|ja .B145|leaq 2160(%rsp), %rcx|movl $1136, %r8d
        movq %r15, %rdx|callq memcpy|movb $0, (%r15)|movzbl 2160(%rsp), %eax
        leal -1(%rax), %ecx|cmpl $3, %ecx|ja .B23|leaq .LJTI50_0(%rip), %rax
        movslq (%rax,%rcx,4), %rcx|addq %rax, %rcx|jmpq *%rcx''')
    for args in ((3,28,38,39),(8,48,30,31),(13,64,34,35),(18,32,42,43)):
        lines+=admission(n,*args)
    lines+=L(f'''.B25:|movb $3, 48(%rsp)|jmp .B143|.B23:|decb %al|movb $2, %bl
        cmpb $4, %al|jb .B145|leaq 2160(%rsp), %rcx|callq {n['drop']}|jmp .B145
        .B26:|movb $3, 48(%rsp)|jmp .B141|.B29:|movb $3, 48(%rsp)|jmp .B46''')
    for args in ((30,31,'68',47,48),(34,35,'48',78,79),(38,39,'90',111,112),(42,43,'88',0,0)):
        lines+=update(n,*args)
    lines+=L(f'''movb $3, 32(%rsp)|leaq 96(%rsp), %rcx|movq %r14, %rdx
        movl %ebp, %r8d|movb $6, %r9b|callq {n['finalize']}
        leaq 680(%rsp), %r14|leaq 144(%rsp), %r8|movl $32, %edx|movl $32, %r9d
        movq %r14, %rcx|callq {n['copy']}|movb $4, %r15b|cmpb $-1, %al|je .B146
        .B45:|movb %r15b, 48(%rsp)|.B46:|leaq 1136(%rsp), %rcx|jmp .B142''')
    lines+=padding(n,47,104,48)+padding(n,78,72,64)+finish_result(n,True)+padding(n,111,144,28)
    lines+=L(f'''.B140:|movb %r15b, 48(%rsp)|.B141:|movq %rbx, %rcx|.B142:
        movq %rsi, %rdx|callq {life.ZERO}|.B143:|leaq 96(%rsp), %rcx
        callq {n['wipe']}|.B144:|movb $6, %bl|.B145:|leaq 1136(%rsp), %rcx
        movl $1024, %edx|callq {life.ZERO}|movl %ebx, %eax|addq $3304, %rsp''')
    lines+=[f'popq %{r}' for r in reversed(saves)]+['retq','.B146:']+initialize(n,32)
    lines+=L('jmp .B147|.B153:|leaq 1136(%rsp), %rbx')+initialize(n,28)+finish_result(n,False)
    return lines+L(f'''.B149:|movq %rdi, %rcx|movq %rsi, %rdx|callq {n['copy']}
        cmpb $-1, %al|sete %bl|negb %bl|testq %r12, %r12|je .B152
        testq %r15, %r15|je .B152|movq %r15, %rcx|movq %r14, %rdx|callq {life.ZERO}
        .B152:|orb $5, %bl|jmp .B145''')
