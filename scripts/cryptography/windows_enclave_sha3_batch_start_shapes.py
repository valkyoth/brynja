"""Independent admission, rejection and placement slices of both start bodies.

Constructor internals between these slices remain separate review work.
"""
from windows_enclave_sha3_batch_receive import L,life


def prefix(lane,operation):
    scalar=lane=='scalar';a=life.LAYOUT[lane]
    owner,slot,flag,guard=('r13','rsi','bl','r12b') if scalar else ('rsi','rdi','r14b','r15b')
    result=1680 if scalar else 1696;end=89 if scalar else 59;reject=87 if scalar else 52
    first=10 if scalar else 3;table=46 if scalar else 44
    saves=['r15','r14','r13','r12','rsi','rdi','rbp','rbx'] if scalar else ['rbp','r15','r14','r13','r12','rsi','rdi','rbx']
    lines=[f'pushq %{r}' for r in saves]
    lines+=L(f'movl ${7192 if scalar else 4888}, %eax|callq __chkstk|subq %rax, %rsp')
    lines+=L('movdqa %xmm6, 7168(%rsp)' if scalar else 'leaq 128(%rsp), %rbp|andq $-32, %rsp')
    lines+=L(f'''movq %r9, %{'rdi' if scalar else 'rbx'}|movq %r8, %{slot}
        movq %rdx, %r8|movq %rcx, %rdx|leaq {result}(%rsp), %rcx
        movb $1, %{flag}|movb $1, %r9b|callq {operation}
        movzbl {result+8}(%rsp), %{'r12d' if scalar else 'r15d'}|cmpb $2, %{guard}
        jne .B2|movzbl {result}(%rsp), %eax|jmp .B{end}|.B2:
        movq {result}(%rsp), %{owner}|cmpq $0, {a['plan']}(%{owner})
        movzbl {a['completed']}(%{owner}), %eax|sete %cl|orb %al, %cl
        testb $1, %cl|je .B{first}''')
    for i in range(1,7):
        lines+=L(f'''cmpq $0, {a['plan']+24*i}(%{owner})|setne %dl
            testb ${1<<i}, %al|sete %r8b|movl ${i}, %ecx|testb %r8b, %dl|jne .B11''')
    lines+=L(f'''cmpq $0, {a['plan']+168}(%{owner})|setne %cl|testb %al, %al
        setns %{flag}|andb %cl, %{flag}|movl $7, %ecx|jmp .B11
        .B{first}:|xorl %ecx, %ecx|.B11:
        leaq {a['plan']}(%{owner}), %{'rbp' if scalar else 'r13'}
        cmpq %{slot}, %rcx|setne %cl|xorb $1, %{flag}|movb $2, %al
        orb %cl, %{flag}|jne .B{reject}|leaq (%{slot},%{slot},2), %rax
        movq (%{'rbp' if scalar else 'r13'},%rax,8), %rcx
        xorl %eax, %eax|decq %rcx|cmpq $7, %rcx|ja .B{reject}''')
    lines+=L('movq 7312(%rsp), %r15|movq 7304(%rsp), %r14|movq 7296(%rsp), %rbx' if scalar
             else 'movq 4880(%rbp), %r8|movq 4872(%rbp), %r14')
    return lines+L(f'leaq .LJTI{table}_0(%rip), %rdx|movslq (%rdx,%rcx,4), %rcx|addq %rdx, %rcx|jmpq *%rcx')


def reject(lane):
    scalar=lane=='scalar';a=life.LAYOUT[lane];owner,plan=('r13','rbp') if scalar else ('rsi','r13')
    if scalar:
        lines=L(f'''.B87:|testb $1, %r12b|jne .B89|leaq 16(%r13), %rcx
            movl %eax, %esi|callq {life.DROP[lane]}|movb $0, 16(%r13)
            leaq 1344(%r13), %rcx|movl $1024, %edx|callq {life.ZERO}|movl %esi, %eax''')
    else:
        lines=L(f'''.B52:|testb $1, %r15b|jne .B59|.B53:|movl %eax, %edi
            leaq 1216(%rsi), %rcx|vzeroupper|callq {life.DROP[lane]}
            movq $2, 2160(%rsi)|movl $1024, %edx|movq %rsi, %rcx|callq {life.ZERO}''')
    lines+=L(f'''movq $0, {life.mem(a['active'],owner)}|movb $0, {a['completed']}(%{owner})
        movq $0, {a['budget']}(%{owner})''')
    lines+=L('xorps %xmm0, %xmm0' if scalar else 'vpxor %xmm0, %xmm0, %xmm0')
    for i in range(8):
        reg,offset=(plan,0) if i==0 else (owner,a['plan']+24*i)
        op=('movaps' if i%2==0 else 'movups') if scalar else ('vmovdqa' if i%2==0 else 'vmovdqu')
        lines+=L(f'{op} %xmm0, {life.mem(offset,reg)}|movb $0, {life.mem(offset+16,reg)}')
    if not scalar:
        lines+=L('movq 2224(%rsi), %rax|cmpb $2, 8(%rax)|je .B55|movb $2, 8(%rax)|movq $3, (%rax)|.B55:')
    lines+=L(f'movb $5, {a["phase"]}(%{owner})')
    if not scalar:lines+=L('movl %edi, %eax')
    return lines


def epilogue(lane):
    if lane=='scalar':
        return L('''.B89:|movaps 7168(%rsp), %xmm6|addq $7192, %rsp|popq %rbx
            popq %rbp|popq %rdi|popq %rsi|popq %r12|popq %r13|popq %r14|popq %r15|retq''')
    return L('''.B59:|leaq 4760(%rbp), %rsp|popq %rbx|popq %rdi|popq %rsi
        popq %r12|popq %r13|popq %r14|popq %r15|popq %rbp|vzeroupper|retq''')


def zero_lengths(lane):
    if lane=='scalar':
        return L('''.B24:|orq %rdi, %r14|orq %rbx, %r15|orq %r14, %r15
            je .B26|xorl %eax, %eax|jmp .B87''')
    return L('''.B20:|orq %rbx, %r14|orq 4864(%rbp), %r8|orq %r14, %r8
        je .B56|xorl %eax, %eax''')


def placement(lane):
    if lane=='avx2':
        return L(f'''.B58:|movq %rax, 608(%rsp)|leaq 1216(%rsi), %rcx|vzeroupper
            callq {life.DROP[lane]}|movb %r12b, 1216(%rsi)|leaq 1217(%rsi), %rcx
            leaq 3945(%rsp), %rdx|movl $943, %r8d|callq memcpy
            movq %r14, 2160(%rsi)|vmovdqa 576(%rsp), %ymm0|vmovdqu %ymm0, 2168(%rsi)
            movq 608(%rsp), %rax|movq %rax, 2200(%rsi)|movq $1, 2232(%rsi)
            movq %rdi, 2240(%rsi)|movb $2, 2249(%rsi)|movb $-1, %al|jmp .B59''')
    lines=L(f'''.B47:|leaq 16(%r13), %rcx|callq {life.DROP[lane]}
        movzbl 35(%rsp), %eax|movb %al, 16(%r13)|movb %bpl, 17(%r13)
        movl 64(%rsp), %eax|movb %al, 18(%r13)
        movq 288(%rsp), %rax|movq 294(%rsp), %rcx|movq %rax, 19(%r13)|movq %rcx, 25(%r13)
        movl 48(%rsp), %eax|movb %al, 33(%r13)|movb %dil, 34(%r13)
        movq 248(%rsp), %rax|movq 254(%rsp), %rcx|movq %rax, 35(%r13)|movq %rcx, 41(%r13)
        movl 36(%rsp), %eax|movb %al, 49(%r13)|movl 40(%rsp), %eax|movb %al, 50(%r13)
        movq 232(%rsp), %rax|movq 238(%rsp), %rcx|movq %rax, 51(%r13)|movq %rcx, 57(%r13)''')
    for dest,source,length in ((65,5861,200),(265,3240,168),(433,3072,168),(601,2904,168)):
        lines+=L(f'leaq {dest}(%r13), %rcx|leaq {source}(%rsp), %rdx|movl ${length}, %r8d|callq memcpy')
    for source,dest in ((1296,769),(1248,809)):
        lines+=L(f'''movaps {source}(%rsp), %xmm0|movaps {source+16}(%rsp), %xmm1
            movups %xmm0, {dest}(%r13)|movups %xmm1, {dest+16}(%r13)
            movq {source+32}(%rsp), %rax|movq %rax, {dest+32}(%r13)''')
    lines+=L('''leaq 849(%r13), %rcx|leaq 5661(%rsp), %rdx|movl $200, %r8d|callq memcpy
        movl %r15d, 1049(%r13)|movb %r12b, 1053(%r13)|movb %r14b, 1054(%r13)|movb %bl, 1055(%r13)
        movl 56(%rsp), %eax|movb %al, 1056(%r13)|movzbl 120(%rsp), %eax|movb %al, 1057(%r13)
        movaps 2800(%rsp), %xmm0|movdqa 2816(%rsp), %xmm1|movaps 2832(%rsp), %xmm2
        movaps 2848(%rsp), %xmm3|movups %xmm0, 1058(%r13)|movdqu %xmm1, 1074(%r13)
        movups %xmm2, 1090(%r13)|movups %xmm3, 1106(%r13)
        movaps 2864(%rsp), %xmm0|movups %xmm0, 1122(%r13)
        movups 2878(%rsp), %xmm0|movups %xmm0, 1136(%r13)
        movq $1, (%r13)|movq %rsi, 8(%r13)|movb $2, 2384(%r13)|movb $-1, %al|jmp .B89''')
    return lines
