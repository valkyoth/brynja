"""Manually reviewed scalar terminal squeeze; independent of candidate text.

Both rate branches retain their distinct registers, spills and cleanup edges.
This describes normal machine paths, not the containing private-frame policy.
"""
from windows_enclave_sha3_batch_receive import L,life


def admission(n,wide):
    owner,prefix,split,next_=(96,56,19,20) if wide else (56,40,8,9)
    lines=L(f'''xorl %eax, %eax|movl %ebp, %ecx|subb $1, %cl|setb %al
        xorl %edx, %edx|cmpb $8, %cl|setb %dl|testq %rsi, %rsi|cmovel %eax, %edx
        movb $4, %bl|cmpb $1, %dl|jne .B75|movb $6, %bl|cmpb $1, 1(%rdi)
        jne .B75|movb $2, 1(%rdi)|leaq 2(%rdi), %rcx|testq %rsi, %rsi|je .B72
        movq %rcx, {owner}(%rsp)|movq %r14, 104(%rsp)|leaq 120(%rsp), %rcx
        movq %rsi, %rdx|callq {life.ZERO}|movq %rsi, %rdx|testb $-9, %bpl
        je .B{split}|cmpq $1, %rsi|movq %rsi, %rdx|adcq $-1, %rdx|.B{split}:''')
    if wide:lines+=L('movq %rsi, 40(%rsp)')
    lines+=L('movl %ebp, %eax|shrb $3, %al|xorl %ecx, %ecx')
    if not wide:lines+=L('movb %bpl, 96(%rsp)')
    return lines+L(f'''cmpb $8, %bpl|movzbl %al, %eax|cmovel %ecx, %eax
        movzbl %al, %eax|xorl %ecx, %ecx|movq %rdx, {prefix}(%rsp)|addq %rdx, %rax
        setb %cl|addq 18(%rdi), %rax|adcq 26(%rdi), %rcx|jae .B{next_}''')


def bulk(n,wide):
    rate,start,prefix,fail,empty,outer,inner,copy,clear,done,hold,capacity=(
        (136,20,56,60,22,51,52,55,58,23,'rsi','40(%rsp)') if wide else
        (168,9,40,35,11,26,27,30,33,12,'rbp','%rsi'))
    return L(f'''.B{start}:|movq 26(%rdi), %rax|movq 18(%rdi), %rcx
        addq {prefix}(%rsp), %rcx|movq %rcx, 80(%rsp)|adcq $0, %rax
        movq %rax, 88(%rsp)|jb .B{fail}|movq {prefix}(%rsp), %r11
        testq %r11, %r11|je .B{empty}|leaq 586(%rdi), %rax|movq %rax, 64(%rsp)
        movq $0, 48(%rsp)|movq %r11, %rcx|.B{outer}:|cmpq ${rate}, %rcx
        movl ${rate}, %r15d|movq %rcx, 72(%rsp)|cmovbq %rcx, %r15
        movzbl 1041(%rdi), %r14d|xorl %r13d, %r13d|.B{inner}:
        movq %r15, %{hold}|subq %r13, %r15|cmpb ${rate-256}, %r14b
        ja .B{fail}|jne .B{copy}|leaq 50(%rdi), %rcx|leaq 754(%rdi), %r14
        movq %r14, %rdx|leaq 794(%rdi), %r12|movq %r12, %r8
        leaq 834(%rdi), %r9|movq %r9, 112(%rsp)|callq {n['permute']}
        movl $40, %edx|movq %r14, %rcx|callq {life.ZERO}
        movl $40, %edx|movq %r12, %rcx|callq {life.ZERO}
        movl $200, %edx|movq 112(%rsp), %rcx|callq {life.ZERO}
        movb $0, 1041(%rdi)|xorl %r14d, %r14d|.B{copy}:
        movzbl %r14b, %r8d|movl ${rate}, %r12d|subq %r8, %r12
        cmpq %r15, %r12|cmovaeq %r15, %r12|leaq 586(%rdi), %rax
        leaq (%rax,%r13), %rcx|leaq 50(%rdi), %rax|addq %rax, %r8
        movq %r12, %rdx|movq %r12, %r9|callq {n['copy']}
        cmpb $-1, %al|jne .B{fail}|addq %r12, %r13|addb %r12b, %r14b
        movb %r14b, 1041(%rdi)|movq %{hold}, %r15|cmpq %{hold}, %r13|jb .B{inner}
        movq 48(%rsp), %rdx|movq %rdx, %r12|addq %r15, %r12|setb %al
        cmpq {capacity}, %r12|seta %cl|orb %al, %cl|jne .B{clear}
        leaq (%rsp,%rdx), %rcx|addq $120, %rcx|leaq 586(%rdi), %r14
        movq %r14, %rdx|movq %r15, %r8|callq {n['bytes']}
        movl $168, %edx|movq %r14, %rcx|callq {life.ZERO}
        movq 72(%rsp), %rdx|movq %rdx, %rax|subq %r15, %rax|movl $0, %ecx
        cmovaeq %rax, %rcx|movq %r12, 48(%rsp)|cmpq ${rate}, %rdx
        movq {prefix}(%rsp), %r11|ja .B{outer}|jmp .B{done}''')


def counter(wide):
    empty,done,tmp,byte=(22,23,'esi','sil') if wide else (11,12,'ebp','bpl')
    return L(f'''.B{empty}:|xorl %r12d, %r12d|.B{done}:
        movq 80(%rsp), %rax|movb %al, 18(%rdi)|movb %ah, 19(%rdi)
        movq 88(%rsp), %rdx|movl %edx, %r14d|shrl $16, %r14d
        movl %eax, %ecx|shrl $16, %ecx|movb %cl, 20(%rdi)
        movl %edx, %{tmp}|movq %rdx, %rcx|shrl $24, %{tmp}
        movl %eax, %edx|shrl $24, %edx|movb %dl, 21(%rdi)
        movq %rcx, %rdx|shrq $32, %rdx|movq %rax, %r8|shrq $32, %r8
        movb %r8b, 22(%rdi)|movq %rcx, %r8|shrq $40, %r8
        movq %rax, %r9|shrq $40, %r9|movb %r9b, 23(%rdi)
        movq %rcx, %r9|shrq $48, %r9|movq %rax, %r10|shrq $48, %r10
        movb %r10b, 24(%rdi)|movq %rcx, %r10|shrq $56, %r10|shrq $56, %rax
        movb %al, 25(%rdi)|movb %cl, 26(%rdi)|movb %ch, 27(%rdi)
        movb %r14b, 28(%rdi)|movb %{byte}, 29(%rdi)|movb %dl, 30(%rdi)
        movb %r8b, 31(%rdi)|movb %r9b, 32(%rdi)|movb %r10b, 33(%rdi)''')


def partial(n,wide):
    start,rate,fail,copy,store,clear,second,third,last=(
        (62,136,60,65,68,59,'r14','rsi','%bpl') if wide else
        (37,168,35,40,43,34,'rbp','r14','96(%rsp)'))
    lines=L(f'''.B{start}:|leaq 50(%rdi), %r15|movzbl 1041(%rdi), %r14d
        cmpb ${rate-256}, %r14b|ja .B{fail}|jne .B{copy}
        leaq 754(%rdi), %r13|leaq 794(%rdi), %{second}|leaq 834(%rdi), %{third}
        movq %r15, %rcx|movq %r13, %rdx|movq %{second}, %r8|movq %{third}, %r9
        callq {n['permute']}|movl $40, %edx|movq %r13, %rcx|callq {life.ZERO}
        movl $40, %edx|movq %{second}, %rcx|callq {life.ZERO}
        movl $200, %edx|movq %{third}, %rcx|callq {life.ZERO}
        movb $0, 1041(%rdi)|xorl %r14d, %r14d|.B{copy}:
        movzbl %r14b, %eax|addq %rax, %r15|movl $1, %edx|movl $1, %r9d
        leaq 586(%rdi), %rcx|movq %r15, %r8|callq {n['copy']}
        cmpb $-1, %al|jne .B{fail}|incb %r14b|movb %r14b, 1041(%rdi)
        xorl %eax, %eax|movb $8, %cl|subb {last}, %cl|movzbl %cl, %ecx
        cmovbl %eax, %ecx|movb $-1, %dl|shrb %cl, %dl|cmpb $8, %cl
        movzbl %dl, %edx|cmovael %eax, %edx|leaq 586(%rdi), %rcx
        movq %rcx, %r15|xorl %r8d, %r8d|callq {n['mask']}|leaq 1(%r12), %r14''')
    if wide:lines+=L('movq 40(%rsp), %rsi')
    return lines+L(f'cmpq %rsi, %r14|jbe .B{store}|movq %r15, %rcx|jmp .B{clear}')


def shape(n):
    saves=['r15','r14','r13','r12','rsi','rdi','rbp','rbx']
    lines=[f'pushq %{r}' for r in saves]+L('''subq $1144, %rsp|movl %r9d, %ebp
        movq %r8, %rsi|movq %rdx, %r14|movq %rcx, %rdi|leaq 120(%rsp), %rcx
        movl $1024, %r8d|xorl %edx, %edx|callq memset|movb $3, %bl
        cmpq $1024, %rsi|ja .B75|movzbl (%rdi), %eax|cmpl $6, %eax|je .B14
        movb $2, %bl|cmpl $5, %eax|jne .B75''')
    lines+=admission(n,False)+L(f'''.B35:|leaq 120(%rsp), %rcx|movq %rsi, %rdx
        callq {life.ZERO}|movq 56(%rsp), %rcx|callq {n['wipe']}|jmp .B75|.B14:''')
    lines+=admission(n,True)+L(f'''.B60:|leaq 120(%rsp), %rcx|movq 40(%rsp), %rdx
        .B71:|callq {life.ZERO}|movq 96(%rsp), %rcx|callq {n['wipe']}|jmp .B75
        .B72:|callq {n['wipe']}|movl $1, %r8d|movq %r14, %rcx|movq %rsi, %rdx
        xorl %r9d, %r9d|callq {n['copy']}|movb $5, %bl|cmpb $-1, %al|jne .B75
        .B74:|movq %rdi, %rcx|callq {n['drop']}|movb $0, (%rdi)|movb $-1, %bl
        .B75:|leaq 120(%rsp), %rcx|movl $1024, %edx|callq {life.ZERO}
        movl %ebx, %eax|addq $1144, %rsp''')
    lines+=[f'popq %{r}' for r in reversed(saves)]+['retq']
    lines+=bulk(n,False)+bulk(n,True)+counter(False)+L(f'''
        cmpq %rsi, %r11|jne .B37|movq %r12, %r14|.B44:|leaq 2(%rdi), %rcx
        cmpq %rsi, %r14|je .B48|movq %rcx, %rdi|leaq 120(%rsp), %rcx
        movq %rsi, %rdx|callq {life.ZERO}|movq %rdi, %rcx|callq {n['wipe']}|jmp .B75''')
    lines+=counter(True)+L(f'''movq 40(%rsp), %rsi|cmpq %rsi, %r11|jne .B62
        movq %r12, %r14|cmpq %rsi, %r14|jne .B70|.B47:|leaq 2(%rdi), %rcx
        .B48:|callq {n['wipe']}|leaq 120(%rsp), %r8|movq 104(%rsp), %rcx
        movq %rsi, %rdx|movq %rsi, %r9|callq {n['copy']}
        leaq 120(%rsp), %rcx|movq %rsi, %rdx|cmpb $-1, %al|je .B73
        callq {life.ZERO}|movb $5, %bl|jmp .B75''')
    lines+=partial(n,False)+partial(n,True)
    for first,second,fail in ((33,34,35),(58,59,60)):
        lines+=L(f'''.B{first}:|movq 64(%rsp), %rcx|.B{second}:|movl $168, %edx
            callq {life.ZERO}|jmp .B{fail}''')
    lines+=L(f'.B73:|callq {life.ZERO}|jmp .B74')
    for block in (43,68):
        lines+=L(f'''.B{block}:|leaq (%rsp,%r12), %rcx|addq $120, %rcx
            movl $1, %r8d|movq %r15, %rdx|callq {n['bytes']}
            movl $168, %edx|movq %r15, %rcx|callq {life.ZERO}''')
        if block==43:lines+=L('jmp .B44')
    return lines+L('cmpq %rsi, %r14|je .B47|.B70:|leaq 120(%rsp), %rcx|movq %rsi, %rdx|jmp .B71')
