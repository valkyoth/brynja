"""Hand-reviewed sequential batch finish callers; not learned from candidates."""
from windows_enclave_sha3_batch_receive import life,L


def scalar(n):
    saves=['r15','r14','r12','rsi','rdi','rbp','rbx']
    lines=[f'pushq %{r}' for r in saves]+L(f'''subq $80, %rsp|movq %r9, %rdi|movq %r8, %rsi
        movq %rdx, %r8|movq %rcx, %rdx|leaq 64(%rsp), %rcx|movb $3, %r9b|callq {n['operation']}
        movzbl 72(%rsp), %ebp|cmpb $2, %bpl|jne .B2|movzbl 64(%rsp), %eax|jmp .B32
        .B2:|movq 64(%rsp), %r12|movb $2, %al|cmpl $1, (%r12)|jne .B30
        cmpq %rsi, 8(%r12)|jne .B30|movq 176(%rsp), %r14|movq 2376(%r12), %rax
        subq %r14, %rax|jae .B6|.B5:|movb $3, %al|jmp .B30|.B6:
        movzbl 184(%rsp), %ebx|movq %rax, 2376(%r12)|xorl %eax, %eax|movl %ebx, %ecx
        subb $1, %cl|setb %al|xorl %edx, %edx|cmpb $8, %cl|setb %dl|testq %r14, %r14
        cmovel %eax, %edx|movb $4, %al|cmpb $1, %dl|jne .B30|testq %r14, %r14|je .B10
        movzbl %bl, %eax|leaq (%rax,%r14,8), %r15|addq $-8, %r15|cmpb $7, %bl|ja .B11
        movb $-1, %dl|movl %ebx, %ecx|shlb %cl, %dl|leaq (%rdi,%r14), %rcx|decq %rcx
        callq {n['mask']}|movl %eax, %ecx|movb $4, %al|testb %cl, %cl|jne .B11|jmp .B30
        .B10:|xorl %r15d, %r15d|.B11:|movq %r14, %rax|shrq $8, %rax|movl %r14d, %ecx
        movq %r14, %rdx|shrq $56, %rdx|movb %dl, 47(%rsp)|shrq $40, %r14
        movw %r14w, 45(%rsp)|movl %eax, 41(%rsp)|movq %r15, 48(%rsp)|movb %bl, 56(%rsp)
        movq %rdi, 32(%rsp)|movb %cl, 40(%rsp)|cmpq $7, %rsi|ja .B5
        leaq (%rsi,%rsi,2), %rax|movq 1152(%r12,%rax,8), %rcx|movq 1160(%r12,%rax,8), %rdi
        movzbl 1168(%r12,%rax,8), %ebx|testq %rsi, %rsi|je .B17
        leaq 1152(,%rax,8), %rax|movq 1160(%r12), %rdx|cmpq $1176, %rax|je .B18''')
    for width,stop in ((1184,1200),(1208,1224),(1232,1248),(1256,1272),(1280,1296)):
        lines+=L(f'addq {width}(%r12), %rdx|jb .B5|cmpq ${stop}, %rax|je .B18')
    lines+=L(f'''movq 1304(%r12), %r8|addq %rdx, %r8|cmpq %rdx, %r8|setae %dl
        cmpq $1320, %rax|sete %al|andb %dl, %al|movq %r8, %rdx|cmpb $1, %al|jne .B5|jmp .B18
        .B17:|xorl %edx, %edx|.B18:|leaq (%rdx,%rdi), %rax|cmpq %rdx, %rax|setb %r8b
        cmpq $1025, %rax|setae %al|orb %r8b, %al|movb $3, %al|jne .B30
        leaq (%r12,%rdx), %r14|addq $1344, %r14|leaq -1(%rcx), %rax|cmpq $4, %rax|jb .B23
        addq $-5, %rcx|cmpq $3, %rcx|ja .B29|leaq 16(%r12), %r15|leaq 32(%rsp), %rdx
        movq %r15, %rcx|callq {n['finish_xof']}|cmpb $-1, %al|jne .B30
        movq %r15, %rcx|movq %r14, %rdx|movq %rdi, %r8|movl %ebx, %r9d|callq {n['squeeze']}
        jmp .B24|.B23:|leaq 16(%r12), %rcx|leaq 32(%rsp), %rdx|movq %r14, %r8
        movq %rdi, %r9|callq {n['finish_fixed']}|.B24:|cmpb $-1, %al|jne .B30
        leaq 16(%r12), %rcx|callq {life.DROP['scalar']}|movb $1, %al|movl %esi, %ecx|shlb %cl, %al
        movb $0, 16(%r12)|orb %al, 2385(%r12)|movq $0, (%r12)|movb $1, 2384(%r12)
        movb $-1, %al|jmp .B32|.B29:|xorl %eax, %eax|.B30:|testb $1, %bpl|jne .B32
        leaq 16(%r12), %rcx|movl %eax, %esi|callq {life.DROP['scalar']}''')
    tail=life.clear_tail('scalar','r12');at=tail.index('callq '+life.ZERO)+1
    return lines+tail[:at]+['movl %esi, %eax']+tail[at:]+life.quarantine('scalar','r12')+L(
        '.B32:|addq $80, %rsp')+[f'popq %{r}' for r in reversed(saves)]+['retq']


def avx2(n):
    saves=['rbp','r15','r14','r13','r12','rsi','rdi','rbx']
    lines=[f'pushq %{r}' for r in saves]+L(f'''subq $104, %rsp|leaq 96(%rsp), %rbp
        movq $-2, (%rbp)|movq %r9, %rbx|movq %r8, %rsi|movq %rdx, %r8|movq %rcx, %rdx
        leaq -64(%rbp), %rcx|movb $3, %r9b|callq {n['operation']}|movzbl -56(%rbp), %eax
        cmpb $2, %al|jne .B2|movzbl -64(%rbp), %edi|jmp .B37|.B2:|movb %al, -1(%rbp)
        movq -64(%rbp), %r13|movb $2, %dil|cmpl $1, 2232(%r13)|jne .B33
        cmpq %rsi, 2240(%r13)|jne .B33|movq 112(%rbp), %r15|movq 2216(%r13), %rax
        subq %r15, %rax|jae .B6|.B5:|movb $3, %dil|jmp .B33|.B6:
        movzbl 120(%rbp), %r14d|movq %rax, 2216(%r13)|xorl %eax, %eax|movl %r14d, %ecx
        subb $1, %cl|setb %al|xorl %edx, %edx|cmpb $8, %cl|setb %dl|testq %r15, %r15
        cmovel %eax, %edx|movb $4, %dil|cmpb $1, %dl|jne .B33|testq %r15, %r15|je .B10
        movzbl %r14b, %eax|leaq (%rax,%r15,8), %r12|addq $-8, %r12|cmpb $7, %r14b|ja .B11
        movb $-1, %dl|movl %r14d, %ecx|shlb %cl, %dl|leaq (%rbx,%r15), %rcx|decq %rcx
        callq {n['mask']}|testb %al, %al|jne .B11|jmp .B33|.B10:|xorl %r12d, %r12d|.B11:
        movq %r15, %rax|shrq $8, %rax|movl %r15d, %ecx|movq %r15, %rdx|shrq $56, %rdx
        movb %dl, -33(%rbp)|shrq $40, %r15|movw %r15w, -35(%rbp)|movl %eax, -39(%rbp)
        movq %r12, -32(%rbp)|movb %r14b, -24(%rbp)|movq %rbx, -48(%rbp)|movb %cl, -40(%rbp)
        cmpq $7, %rsi|ja .B5|leaq (%rsi,%rsi,2), %rcx|movq 1024(%r13,%rcx,8), %rax
        movq 1032(%r13,%rcx,8), %rbx|movzbl 1040(%r13,%rcx,8), %r14d
        testq %rsi, %rsi|je .B17|movq 1032(%r13), %r15|cmpq $1, %rsi|je .B18''')
    for width,stop in ((1056,2),(1080,3),(1104,4),(1128,5)):
        lines+=L(f'addq {width}(%r13), %r15|jb .B5|cmpq ${stop}, %rsi|je .B18')
    lines+=L(f'''movq %r13, %rcx|addq 1152(%r13), %r15|jae .B47|movb $3, %dil
        movq %rcx, %r13|jmp .B33|.B17:|xorl %r15d, %r15d|.B18:
        leaq (%r15,%rbx), %rcx|cmpq %r15, %rcx|setb %dl|cmpq $1025, %rcx|setae %cl
        orb %dl, %cl|movb $3, %dil|jne .B33|addq %r13, %r15|leaq -1(%rax), %rcx
        cmpq $4, %rcx|jb .B24|addq $-5, %rax|cmpq $3, %rax|ja .B32
        movq %r13, -16(%rbp)|leaq 1216(%r13), %r12|leaq -48(%rbp), %rdx|movq %r12, %rcx
        callq {n['finish_xof']}|nop|movb $6, %dil|cmpb $-1, %al|je .B29
        movq -16(%rbp), %r13|jmp .B33|.B24:|movq %r13, -16(%rbp)|leaq 1216(%r13), %rcx
        leaq -48(%rbp), %rdx|movq %r15, %r8|movq %rbx, %r9|callq {n['finish_fixed']}
        nop|movb $6, %dil|jmp .B30|.B29:|movq %r12, %rcx|movq %r15, %rdx
        movq %rbx, %r8|movl %r14d, %r9d|callq {n['squeeze']}|nop|.B30:
        cmpb $-1, %al|movq -16(%rbp), %r13|jne .B33|leaq 1216(%r13), %rcx|callq {life.DROP['avx2']}
        movb $1, %al|movl %esi, %ecx|shlb %cl, %al|movq $2, 2160(%r13)
        orb %al, 2248(%r13)|movq $0, 2232(%r13)|movb $1, 2249(%r13)
        movb $-1, %dil|jmp .B37|.B32:|xorl %edi, %edi|.B33:|testb $1, -1(%rbp)|jne .B37''')
    return lines+life.clear('avx2','r13')+life.quarantine('avx2','r13',label=36)+L(
        '.B37:|movl %edi, %eax|addq $104, %rsp')+[f'popq %{r}' for r in reversed(saves)]+L('''retq
        .B47:|cmpq $6, %rsi|jne .B49|movq %rcx, %r13|jmp .B18|.B49:|movq %rcx, %r13
        addq 1176(%rcx), %r15|jb .B5|jmp .B18''')
