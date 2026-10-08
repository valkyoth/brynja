"""Reviewed AVX2 terminal State bodies; expectations never learned from input."""
from windows_enclave_sha3_batch_receive import life,L


def reject(n,failed,cleared,exit_label,saves):
    return L(f''' .B{failed}:|movb $1, 859(%rsi)|movq $0, 616(%rsi)
        leaq 624(%rsi), %rcx|callq {n['wipe']}|cmpb $-1, 938(%rsi)|je .B{cleared}
        leaq 936(%rsi), %rcx|movl $1, %edx|callq {life.ZERO}|movb $0, 937(%rsi)
        vxorps %xmm0, %xmm0, %xmm0|vmovaps %ymm0, 864(%rsi)|vmovaps %ymm0, 896(%rsi)
        .B{cleared}:|movb $-1, 938(%rsi)|movb $3, 962(%rsi)
        .B{exit_label}:|movl %edi, %eax|addq $1064, %rsp''')+[
        f'popq %{r}' for r in reversed(saves)]+L('vzeroupper|retq')


def wipe(n):
    return L(f'leaq 40(%rsp), %rcx|movl $1024, %edx|callq {life.ZERO}')


def complete(n,label,exit_label):
    return L(f'movq %rsi, %rcx|callq {n["clear"]}')+wipe(n)+L(f'''
        cmpl $2, 944(%rsi)|je .B{label}|movq %rsi, %rcx|callq {n['drop']}
        .B{label}:|movq $2, 944(%rsi)|movb $-1, %dil|jmp .B{exit_label}''')


def fixed(n):
    saves=['r14','rsi','rdi','rbx']
    lines=[f'pushq %{r}' for r in saves]+L('''subq $1064, %rsp|movq 944(%rcx), %rax
        movb $7, %dil|cmpq $2, %rax|je .B23|movq %rcx, %rsi|movb $7, %dil
        cmpb $1, 962(%rcx)|jne .B20|cmpb $0, 859(%rsi)|jne .B20
        cmpb $0, 858(%rsi)|jne .B20|movq 576(%rsi), %rcx|movzbl 8(%rcx), %r10d
        testl %r10d, %r10d|je .B5|cmpl $1, %r10d|jne .B24|movq (%rcx), %r10
        movb $5, %dil|cmpq 584(%rsi), %r10|jne .B20|movzbl 9(%rcx), %ecx
        movb $1, %dil|movl $44, %r10d|btl %ecx, %r10d|jae .B9|xorl %edi, %edi
        jmp .B20|.B5:|movb $3, %dil|jmp .B20|.B24:|movb $4, %dil''')
    lines+=reject(n,20,22,23,saves)
    lines+=L(f'''.B9:|movl $3, %r10d|btl %ecx, %r10d|jb .B20|movb $9, %dil
        cmpl $1, %eax|jne .B20|cmpq %r9, 952(%rsi)|jne .B20|movzbl 960(%rsi), %eax
        movzbl 961(%rsi), %r10d|movq %rsi, %rcx|movq %r8, %rbx|movl %eax, %r8d
        movq %r9, %r14|movl %r10d, %r9d|callq {n['engine_finish']}|movl %eax, %edi
        cmpb $-1, %al|jne .B20|leaq 40(%rsp), %rcx|movl $1024, %r8d
        xorl %edx, %edx|callq memset|movb $9, %dil|cmpq $1024, %r14|ja .B19
        movq %r14, %r8|leaq 40(%rsp), %rdx|movq %rsi, %rcx|callq {n['read']}
        movl %eax, %edi|cmpb $-1, %al|jne .B19|movq %r14, %rdx|leaq 40(%rsp), %r8
        movq %rbx, %rcx|movq %r14, %r9|callq {n['copy']}|movb $10, %dil
        cmpb $-1, %al|je .B16|.B19:''')
    return lines+wipe(n)+L('jmp .B20|.B16:')+complete(n,18,23)


def squeeze(n):
    saves=['r15','r14','rsi','rdi','rbp','rbx']
    lines=[f'pushq %{r}' for r in saves]+L('''subq $1064, %rsp|movb $7, %dil
        cmpl $2, 944(%rcx)|je .B30|movq %rcx, %rsi|movb $7, %dil|cmpb $2, 962(%rcx)
        jne .B27|cmpb $0, 859(%rsi)|jne .B27|cmpb $0, 858(%rsi)|je .B27
        movq 576(%rsi), %rax|movzbl 8(%rax), %ecx|testl %ecx, %ecx|je .B5
        cmpl $1, %ecx|jne .B31|movq (%rax), %rcx|movb $5, %dil|cmpq 584(%rsi), %rcx
        jne .B27|movzbl 9(%rax), %eax|movb $1, %dil|movl $44, %ecx|btl %eax, %ecx
        jae .B9|xorl %edi, %edi|jmp .B27|.B5:|movb $3, %dil|jmp .B27
        .B31:|movb $4, %dil''')
    lines+=reject(n,27,29,30,saves)
    lines+=L(f'''.B9:|movl $3, %ecx|btl %eax, %ecx|jb .B27|testq %r8, %r8|je .B11
        movl %r9d, %ebp|movq %rdx, %rbx|leaq 40(%rsp), %rcx|movq %r8, %r14
        movl $1024, %r8d|xorl %edx, %edx|callq memset|movb $9, %dil
        cmpq $1025, %r14|jae .B13|xorl %ecx, %ecx|movl %ebp, %r15d|subb $1, %r15b
        setb %cl|xorl %edx, %edx|cmpb $8, %r15b|setb %dl|testq %r14, %r14
        cmovel %ecx, %edx|cmpb $1, %dl|jne .B13|leaq (,%r14,8), %rcx
        movzbl %bpl, %eax|movl $7, %edx|subq %rcx, %rdx|cmpq %rax, %rdx
        jae .B17|jmp .B13|.B11:|movb $9, %dil|testb %r9b, %r9b|jne .B27
        movq %rdx, %rbx|leaq 40(%rsp), %rcx|movq %r8, %r14|movl $1024, %r8d
        xorl %edx, %edx|movl %r9d, %r15d|callq memset|xorl %eax, %eax
        movl %r15d, %ebp|subb $1, %r15b|setb %al|xorl %ecx, %ecx|cmpb $8, %r15b
        setb %cl|testq %r14, %r14|cmovel %eax, %ecx|movb $9, %dil|testb %cl, %cl
        je .B13|.B17:|leaq 40(%rsp), %rdx|movq %rsi, %rcx|movq %r14, %r8
        callq {n['read']}|movl %eax, %edi|cmpb $-1, %al|je .B18|.B13:''')
    lines+=wipe(n)+L(f'''jmp .B27|.B18:|movq %r14, %rdx|cmpb $6, %r15b|ja .B22
        testq %rdx, %rdx|je .B20|leaq (%rsp,%rdx), %rax|addq $39, %rax
        movb $8, %cl|subb %bpl, %cl|movb $-1, %dl|shrb %cl, %dl
        movq %rax, %rcx|callq {n['mask']}|movq %r14, %rdx|.B22:
        leaq 40(%rsp), %r8|movq %rbx, %rcx|movq %rdx, %r9|callq {n['copy']}
        cmpb $-1, %al|je .B23''')
    return lines+wipe(n)+L('movb $10, %dil|jmp .B27|.B23:')+complete(n,25,30)+L(
        '.B20:|movb $9, %dil|jmp .B13')
