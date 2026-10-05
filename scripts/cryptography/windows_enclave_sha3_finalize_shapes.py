"""Inspected saved padding/squeeze sequences; not a general assembly verifier."""
import re
import windows_enclave_sha3_update as u

ZERO,PERMUTE = u.ZERO,u.PERMUTE


def sequences(kind,rate,helpers,pins):
    if kind=='enter':
        return (
            'cmpb $0, (%rcx)|je .LBBX_2|xorl %eax, %eax|jmp .LBBX_17',
            'shrq $3, %rax|addq 1(%rsi), %rax|movq 9(%rsi), %rax|adcq $0, %rax|movb $1, %al|jb .LBBX_17',
            'callq '+u.state.s.UPDATE+format(rate,'x')+'_E6updateB6_|testb %al, %al|movb $1, %al|jne .LBBX_17',
            'cmpb $1, 1037(%rsi)|jne .LBBX_9|movb $3, 32(%rsp)',
            'cmpb $1, 1037(%rsi)|jne .LBBX_14|movb $3, 32(%rsp)',
            'movb $4, %r9b|jmp .LBBX_16',
            '.LBBX_15:|movb $31, %r9b',
            'callq '+pins['finalize'+str(rate)]['name']+'|leaq 33(%rsi), %rcx|movl $16, %edx|callq '+ZERO+
            '|leaq 1037(%rsi), %rcx|movl $1, %edx|callq '+ZERO+'|movb $1, (%rsi)|movb $-1, %al')
    if kind=='finalize':
        return (
            'movb $0, 1032(%rdi)|testq %rdx, %rdx',
            'movb %al, 1033(%rdi)|movb %r13b, 1034(%rdi)|movb %sil, 1035(%rdi)',
            'cmpq $168, %r12|ja .LBBX_5',
            'movb $-1, %dl|shrb %cl, %dl|cmpb $8, %cl|movzbl %dl, %edx|cmovael %eax, %edx|movq %r12, %rcx|xorl %r8d, %r8d|callq '+helpers['mask']['name'],
            f'cmpq ${rate*8}, %r14|jne .LBBX_14|movl ${rate}, %r12d',
            'movzbl %bpl, %eax|btl %eax, %edi|jae .LBBX_16|cmpq $1344, %r14|jae .LBBX_16',
            f'cmpq ${rate*8}, %r14|movq 88(%rsp), %rdi|jne .LBBX_21|movl ${rate}, %esi',
            f'leaq {416+rate-1}(%rdi), %rcx|movb $-1, %dl|movb $-128, %r8b|callq '+helpers['mask']['name'],
            'movb $1, 1037(%rdi)|movb $0, 1039(%rdi)|movl $168, %edx|movq 80(%rsp), %rcx|callq '+ZERO+
            '|movb $0, 1038(%rdi)|movl $168, %edx|movq %rbx, %rcx|callq '+ZERO+
            '|addq $584, %rdi|movl $168, %edx|movq %rdi, %rcx|callq '+ZERO+'|movl $4, %edx|movq 96(%rsp), %rcx')
    return (
        'movq 24(%rcx), %rbx|movq 16(%rcx), %rax|addq %r8, %rax|movq %rax, 96(%rsp)|adcq $0, %rbx|jb .LBBX_1',
        'movq %rcx, %rsi|testq %r8, %r8|je .LBBX_17',
        f'cmpb ${rate-256}, %dil|ja .LBBX_6|jne .LBBX_9',
        'movq %r13, %r9|callq '+helpers['copy']['name']+'|movb $4, %r12b|cmpb $-1, %al|jne .LBBX_15',
        'testq %r13, %r13|movq 88(%rsp), %rcx|je .LBBX_14|movq %rcx, %rdi|addq %rbx, %rdi|jb .LBBX_14|cmpq 64(%rsp), %rdi|ja .LBBX_14',
        'callq '+helpers['copy_bytes']['name']+'|movq 48(%rsp), %r12|movq %rdi, 16(%r12)|movl $168, %edx|movq %r14, %rcx|callq '+ZERO,
        '.LBBX_14:|movl $168, %edx|movq 40(%rsp), %rcx|callq '+ZERO,
        'movb %al, 23(%rsi)|movb %bl, 24(%rsi)|movb %bh, 25(%rsi)|movb %r11b, 26(%rsi)|movb %cl, 27(%rsi)|movb %dl, 28(%rsi)|movb %r8b, 29(%rsi)|movb %r9b, 30(%rsi)|movb %r10b, 31(%rsi)|movb $-1, %r12b',
        '.LBBX_6:|xorl %r12d, %r12d|jmp .LBBX_15',
        '.LBBX_1:|movb $2, %r12b|jmp .LBBX_15')


def landmarks(kind,rate,body,helpers,pins):
    text = u.normalized(body)
    for seq in sequences(kind,rate,helpers,pins):
        u.require(seq.replace('|','\n') in text,'finalize/squeeze/transition semantic landmark')
    if kind=='finalize':
        u.require(text.rstrip().endswith('jmp '+ZERO+'\n.Lfunc_end'+('18:' if rate==136 else '22:')),
                  'final suffix erasure tail call after epilogue')


def erasure_sequences(kind):
    if kind=='enter': return []
    if kind=='finalize':
        registers = (('%r13','%r12','%r14','%rbx'),('%r15','%r14','%rsi','%rbx'),('%r15','%r14','%rsi','%rbx'))
        return [[line for size,reg in zip((40,40,200,168),regs)
                 for line in (f'movl ${size}, %edx',f'movq {reg}, %rcx','callq '+ZERO)] for regs in registers]
    return [['movl $40, %edx','movq %r14, %rcx','callq '+ZERO,
             'movl $40, %edx','movq %rdi, %rcx','callq '+ZERO,
             'movl $200, %edx','movq %r15, %rcx','movq %r13, %r15','callq '+ZERO,'movb $0, 1039(%rsi)']]


def cleanup(kind,body):
    lines = u.normalized(body).splitlines();sites = [i for i,v in enumerate(lines) if v=='callq '+PERMUTE]
    expected = erasure_sequences(kind);u.require(len(sites)==len(expected),'complete permutation site population')
    for at,seq in zip(sites,expected):
        u.require(lines[at+1:at+1+len(seq)]==seq,'all immediate permutation erasures')
    return len(sites)


def common_shape(kind,rate,body,name,pins):
    text = u.normalized(body).replace(name,'FUNC')
    text = re.sub(r'\.Lfunc_(begin|end)\d+',r'.Lfunc_\1X',text)
    if kind=='enter':
        return text.replace(u.state.s.UPDATE+format(rate,'x')+'_E6updateB6_','RATE_UPDATE').replace(
            pins['finalize'+str(rate)]['name'],'RATE_FINALIZE')
    if kind=='finalize':
        # Do not conflate the backing-buffer check (1344 bits) with the rate.
        for next_line in ('jne .LBBX_14','movq 88(%rsp), %rdi'):
            text = text.replace(f'cmpq ${rate*8}, %r14\n'+next_line,'cmpq $RATE_BITS, %r14\n'+next_line)
        for reg in ('%r12d','%esi'): text = text.replace(f'movl ${rate}, '+reg,'movl $RATE, '+reg)
        return text.replace(f'leaq {416+rate-1}(%rdi), %rcx','leaq LAST_RATE_BYTE(%rdi), %rcx')
    for pattern in ('cmpq ${}, %r8','movl ${}, %ebx','movl ${}, %r13d','cmpq ${}, %rdx'):
        text = text.replace(pattern.format(rate),pattern.format('RATE'))
    return text.replace(f'cmpb ${rate-256}, %dil','cmpb $RATE_BYTE, %dil')
