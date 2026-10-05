"""Inspected scalar SHA-3 state sequences, not general compiler verification."""
import windows_enclave_sha3_operations as ops

STATE = ops.s.STATE
NAMES = dict(new=STATE+'3new',finish_fixed=STATE+'12finish_fixed',finish_xof=STATE+'10finish_xof')
ZERO,DROP,WIPE = ops.s.ZERO,ops.s.DROP,ops.life.s.WIPE
CORE = '_RNvNtCsjNKEhcqdpKw_11brynja_core'
BYTES = CORE+'22secret_memory_transfer10copy_bytes'
MASK = CORE+'13secret_memory22apply_secret_byte_mask'
PERMUTE = '_RNvNtNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened11permutation6native6scalar'
OUTPUT = '_RNvNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6output13finish_secret'
UPDATE = '_RNvMNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6spongeINtNtB4_5owner20HardenedFips202OwnerKj'
ENTER128 = '_RNvMs4_NtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6cshakeNtB5_17HardenedCshake12824enter_squeezing_in_place'
ENTER256 = ENTER128.replace('Ms4_','Ms6_').replace('12824','25624')
SEQUENCES = {
 'new':(
    'movq 16(%r8), %rsi|cmpq $8192, %rsi|ja .LBB45_2',
    'movq 16(%r9), %rbx|cmpq $8193, %rbx|jb .LBB45_3',
    'movl %edx, %eax|notb %al|testb $6, %al|je .LBB45_5|movq %rbx, %rax|orq %rsi, %rax|je .LBB45_5|movw $255, (%rcx)',
    'movzbl %dl, %eax|leaq .LJTI45_0(%rip), %rdx|movslq (%rdx,%rax,4), %rax|addq %rdx, %rax|jmpq *%rax',
    'movw $-22527, 1152(%rsp)|movw $2, 1408(%rsp)',
    'movw $-30719, 1152(%rsp)|movw $2, 1408(%rsp)',
    'cmpq %rbx, %rdi|jne .LBB45_51|movq 1432(%rsp), %rcx|movl $1, %edx|callq '+ZERO,
    'cmpq %rbx, %rsi|jne .LBB45_51|movq 1432(%rsp), %rcx|movl $1, %edx|callq '+ZERO,
    '.LBB45_51:|movq 1432(%rsp), %rcx|movl $1, %edx|callq '+ZERO+'|leaq 1688(%rsp), %rcx|callq '+WIPE,
    'movq 104(%rsp), %rax|movw $1791, (%rax)|jmp .LBB45_50',
    '.LBB45_30:|movb %al, (%rcx)|movb $0, 1(%rcx)',
    'movl %ebx, 1033(%rsi)|movb %r14b, 1037(%rsi)|movb %r12b, 1038(%rsi)|movb %r15b, 1039(%rsi)|movb %r13b, 1040(%rsi)|movb %bpl, 1041(%rsi)|jmp .LBB45_50'),
 'finish_fixed':(
    'leaq 1136(%rsp), %rcx|movl $1024, %r8d|xorl %edx, %edx|callq memset',
    'leaq 2160(%rsp), %rcx|movl $1136, %r8d|movq %rbx, %rdx|callq memcpy|movb $0, (%rbx)',
    'movzbl 2160(%rsp), %eax|leal -1(%rax), %ecx|cmpl $3, %ecx|ja .LBB50_18',
    'leaq 2160(%rsp), %rcx|callq '+DROP+'|jmp .LBB50_130',
    'movb $3, 32(%rsp)|leaq 96(%rsp), %rcx|movq %r14, %rdx|movl %ebp, %r8d|movb $6, %r9b|callq '+UPDATE+'88_E8finalizeB6_',
    '.LBB50_128:|movb %r15b, 48(%rsp)|leaq 1136(%rsp), %rcx|movq %rsi, %rdx|callq '+ZERO+'|leaq 96(%rsp), %rcx|callq '+WIPE,
    '.LBB50_130:|leaq 1136(%rsp), %rcx|movl $1024, %edx|callq '+ZERO,
    '.LBB50_133:|movq %rdi, %rcx|movq %rsi, %rdx|callq '+ops.s.COPY,
    'testq %r12, %r12|je .LBB50_136|testq %r15, %r15|je .LBB50_136|movq %r15, %rcx|movq %r14, %rdx|callq '+ZERO,
    '.LBB50_136:|orb $5, %bl|jmp .LBB50_130'),
 'finish_xof':(
    'movzbl (%rcx), %r8d|cmpl $6, %r8d|je .LBB52_3|movb $2, %al|cmpl $5, %r8d|jne .LBB52_5',
    'incq %rcx|callq '+ENTER128+'|jmp .LBB52_4',
    '.LBB52_3:|incq %rcx|callq '+ENTER256,
    '.LBB52_4:|cmpb $-1, %al|sete %al|negb %al|orb $6, %al'),
}


def normalized(text):
    return '\n'.join(' '.join(l.split()) for l in text.splitlines() if not l.lstrip().startswith('#'))


def sequences(role,body):
    body = normalized(body)
    for sequence in SEQUENCES[role]:
        ops.require(sequence.replace('|','\n') in body,'reviewed state admission/consumption/cleanup: '+role)
    if role=='finish_fixed':
        for width in (28,32,48,64):
            ops.require(f'cmpq ${width}, %rsi\njne .LBB50_128' in body,'exact fixed-output width')
        carry = 'addq 96(%rsp), %rax\nmovq 104(%rsp), %rax\nadcq $0, %rax\nmovb $1, %r15b\njb .LBB50_128'
        ops.require(body.count(carry)==4,'all four checked message admissions')
        ops.require(body.count('callq '+OUTPUT+'\nmovq 40(%rsp), %r12\nleaq 96(%rsp), %rcx\ncallq '+WIPE)==2,
                    'both output-wrapper branches destroy consumed active state')


def permutation_cleanup(body):
    """Every inlined fixed-finalizer permutation is followed by four erasures."""
    lines = normalized(body).splitlines();found = []
    for at,line in enumerate(lines):
        if line!='callq '+PERMUTE: continue
        following = lines[at+1:at+13]
        choices = []
        for third in ('%r15','%rbp'):
            expected = []
            for size,reg in ((40,'%r12'),(40,'%r14'),(200,third),(168,'%r13')):
                expected += [f'movl ${size}, %edx',f'movq {reg}, %rcx','callq '+ZERO]
            choices.append(expected)
        ops.require(following in choices,'each permutation clears all four scratch regions before branching')
        found.append(at)
    ops.require(len(found)==15,'complete inlined permutation-call population')
    for width,rate,last_at in ((28,144,655),(48,104,615),(64,72,583)):
        ops.require(lines.count(f'movl ${rate}, %ebp')==5,'five permutation loops per inlined rate')
        ops.require(f'leaq {last_at}(%rsp), %rcx\nmovb $-1, %dl\nmovb $-128, %r8b\ncallq '+MASK in '\n'.join(lines),
                    'last rate-byte padding bit')
        ops.require(f'movl ${width}, %edx\nmovl ${width}, %r9d' in '\n'.join(lines),'fixed digest transfer width')
    return dict(inlined_permutation_calls=15,scratch_lengths=[40,40,200,168],
                sha3_256_finalize_delegated=True,permutation_internals_qualified=False)
