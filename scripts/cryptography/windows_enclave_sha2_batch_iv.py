"""Scoped public IV derivation checks for the frozen scalar batch constructor."""
import re
import windows_enclave_kmac_shapes as s

IVS=(
    'c1059ed8 367cd507 3070dd17 f70e5939 ffc00b31 68581511 64f98fa7 befa4fa4',
    '6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19',
    'cbbb9d5dc1059ed8 629a292a367cd507 9159015a3070dd17 152fecd8f70e5939 '
    '67332667ffc00b31 8eb44a8768581511 db0c2e0d64f98fa7 47b5481dbefa4fa4',
    '6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 '
    '510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179',
    '8c3d37c819544da2 73e1996689dcd4d6 1dfab7ae32ff9c82 679dd514582f9fcf '
    '0f6d2b697bd44da8 77e36f7304c48942 3f9d85a86a1d36c8 1112e6ad91d692a1',
    '22312194fc2bf72c 9f555fa3c84c64c2 2393b86b6f53b151 963877195940eabd '
    '96283ee2a88effe3 be5e1e2553863992 2b0199fc2c85b8aa 0eb72ddc81c52ca2')
REGISTERS={'r13':'r12','r12':'rbp','r15':'rbx','rbp':'r14',
           'rbx':'r15','rsi':'rdi','rdi':'r13','r14':'rsi'}
ROUND='anon.7b9e5a485f344afc4b021075be1f825c.0'


def decimal_label(t):
    """Cross-check emitted reciprocal division and encoded-tag comparisons."""
    s.require(type(t) is int and 1<=t<=511 and t!=384,'admitted public general-t')
    hundreds=((t>>2)*5243)>>17;tens_div=(t*52429)>>19
    tens=tens_div-((((tens_div*6554)>>15)&~1)*5);ones=t-10*tens_div
    encoded=(t<<16)|6
    first=1+int(encoded<655360)
    if encoded>=6553600: first=0
    digits=(hundreds,tens,ones)[first:]
    s.require(all(0<=digit<=9 for digit in digits),'decimal digit bounds')
    return b'SHA-512/'+bytes(48+digit for digit in digits)


def loop(body,label):
    code=s.lines(body);start=code.index(label+':');end=code.index('jne '+label,start)
    return code[start:end+1]


def loops(previous,current):
    """Only two named public loops; explicit frame and register substitutions."""
    result={}
    for role,old,new,renames in (('schedule','.B14','.B30',{}),
                                 ('rounds','.B16','.B32',REGISTERS)):
        before=loop(previous,old);after=loop(current,new)
        expected=[]
        for line in before:
            line=line.replace(old,new)
            line=re.sub(r'(\d+)\(%rsp',lambda m:str(int(m[1])+1136)+'(%rsp',line)
            line=re.sub(r'%([a-z0-9]+)\b',lambda m:'%'+renames.get(m[1],m[1]),line)
            expected.append(line)
        s.require(after==expected,'exact public '+role+' loop under explicit substitutions')
        result[role]=dict(instructions=len(after)-1,stack_displacement=1136,register_substitutions=renames)
    return result


def named(body):
    places=('%esi','%r14d','40(%rsp)','%r12d','36(%rsp)','%r15d','32(%rsp)','%r13d')
    for tag,hexadecimal in enumerate(IVS):
        raw=bytes.fromhex(hexadecimal)
        initialize=[f'.B{17+tag}:','xorps %xmm0, %xmm0']
        initialize += [f'movaps %xmm0, {n}(%rsp)' for n in (112,96,80,64)]
        initialize += [f'movups %xmm0, {n}(%rsp)' for n in range(1199,1327,16)]
        initialize += ['movaps %xmm0, 128(%rsp)',
                       'movq $0, 56(%rsp)' if tag<2 else 'movl $0, 44(%rsp)',
                       'leaq 306(%rsp), %rcx','movl $893, %r8d','xorl %edx, %edx','callq memset']
        if tag: initialize.append(f'movb ${tag}, %cl')
        initialize += [f'movl ${int.from_bytes(raw[4*i:4*i+4],"little",signed=True)}, {place}'
                       for i,place in enumerate(places)]
        if tag>=2:
            for i,place in enumerate(('%rbx','%rbp','%rax','%rax')):
                value=int.from_bytes(raw[32+8*i:40+8*i],'little',signed=True)
                initialize.append(f'movabsq ${value}, {place}')
                if i>=2: initialize.append(f'movq %rax, {48+8*(i-2)}(%rsp)')
        elif tag==0:
            initialize += ['movq $0, 48(%rsp)','xorl %ebp, %ebp','xorl %ebx, %ebx',
                           'movl $0, 44(%rsp)','xorl %ecx, %ecx']
        else:
            initialize += ['movl $0, %eax','movq %rax, 48(%rsp)','movl $0, %ebp',
                           'movl $0, %ebx','movl $0, 44(%rsp)']
        initialize.append('jmp .B34');s.sequences(body,['|'.join(initialize)])
    return dict(variants=6,iv_storage_byte_order='big endian',unused_narrow_words_zero=True)


def general(body):
    s.sequences(body,[
        '.B23:|movq %rdi, 152(%rsp)|movb $0, 1338(%rsp)|movw $0, 1336(%rsp)|'
        'movabsq $3400834773080426579, %rcx|movq %rcx, 1328(%rsp)|movl %eax, %ecx|'
        'shrl $2, %ecx|imull $5243, %ecx, %ecx|shrl $17, %ecx|imull $52429, %eax, %r8d|'
        'shrl $19, %r8d|imull $6554, %r8d, %r9d|shrl $15, %r9d|andl $-2, %r9d|'
        'leal (%r9,%r9,4), %r9d|movl %r8d, %r10d|subl %r9d, %r10d|addl %r8d, %r8d|'
        'leal (%r8,%r8,4), %r8d|movl %eax, %r9d|subl %r8d, %r9d|'
        'movw %cx, 160(%rsp)|movw %r10w, 162(%rsp)|movw %r9w, 164(%rsp)',
        'xorl %r8d, %r8d|cmpl $655360, %edx|movl $0, %ecx|adcq $1, %rcx|'
        'cmpl $6553600, %edx|cmovaeq %r8, %rcx|movl %ecx, %r8d|'
        'movzbl 160(%rsp,%r8,2), %r8d|addb $48, %r8b|movzbl %r8b, %r9d|'
        'movl $255, %r8d|cmovbl %r8d, %r9d|movb %r9b, 1336(%rsp)|cmpq $2, %rcx|je .B26|'
        'movzbl 162(%rsp,%rcx,2), %r9d|addb $48, %r9b|movzbl %r9b, %r9d|'
        'cmovbl %r8d, %r9d|movb %r9b, 1337(%rsp)|leal -655360(%rdx), %r8d|'
        'cmpl $5898240, %r8d|jb .B26|movzbl 164(%rsp,%rcx,2), %r8d|addb $48, %r8b|'
        'movzbl %r8b, %r8d|movl $255, %r9d|cmovael %r8d, %r9d|movb %r9b, 1338(%rsp)',
        '.B26:|movl %eax, 44(%rsp)|movq 1328(%rsp), %r9|movzbl 1336(%rsp), %r10d|'
        'movzbl 1337(%rsp), %r8d|movzbl 1338(%rsp), %eax|movl $11, %edi|subq %rcx, %rdi|'
        'xorps %xmm6, %xmm6|'+'|'.join(f'movaps %xmm6, {n}(%rsp)' for n in (160,256,240,224,208,192,176))+
        '|movq %r9, 160(%rsp)|movb %r10b, 168(%rsp)|cmpq $2, %rcx|je .B29|'
        'movb %r8b, 169(%rsp)|addl $-655360, %edx|cmpl $5898240, %edx|jb .B29|movb %al, 170(%rsp)',
        '.B29:|movb $-128, 160(%rsp,%rdi)|shll $3, %edi|leaq 1456(%rsp), %rcx|'
        'xorl %esi, %esi|movl $512, %r8d|xorl %edx, %edx|callq memset|'
        'movq 160(%rsp), %rax|movq 168(%rsp), %rcx|bswapq %rax|movq %rax, 1328(%rsp)|'
        'bswapq %rcx|movq %rcx, 1336(%rsp)|'+
        '|'.join(f'movups %xmm6, {n}(%rsp)' for n in range(1344,1440,16))+
        '|movq $0, 1440(%rsp)|movq %rdi, 1448(%rsp)'])
    words=[int(x,16)^0xa5a5a5a5a5a5a5a5 for x in IVS[3].split()]
    signed=[x if x<1<<63 else x-(1<<64) for x in words]
    regs=('r14','r12','r10','rdx','rbx','rbp','r9','r8')
    init=[f'movabsq ${signed[i]}, %{regs[i]}' for i in (1,2,3,5,6,7,4,0)]
    s.sequences(body,['|'.join(init)+f'|xorl %eax, %eax|leaq {ROUND}(%rip), %rcx'])
    out=('r14','r12','r15','r13','rbx','rbp','rdi','rsi')
    feed=[]
    for value,reg in zip(signed[:7],out[:7]): feed += [f'movabsq ${value}, %rax',f'addq %rax, %{reg}']
    feed += [f'movabsq ${signed[7]}, %rax']+[f'bswapq %{reg}' for reg in out[:7]]
    feed += ['addq %rax, %rsi','bswapq %rsi']
    s.sequences(body,['|'.join(feed)])
    return dict(public_label='SHA-512/<decimal t>',admitted_parameters=510,
        single_block_padding=True,rounds=80,initial_state_xor='a5a5a5a5a5a5a5a5',
        feedforward_and_big_endian_serialization_checked=True,
        loops_require_explicit_prior_review_replay=True)


def transfer(body):
    s.sequences(body,[
        'xorps %xmm6, %xmm6|'+'|'.join(f'movaps %xmm6, {n}(%rsp)' for n in (1376,1360,1344,1328))+'|'+
        '|'.join(f'movups %xmm6, {n}(%rsp)' for n in (1202,1218,1234,1250,1266,1282,1298,1311))+
        '|movw $0, 160(%rsp)|movb $0, 162(%rsp)|movq $0, 1392(%rsp)|movq $0, 1397(%rsp)|'
        'leaq 306(%rsp), %rcx|movl $896, %r8d|xorl %edx, %edx|callq memset|'+
        '|'.join(f'movq %{reg}, {163+8*i}(%rsp)' for i,reg in enumerate(('r14','r12','r15','r13','rbx','rbp','rdi','rsi'))),
        'movl 160(%rsp), %esi|shrq $8, %r14|movl 168(%rsp), %eax|movl %eax, 40(%rsp)|'
        'shrq $8, %r12|movl 176(%rsp), %eax|movl %eax, 36(%rsp)|shrq $8, %r15|'
        'movl 184(%rsp), %eax|movl %eax, 32(%rsp)|shrq $8, %r13|movq 192(%rsp), %rbx|'
        'movq 200(%rsp), %rbp|movq 208(%rsp), %rax|movq %rax, 48(%rsp)|'
        'movq 216(%rsp), %rax|movq %rax, 56(%rsp)|movzwl 224(%rsp), %eax|movw %ax, 64(%rsp)|'
        'movzbl 226(%rsp), %eax|movb %al, 66(%rsp)|movups %xmm6, 112(%rsp)|'
        'movups %xmm6, 99(%rsp)|movups %xmm6, 83(%rsp)|movups %xmm6, 67(%rsp)|'
        'movups 1389(%rsp), %xmm0|movaps %xmm0, 128(%rsp)|movb $6, %cl|movq 152(%rsp), %rdi',
        'movl %esi, 1633(%rdi)|movl %r14d, 1637(%rdi)|movl 40(%rsp), %eax|movl %eax, 1641(%rdi)|'
        'movl %r12d, 1645(%rdi)|movl 36(%rsp), %eax|movl %eax, 1649(%rdi)|movl %r15d, 1653(%rdi)|'
        'movl 32(%rsp), %eax|movl %eax, 1657(%rdi)|movl %r13d, 1661(%rdi)|'
        'movq %rbx, 1665(%rdi)|movq %rbp, 1673(%rdi)|movq 48(%rsp), %rax|movq %rax, 1681(%rdi)|'
        'movq 56(%rsp), %rax|movq %rax, 1689(%rdi)|movaps 64(%rsp), %xmm0|movaps 80(%rsp), %xmm1|'
        'movaps 96(%rsp), %xmm2|movaps 112(%rsp), %xmm3|movups %xmm0, 1697(%rdi)|'
        'movups %xmm1, 1713(%rdi)|movups %xmm2, 1729(%rdi)|movups %xmm3, 1745(%rdi)|'
        'movaps 128(%rsp), %xmm0|movups %xmm0, 1761(%rdi)|movl $0, 1777(%rdi)|movw $512, 1781(%rdi)'])
    return dict(named_iv_offset=1633,general_iv_offset=1636,general_prefix_zero_bytes=3,
        scratch_bytes=1024,pending_length_and_count_zero=True,
        compiler_copies_require_enclosing_window_cleanup=True)


def inspect(bodies):
    body=bodies[s.one(bodies,r'Owner5start$')]
    return dict(named=named(body),general=general(body),placement=transfer(body))
