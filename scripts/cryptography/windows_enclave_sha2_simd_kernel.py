"""Complete saved SHA-2 AVX2 kernels/transposes; not a general code verifier."""
import re
import windows_enclave_kmac_shapes as s

CONSTANTS={'simd256':'anon.aec77d9285fa1a27a1a0db11b330ebc4.3',
           'simd512':'anon.5401310e1ef939bdace79f9ff2af83d4.3'}


def parameters(lane):
    s.require(lane in CONSTANTS,'known saved SIMD lane')
    return (32,64,2304,2560,22) if lane=='simd256' else (64,80,2816,3072,20)


def cuberoot(value):
    low,high=0,1 << ((value.bit_length()+2)//3)
    while high-low>1:
        mid=(low+high)//2
        if mid**3<=value: low=mid
        else: high=mid
    return low


def round_constants(lane):
    """Exact fractional cube roots of the first 64/80 primes; no floating point."""
    bits,rounds,*_=parameters(lane);primes=[];candidate=2
    while len(primes)<rounds:
        if all(candidate%p for p in primes if p*p<=candidate): primes.append(candidate)
        candidate+=1
    mask=(1<<bits)-1
    return b''.join((cuberoot(p<<(3*bits))&mask).to_bytes(bits//8,'little') for p in primes)


def opaque_parts(body,markers):
    s.require(body.count('#APP')==body.count('#NO_APP')==1,'one opaque instruction region')
    before,middle=body.split('#APP');middle,after=middle.split('#NO_APP')
    for marker in markers: s.require(middle.count(marker)==1,'unique opaque marker '+marker)
    return [s.sha3.normalized(part) for part in (before,middle,after)]


def complete(actual,expected,label):
    s.require(actual==expected,'complete saved '+label+' instruction sequence')


def transpose_shape(lane,words,pack):
    bits,*_=parameters(lane);word=bits//8
    block=words==16
    tmp=(10 if lane=='simd256' else 8)+(4 if block else 0 if pack else 8)
    labels=[f'.Ltmp{tmp+i}' for i in range(4)]
    width,source,dest,swap=('%r10','%r11','%rsi','%edi') if block else ('%r11','%rsi','%rdi','%r10d')
    op,acc=('l','%eax') if word==4 else ('q','%rax')
    sw,sl,dw,dl=(word,words*word,32,word) if pack else (32,word,word,words*word)
    return ['xorl %r8d, %r8d',f'testq {width}, {width}','je '+labels[0],labels[1]+':',
        'xorl %ecx, %ecx',labels[2]+':',f'imulq ${sw}, %r8, %rdx',f'imulq ${sl}, %rcx, %r9',
        'addq %r9, %rdx',f'mov{op} ({source},%rdx), {acc}',f'testl {swap}, {swap}',
        'je '+labels[3],f'bswap{op} {acc}',labels[3]+':',f'imulq ${dw}, %r8, %rdx',
        f'imulq ${dl}, %rcx, %r9','addq %r9, %rdx',f'mov{op} {acc}, ({dest},%rdx)',
        'incq %rcx',f'cmpq {width}, %rcx','jne '+labels[2],'incq %r8',f'cmpq ${words}, %r8',
        'jne '+labels[1],labels[0]+':']+[f'xorl %{r}, %{r}' for r in ('eax','ecx','edx','r8d','r9d')]


def transpose_offsets(bits,words,width,pack):
    """Byte ranges derived from the inspected two-counter address expressions."""
    s.require(type(bits) is int and bits in (32,64) and type(words) is int and words in (8,16),
              'fixed transpose shape')
    s.require(type(width) is int and 0<=width<=256//bits and type(pack) is bool,'bounded lane count')
    word=bits//8
    pairs=[(lane*words*word+index*word,index*32+lane*word)
           for index in range(words) for lane in range(width)]
    return pairs if pack else [(b,a) for a,b in pairs]


def transposes(bodies,lane):
    bits,*_=parameters(lane);out={}
    for words,pack in ((8,True),(16,True),(8,False)):
        name=s.one(bodies,r'transfer9transposeKj'+('8' if words==8 else '10')+'_Kb'+str(int(pack))+'_')
        before,active,after=opaque_parts(bodies[name],('BRYNJA_TRANSFER_BEGIN','BRYNJA_TRANSFER_ERASE','BRYNJA_TRANSFER_END'))
        pre=['pushq %rsi','.seh_pushreg %rsi','pushq %rdi','.seh_pushreg %rdi','.seh_endprologue']
        pre += (['movq %r8, %r10','movq %rdx, %r11','movq %rcx, %rsi','movl $1, %edi'] if words==16 else
                ['movl %r9d, %r10d','movq %r8, %r11','movq %rdx, %rsi','movq %rcx, %rdi'])
        complete(before[3:],pre,'transpose pointer-only prologue')
        complete(active,transpose_shape(lane,words,pack),'transpose address/byte-order/erasure')
        complete(after,['.seh_startepilogue','popq %rdi','popq %rsi','.seh_endepilogue','retq'],
                 'transpose pointer-only epilogue')
        ranges=transpose_offsets(bits,words,256//bits,pack)
        out[name]=dict(words=words,lanes=256//bits,word_bytes=bits//8,pack=pack,
            source_extent=max(a for a,_ in ranges)+bits//8,destination_extent=max(b for _,b in ranges)+bits//8,
            swaps_publicly_selected=True,opaque_stack_accesses=0,secret_gpr_erased='rax')
    return out


def sigma(bits,rotations,shift=False):
    op='d' if bits==32 else 'q';a,b,c=rotations
    code=[f'vpsrl{op} ${a}, %ymm0, %ymm1',f'vpsll{op} ${bits-a}, %ymm0, %ymm2',
        'vpor %ymm2, %ymm1, %ymm1',f'vpsrl{op} ${b}, %ymm0, %ymm2',
        f'vpsll{op} ${bits-b}, %ymm0, %ymm3','vpor %ymm3, %ymm2, %ymm2','vpxor %ymm2, %ymm1, %ymm1']
    if shift: return code+[f'vpsrl{op} ${c}, %ymm0, %ymm0','vpxor %ymm0, %ymm1, %ymm1']
    return code+[f'vpsrl{op} ${c}, %ymm0, %ymm2',f'vpsll{op} ${bits-c}, %ymm0, %ymm3',
                 'vpor %ymm3, %ymm2, %ymm2','vpxor %ymm2, %ymm1, %ymm1']


def kernel_shape(lane):
    bits,rounds,work,tmp,first=parameters(lane);op='d' if bits==32 else 'q'
    l=[f'.Ltmp{first+i}' for i in range(6)]
    small=((7,18,3),(17,19,10)) if bits==32 else ((1,8,7),(19,61,6))
    big=((2,13,22),(6,11,25)) if bits==32 else ((28,34,39),(14,18,41))
    code=['xorl %ecx, %ecx',l[0]+':','vmovdqu (%r8,%rcx), %ymm0',f'vmovdqu %ymm0, {work}(%r8,%rcx)',
        'addq $32, %rcx','cmpq $256, %rcx','jne '+l[0],'movl $768, %ecx',l[1]+':',
        'vmovdqu -480(%r8,%rcx), %ymm0']+sigma(bits,small[0],True)
    code += [f'vmovdqu %ymm1, {tmp}(%r8)','vmovdqu -64(%r8,%rcx), %ymm0']+sigma(bits,small[1],True)
    code += [f'vpadd{op} {tmp}(%r8), %ymm1, %ymm1',f'vpadd{op} -512(%r8,%rcx), %ymm1, %ymm1',
        f'vpadd{op} -224(%r8,%rcx), %ymm1, %ymm1','vmovdqu %ymm1, (%r8,%rcx)',
        'addq $32, %rcx',f'cmpq ${work}, %rcx','jne '+l[1],'xorl %ecx, %ecx','xorl %edx, %edx',l[2]+':']
    for state,stage,rotations in ((work,tmp,big[0]),(work+128,tmp+32,big[1])):
        code += [f'vmovdqu {state}(%r8), %ymm0']+sigma(bits,rotations)+[f'vmovdqu %ymm1, {stage}(%r8)']
    # Ch(e,f,g) = g XOR (e AND (f XOR g)); Maj(a,b,c) = (a AND b) XOR ((a XOR b) AND c).
    code += [f'vmovdqu {work+128+32*i}(%r8), %ymm{i}' for i in range(3)]
    code += ['vpxor %ymm2, %ymm1, %ymm1','vpand %ymm1, %ymm0, %ymm0','vpxor %ymm2, %ymm0, %ymm0',
             f'vmovdqu %ymm0, {tmp+64}(%r8)']
    code += [f'vmovdqu {work+32*i}(%r8), %ymm{i}' for i in range(3)]
    code += ['vpand %ymm1, %ymm0, %ymm3','vpxor %ymm1, %ymm0, %ymm0','vpand %ymm2, %ymm0, %ymm0',
        'vpxor %ymm3, %ymm0, %ymm0',f'vmovdqu %ymm0, {tmp+96}(%r8)',f'vmovdqu {work+224}(%r8), %ymm0',
        f'vpadd{op} {tmp+32}(%r8), %ymm0, %ymm0',f'vpadd{op} {tmp+64}(%r8), %ymm0, %ymm0',
        f'vpadd{op} 256(%r8,%rcx), %ymm0, %ymm0',f'vpbroadcast{op} (%r9,%rdx), %ymm1',
        f'vpadd{op} %ymm1, %ymm0, %ymm0',f'vmovdqu %ymm0, {tmp+128}(%r8)',
        f'vmovdqu {tmp}(%r8), %ymm0',f'vpadd{op} {tmp+96}(%r8), %ymm0, %ymm0',f'vmovdqu %ymm0, {tmp+160}(%r8)']
    for index in range(7,0,-1):
        code += [f'vmovdqu {work+32*(index-1)}(%r8), %ymm0']
        if index==4: code += [f'vpadd{op} {tmp+128}(%r8), %ymm0, %ymm0']
        code += [f'vmovdqu %ymm0, {work+32*index}(%r8)']
    code += [f'vmovdqu {tmp+128}(%r8), %ymm0',f'vpadd{op} {tmp+160}(%r8), %ymm0, %ymm0',
        f'vmovdqu %ymm0, {work}(%r8)','addq $32, %rcx',f'addq ${bits//8}, %rdx',
        f'cmpq ${rounds*bits//8}, %rdx','jne '+l[2],'xorl %ecx, %ecx',l[3]+':',
        f'vmovdqu {work}(%r8,%rcx), %ymm0',f'vpadd{op} (%r8,%rcx), %ymm0, %ymm0',
        f'vmovdqu %ymm0, {work}(%r8,%rcx)','addq $32, %rcx','cmpq $256, %rcx','jne '+l[3],
        'xorl %eax, %eax','xorl %ecx, %ecx',l[4]+':','movq %rax, (%r8,%rcx)','addq $8, %rcx',
        f'cmpq ${work}, %rcx','jne '+l[4],f'movl ${tmp}, %ecx',l[5]+':',
        'movq %rax, (%r8,%rcx)','addq $8, %rcx',f'cmpq ${tmp+192}, %rcx','jne '+l[5]]
    code += [f'vpxor %ymm{i}, %ymm{i}, %ymm{i}' for i in range(4)]
    return code+[f'xorl %{r}, %{r}' for r in ('eax','ecx','edx')]+['cmpl %eax, %eax','vzeroupper']


def kernel(bodies,lane):
    bits,rounds,work,tmp,_=parameters(lane)
    name=s.one(bodies,r'hardened_batch3x866secret8compress$')
    wrapper=s.one(bodies,r'hardened_batch3x8615compress_secret$')
    complete(s.lines(bodies[wrapper])[2:],['jmp '+name],'kernel tail wrapper')
    before,active,after=opaque_parts(bodies[name],('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END'))
    complete(active,kernel_shape(lane),'SHA-2 schedule/rounds/feedforward/erase')
    pre=['subq $168, %rsp','.seh_stackalloc 168']
    mem=lambda offset: (str(offset) if offset else '')+'(%rsp)'
    for r in range(15,5,-1): pre += [f'vmovaps %xmm{r}, {mem((r-6)*16)}',f'.seh_savexmm %xmm{r}, {(r-6)*16}']
    pre += ['.seh_endprologue','movq %rcx, %r8',f'leaq {CONSTANTS[lane]}(%rip), %r9']
    complete(before[3:],pre,'kernel incoming-register saves and pointers')
    complete(after,[f'vmovaps {mem((r-6)*16)}, %xmm{r}' for r in range(6,16)]+
        ['.seh_startepilogue','addq $168, %rsp','.seh_endepilogue','retq'],'kernel incoming-register restores')
    return dict(function=name,rounds=rounds,word_bits=bits,lanes=256//bits,
        initial_region=[0,256],schedule_region=[256,work],output_region=[work,tmp],scratch_region=[tmp,tmp+192],
        erased_regions=[[0,work],[tmp,tmp+192]],output_requires_session_wipe=True,
        working_vectors_erased=[0,1,2,3],working_gprs_erased=['rax','rcx','rdx'],opaque_stack_accesses=0,
        incoming_vector_saves_require_outer_window_clearing=True,shared_runtime_qualified=False)


def inspect(bodies,lane):
    return dict(transposes=transposes(bodies,lane),kernel=kernel(bodies,lane),
                full_digest_lane_engine_and_storage_composition_pending=True)
