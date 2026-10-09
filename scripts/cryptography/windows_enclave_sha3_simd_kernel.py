"""Saved four-lane Keccak leaf contracts; caller/whole-frame review is separate.

Expected instructions are generated from Keccak coordinates, not copied from
the candidate disassembly. The parent binds relocations and linked table bytes.
This checks the saved compiler output only, not arbitrary future machine code.
"""
import hashlib
import windows_enclave_sha2_simd_kernel as envelope
import windows_enclave_sha2_simd_reuse as features
import windows_enclave_kmac_reuse as reuse

s=reuse.shapes
TABLE='anon.7c919edcafcc2b40f04074ce5f7a2ecc.0'


def rotations():
    result={(0,0):0};x,y=1,0
    for t in range(24):
        result[x,y]=((t+1)*(t+2)//2)%64
        x,y=y,(2*x+3*y)%5
    return result


def round_constants():
    state=1;out=[]
    for _ in range(24):
        value=0
        for j in range(7):
            if state&1:value^=1<<((1<<j)-1)
            state=((state<<1)^ (0x71 if state&128 else 0))&255
        out.append(value)
    return b''.join(v.to_bytes(8,'little') for v in out)


def mem(offset,index=False):
    return (str(offset) if offset else '')+'(%r8'+(',%rcx)' if index else ')')


def rotate(bits):
    if not bits:return []
    return [f'vpsllq ${bits}, %ymm0, %ymm1',f'vpsrlq ${64-bits}, %ymm0, %ymm0',
            'vpor %ymm1, %ymm0, %ymm0']


def kernel_shape():
    code=['xorl %eax, %eax','.Ltmp14:','xorl %ecx, %ecx','.Ltmp15:',
          'vmovdqu (%r8,%rcx), %ymm0']
    code += [f'vpxor {mem(160*y,True)}, %ymm0, %ymm0' for y in range(1,5)]
    code += ['vmovdqu %ymm0, 800(%r8,%rcx)','addq $32, %rcx','cmpq $160, %rcx','jne .Ltmp15']
    for x in range(5):
        code += [f'vmovdqu {mem(800+32*((x+1)%5))}, %ymm0']+rotate(1)
        code += [f'vpxor {mem(800+32*((x-1)%5))}, %ymm0, %ymm0',
                 f'vmovdqu %ymm0, {mem(960+32*x)}']
    rho=rotations()
    for y in range(5):
        for x in range(5):
            code += [f'vmovdqu {mem(32*(x+5*y))}, %ymm0',
                     f'vpxor {mem(960+32*x)}, %ymm0, %ymm0']+rotate(rho[x,y])
            code += [f'vmovdqu %ymm0, {mem(1120+32*(y+5*((2*x+3*y)%5)))}']
    code += ['xorl %ecx, %ecx','.Ltmp16:']
    for x in range(5):
        code += [f'vmovdqu {mem(1120+32*((x+1)%5),True)}, %ymm0',
                 f'vpandn {mem(1120+32*((x+2)%5),True)}, %ymm0, %ymm0',
                 f'vpxor {mem(1120+32*x,True)}, %ymm0, %ymm0',
                 f'vmovdqu %ymm0, {mem(32*x,True)}']
    code += ['addq $160, %rcx','cmpq $800, %rcx','jne .Ltmp16',
             'vpbroadcastq (%r9,%rax), %ymm0','vpxor (%r8), %ymm0, %ymm0',
             'vmovdqu %ymm0, (%r8)','addq $8, %rax','cmpq $192, %rax','jne .Ltmp14',
             'vpxor %ymm0, %ymm0, %ymm0','movl $800, %ecx','.Ltmp17:',
             'vmovdqu %ymm0, (%r8,%rcx)','addq $32, %rcx','cmpq $1920, %rcx','jne .Ltmp17']
    code += [f'xorl %{r}, %{r}' for r in ('eax','ecx','edx')]
    code += [f'vpxor %ymm{i}, %ymm{i}, %ymm{i}' for i in range(4)]
    return code+['cmpl %eax, %eax','vzeroupper']


def transpose_shape(pack):
    first=8 if pack else 11
    end,outer,inner=[f'.Ltmp{first+i}' for i in range(3)]
    sw,sl,dw,dl=(8,200,32,8) if pack else (32,8,8,200)
    return ['xorl %r8d, %r8d','testq %r10, %r10','je '+end,outer+':',
        'xorl %ecx, %ecx',inner+':',f'imulq ${sw}, %r8, %rdx',f'imulq ${sl}, %rcx, %r9',
        'addq %r9, %rdx','movq (%r11,%rdx), %rax',f'imulq ${dw}, %r8, %rdx',
        f'imulq ${dl}, %rcx, %r9','addq %r9, %rdx','movq %rax, (%rsi,%rdx)',
        'incq %rcx','cmpq %r10, %rcx','jne '+inner,'incq %r8','cmpq $25, %r8',
        'jne '+outer,end+':']+[f'xorl %{r}, %{r}' for r in ('eax','ecx','edx','r8d','r9d')]


def offsets(width,pack):
    # Machine loop supports 0..4; this saved LLVM specialization admits 2..4.
    s.require(type(width) is int and 0<=width<=4 and type(pack) is bool,'bounded transpose model')
    pairs=[(200*lane+8*word,32*word+8*lane) for word in range(25) for lane in range(width)]
    return pairs if pack else [(b,a) for a,b in pairs]


def abi(ir,name,role):
    target=features.SIMD_FEATURES
    if role in ('kernel','wrapper'):
        target+=',+avx,+avx2,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3'
    argument=('ptr noundef nonnull %0, ptr noundef nonnull %1, i64 noundef range(i64 2, 5) %2'
              if role=='transpose' else 'ptr noalias nofree noundef nonnull dereferenceable(1920) %0')
    attrs='noinline nounwind uwtable'
    suffix=' personality ptr @__CxxFrameHandler3' if role=='kernel' else ''
    expected=f'define internal fastcc void @{name}({argument}) unnamed_addr '+(
        '{ '+attrs+' "target-cpu"="x86-64" "target-features"="'+target+'" }')+suffix+' {'
    s.require(reuse.abi(ir,name)==expected,'exact Keccak SIMD leaf ABI '+role)


def inspect(bodies,ir,constants):
    raw=round_constants()
    s.require(TABLE in constants and constants[TABLE]['bytes']==192 and
        constants[TABLE]['sha256']==hashlib.sha256(raw).hexdigest(),'independently derived linked Keccak constants')
    names={};complete=envelope.complete
    for pack in (True,False):
        name=s.one(bodies,r'keccak_hardened_batch8transfer9transposeKb'+str(int(pack))+'_')
        before,active,after=envelope.opaque_parts(bodies[name],
            ('BRYNJA_TRANSFER_BEGIN','BRYNJA_TRANSFER_ERASE','BRYNJA_TRANSFER_END'))
        complete(before[3:],['pushq %rsi','.seh_pushreg %rsi','.seh_endprologue',
            'movq %r8, %r10','movq %rdx, %r11','movq %rcx, %rsi'],'Keccak transpose pointer envelope')
        complete(active,transpose_shape(pack),'Keccak transpose mapping and erasure')
        complete(after,['.seh_startepilogue','popq %rsi','.seh_endepilogue','retq'],'Keccak transpose return')
        abi(ir,name,'transpose');names['pack' if pack else 'unpack']=name
    name=s.one(bodies,r'keccak_hardened_batch3x866secret7permute$');names['kernel']=name
    wrapper=s.one(bodies,r'keccak_hardened_batch3x8614permute_secret$');names['wrapper']=wrapper
    complete(s.lines(bodies[wrapper])[2:],['jmp '+name],'Keccak kernel tail wrapper')
    before,active,after=envelope.opaque_parts(bodies[name],
        ('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END'))
    pre=['subq $168, %rsp','.seh_stackalloc 168']
    stack=lambda n:(str(n) if n else '')+'(%rsp)'
    for r in range(15,5,-1):
        pre += [f'vmovaps %xmm{r}, {stack((r-6)*16)}',f'.seh_savexmm %xmm{r}, {(r-6)*16}']
    pre += ['.seh_endprologue','movq %rcx, %r8',f'leaq {TABLE}(%rip), %r9']
    complete(before[3:],pre,'Keccak incoming-register saves and pointers')
    complete(active,kernel_shape(),'Keccak theta/rho/pi/chi/iota and scratch/register erasure')
    complete(after,[f'vmovaps {stack((r-6)*16)}, %xmm{r}' for r in range(6,16)]+
        ['.seh_startepilogue','addq $168, %rsp','.seh_endepilogue','retq'],'Keccak incoming-register restores')
    abi(ir,name,'kernel');abi(ir,wrapper,'wrapper')
    return dict(functions=names,rounds=24,lanes=4,word_bits=64,
        transpose_llvm_width_range=[2,5],transpose_machine_width_model=[0,4],
        state_region=[0,800],column_region=[800,960],delta_region=[960,1120],stage_region=[1120,1920],
        erased_scratch_region=[800,1920],working_gprs_erased=['rax','rcx','rdx'],
        working_vectors_erased=[0,1,2,3],opaque_stack_accesses=0,
        linked_constants_independently_derived=True,
        caller_valid_disjoint_allocations_and_isa_required=True,
        inactive_lanes_require_caller_initialization=True,output_requires_caller_wipe=True,
        incoming_vector_saves_require_outer_window_clearing=True,
        session_and_caller_lifetimes_qualified=False,private_frame_erasure_qualified=False)
