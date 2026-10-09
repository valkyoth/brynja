"""Exact workspace/output destruction and bounded-copy helper contracts."""
import windows_enclave_sha3_simd_receive as receive
import windows_enclave_sha3_batch_copy as copy
life,s,L=receive.life,receive.s,receive.L


def names(bodies):
    return receive.names(bodies)|{role:s.one(bodies,pattern) for role,pattern in (
        ('executor',r'^[^?].*Executor13digest_secret$'),
        ('workspace_drop',r'^_RINv.*drop_glue.*workspace9WorkspaceE'),
        ('workspace_wipe',r'^_RNvMs_.*hardened_batch9workspace.*Workspace4wipe$'),
        ('scalar_wipe',r'HardenedFips202OwnerKj88_E4wipe'),
        ('cpu_wipe',r'^_RNvMs_.*keccak_hardened_batch7scratch.*Workspace4wipe$'),
        ('output_drop',r'^_RNvXs_.*SecretBatchOutput.*Drop4drop$'))}|{'copy':copy.WRAPPER,'copy_leaf':copy.LEAF}


def lane_clear():
    code=[]
    for base in range(3584,4208,156):
        code+=L(f'''leaq {base}(%rsi), %rdi|leaq {base+32}(%rsi), %rcx|
            movl $72, %edx|callq {life.ZERO}|leaq {base+104}(%rsi), %rcx|
            movl $51, %edx|callq {life.ZERO}|movl $32, %edx|movq %rdi, %rcx|
            callq {life.ZERO}|leaq {base+155}(%rsi), %rcx|movl $1, %edx|callq {life.ZERO}''')
    return code


def shapes(n):
    start=L('pushq %rsi|pushq %rdi|subq $40, %rsp|movq %rcx, %rsi')
    tail=L(f'''leaq 4208(%rsi), %rcx|callq {n['scalar_wipe']}|movq %rsi, %rcx|
        addq $40, %rsp|popq %rdi|popq %rsi|jmp {n['cpu_wipe']}''')
    wipe=start+L(f'addq $1920, %rcx|movl $800, %edx|callq {life.ZERO}')
    for at,size in ((2720,800),(3520,32),(3552,32),(5248,4),(5252,4),(5256,4)):
        wipe+=L(f'leaq {at}(%rsi), %rcx|movl ${size}, %edx|callq {life.ZERO}')
    scalar=L(f'pushq %rsi|subq $32, %rsp|movq %rcx, %rsi|addq $48, %rcx|movl $200, %edx|callq {life.ZERO}')
    for at,size in ((248,168),(0,16),(16,16),(32,16),(1036,1),(1037,3),(1032,4),
                    (416,168),(584,168),(752,40),(792,40)):
        scalar += [f'leaq {at}(%rsi), %rcx'] if at else []
        scalar += [f'movl ${size}, %edx']+(['movq %rsi, %rcx'] if not at else [])+['callq '+life.ZERO]
    scalar+=L(f'''addq $832, %rsi|movl $200, %edx|movq %rsi, %rcx|
        addq $32, %rsp|popq %rsi|jmp {life.ZERO}''')
    output=start+L(f'''xorl %edi, %edi|cmpq $64, %rdi|jne .B2|jmp .B4|.B3:|
        addq $16, %rdi|cmpq $64, %rdi|je .B4|.B2:|movq (%rsi,%rdi), %rcx|
        testq %rcx, %rcx|je .B3|movq 8(%rsi,%rdi), %rdx|testq %rdx, %rdx|
        je .B3|callq {life.ZERO}|addq $16, %rdi|cmpq $64, %rdi|jne .B2|
        .B4:|leaq 96(%rsi), %rcx|movl $4, %edx|callq {life.ZERO}|
        addq $64, %rsi|movl $32, %edx|movq %rsi, %rcx|
        addq $40, %rsp|popq %rdi|popq %rsi|jmp {life.ZERO}''')
    return {n['workspace_wipe']:wipe+lane_clear()+tail,
        n['workspace_drop']:start+['callq '+n['workspace_wipe']]+lane_clear()+tail,
        n['scalar_wipe']:scalar,n['output_drop']:output}


def geometry():
    scalar=((48,200),(248,168),(0,16),(16,16),(32,16),(1036,1),(1037,3),(1032,4),
            (416,168),(584,168),(752,40),(792,40),(832,200))
    scalar_bytes=[i for at,size in scalar for i in range(at,at+size)]
    s.require(sorted(scalar_bytes)==list(range(1040)),'complete scalar owner cleanup without gaps')
    ranges=[(0,1920),(1920,800),(2720,800),(3520,32),(3552,32),(5248,4),(5252,4),(5256,4)]
    for base in range(3584,4208,156):ranges.extend((base+at,size) for at,size in ((32,72),(104,51),(0,32),(155,1)))
    ranges.extend((4208+at,size) for at,size in scalar)
    covered=[i for at,size in ranges for i in range(at,at+size)]
    s.require(sorted(covered)==list(range(5260)),'entire 5260-byte workspace subobject coverage')
    return dict(workspace_bytes=5260,scalar_owner_bytes=1040,workspace_wipe_ranges=[list(r) for r in ranges],
        destructor_repeats_subobject_clears=True,secret_output_descriptor_pointers_erased=False,
        complete_caller_frame_erasure_qualified=False)


def inspect(bodies,ir,session):
    n=names(bodies)
    s.require(session['functions']['wipe']==n['cpu_wipe'] and
        session['full_scratch_wipe_ranges']==[[0,800],[800,960],[960,1120],[1120,1920]],'replayed CPU workspace wipe')
    expected=shapes(n)
    for name,want in expected.items():s.require(life.code(bodies[name])==want,'complete workspace/output helper')
    leaf=[line for line in copy.LEAF_CODE]
    for i in range(3,-1,-1):leaf=[l.replace('.Ltmp'+str(i),'.Ltmp'+str(i+4)) for l in leaf]
    s.require(copy.code(bodies[n['copy_leaf']])==leaf,'actual bounded byte-copy leaf including labels')
    s.require(life.code(bodies[n['copy']])==copy.WRAPPER_CODE,'complete checked-length copy wrapper')
    target='"target-cpu"="x86-64" "target-features"="'+receive.worker.resident.session.zero.SIMD_FEATURES+'"'
    for role,size,extra,personality in (('workspace_wipe',5260,'',False),('workspace_drop',5260,'',True),
        ('scalar_wipe',1040,'noinline ',False),('output_drop',104,'',True)):
        align='align 8 ' if role=='output_drop' else ''
        want=f'define internal fastcc void @{n[role]}(ptr noalias nofree noundef nonnull {align}dereferenceable({size}) %0) unnamed_addr '+(
            '{ nofree '+extra+'norecurse nounwind uwtable '+target+' } '+
            ('personality ptr @__CxxFrameHandler3 {' if personality else '{'))
        s.require(life.reuse.abi(ir,n[role])==want,'exact cleanup helper ABI '+role)
    for role,result,args in (('copy_leaf','void','ptr noundef nonnull %0, ptr noundef nonnull %1, i64 noundef range(i64 0, 1025) %2'),
        ('copy','noundef range(i8 -1, 3) i8','ptr noalias nofree noundef nonnull %0, i64 noundef range(i64 0, -9223372036854775808) %1, ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) %2, i64 noundef range(i64 0, -9223372036854775808) %3')):
        want=f'define internal fastcc {result} @{n[role]}({args}) unnamed_addr '+'{ noinline nounwind uwtable '+target+' } {'
        s.require(life.reuse.abi(ir,n[role])==want,'exact mixed-range copy ABI '+role)
    return dict(functions=n,instruction_positions={k:len(v) for k,v in expected.items()},geometry=geometry(),
        copy_leaf_length_limit=1024,copy_wrapper_checks_equal_lengths=True,
        copy_caller_bounds_and_nonoverlap_required=True,
        output_drop_requires_live_executor_returned_pointers=True,
        output_drop_clears_four_present_nonempty_destinations=True,
        output_drop_clears_output_bits_and_identities_not_slice_descriptors=True)
