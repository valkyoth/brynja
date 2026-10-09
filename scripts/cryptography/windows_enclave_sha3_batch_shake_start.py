"""Saved scalar SHAKE result-to-owner joins, including the extra wrapper byte."""
import windows_enclave_sha3_batch_fixed_start as fixed

empty,life,s,L=fixed.empty,fixed.life,fixed.s,fixed.L


def decode(bits):
    lines=empty.caller_slice(bits)+L('''movzbl 1680(%rsp), %ebp|cmpb $-1, %bpl|je .B58
        movzbl 1681(%rsp), %eax|movl %eax, 64(%rsp)
        movq 1682(%rsp), %rax|movq %rax, 104(%rsp)
        movq 1688(%rsp), %rax|movq %rax, 110(%rsp)
        movzbl 1696(%rsp), %eax|movl %eax, 48(%rsp)|movzbl 1697(%rsp), %edi
        movq 1698(%rsp), %rax|movq %rax, 88(%rsp)
        movq 1704(%rsp), %rax|movq %rax, 94(%rsp)
        movzbl 1712(%rsp), %eax|movl %eax, 36(%rsp)
        movzbl 1713(%rsp), %eax|movl %eax, 40(%rsp)
        movq 1714(%rsp), %rax|movq %rax, 72(%rsp)
        movq 1720(%rsp), %rax|movq %rax, 78(%rsp)''')
    for source,dest,width in ((1728,1040,200),(1928,656,168),(2096,480,168),(2264,304,168)):
        lines+=L(f'leaq {source}(%rsp), %rdx|leaq {dest}(%rsp), %rcx|movl ${width}, %r8d|callq memcpy')
    lines+=L('''movups 2432(%rsp), %xmm0|movups 2448(%rsp), %xmm1
        movaps %xmm0, 192(%rsp)|movaps %xmm1, 208(%rsp)|movq 2464(%rsp), %rax|movq %rax, 224(%rsp)
        movups 2472(%rsp), %xmm0|movaps %xmm0, 144(%rsp)
        movups 2488(%rsp), %xmm0|movaps %xmm0, 160(%rsp)|movq 2504(%rsp), %rax|movq %rax, 176(%rsp)
        leaq 2512(%rsp), %rdx|leaq 832(%rsp), %rcx|movl $200, %r8d|callq memcpy
        movl 2712(%rsp), %r15d|movzbl 2716(%rsp), %r12d|movzbl 2717(%rsp), %r14d
        movzbl 2718(%rsp), %ebx|movzbl 2719(%rsp), %eax|movl %eax, 56(%rsp)
        movzbl 2720(%rsp), %eax|movb %al, 120(%rsp)''')
    return lines+L(f'movb ${5 if bits==128 else 6}, 35(%rsp)|jmp .B39')


FAILURE=L('.B58:|movb $6, %al|movq %rdi, %rbp|jmp .B87')


def check_shapes(bodies,assembly):
    name,_=empty.check_caller(bodies,assembly);lines=life.code(bodies[name])
    parts=[decode(128),decode(256),fixed.staging(),FAILURE];covered=set()
    for part in parts:
        at=lines.index(part[0]);end=next((i for i in range(at+1,len(lines)) if lines[i].endswith(':')),len(lines))
        s.require(lines[at:end]==part,'complete SHAKE decode, staging and error transfer')
        covered.update(range(at,end))
    return name,sorted(covered)


def schedule(tag):
    s.require(type(tag) is int and tag in (5,6),'SHAKE constructor tag')
    steps=[('result',)]
    for source,dest in ((1681,64),(1696,48),(1712,36),(1713,40),(2719,56)):
        steps.append(('byte32',source,dest))
    for source,dest,size in ((1682,104,8),(1688,110,8),(1698,88,8),(1704,94,8),
        (1714,72,8),(1720,78,8),(1728,1040,200),(1928,656,168),(2096,480,168),
        (2264,304,168),(2432,192,40),(2472,144,40),(2512,832,200),(2720,120,1)):
        steps.append(('copy','frame',source,'frame',dest,size))
    # Nonvolatile registers: bpl, dil, r15d, r12b, r14b, bl.
    for source,dest,size in ((1680,0,1),(1697,1,1),(2712,2,4),(2716,6,1),(2717,7,1),(2718,8,1)):
        steps.append(('copy','frame',source,'saved',dest,size))
    steps.append(('tag',tag))
    for source,dest in ((104,288),(110,294),(88,248),(94,254),(72,232),(78,238)):
        steps.append(('copy','frame',source,'frame',dest,8))
    for source,dest,size in ((1040,5861,200),(656,3240,168),(480,3072,168),(304,2904,168),
                             (192,1296,40),(144,1248,40),(832,5661,200)):
        steps.append(('copy','frame',source,'frame',dest,size))
    steps.append(('destroy',))
    for source,dest,size in ((35,16,1),(64,18,1),(288,19,8),(294,25,8),(48,33,1),
        (248,35,8),(254,41,8),(36,49,1),(40,50,1),(232,51,8),(238,57,8),
        (5861,65,200),(3240,265,168),(3072,433,168),(2904,601,168),
        (1296,769,40),(1248,809,40),(5661,849,200),(56,1056,1),(120,1057,1)):
        steps.append(('copy','frame',source,'owner',dest,size))
    for source,dest,size in ((0,17,1),(1,34,1),(2,1049,4),(6,1053,1),(7,1054,1),(8,1055,1)):
        steps.append(('copy','saved',source,'owner',dest,size))
    return steps


def replay(tag,steps=None):
    """Byte origins, not zero equality: detect swapped fields even in a zero owner."""
    s.require(type(tag) is int and tag in (5,6),'SHAKE model identity')
    original=[('result',i) for i in range(1041)]
    memory={'frame':[None]*7168,'saved':[None]*9,'owner':[('old',i) for i in range(2400)]}
    before=memory['owner'].copy();produced=False;destroyed=False;written=set();overlap=0
    def region(name,at,size):
        s.require(name in memory and type(at) is int and type(size) is int and size>0 and
            (32 if name=='frame' else 16 if name=='owner' else 0)<=at and
            at+size<=(1058 if name=='owner' else len(memory[name])),'bounded SHAKE source/destination region')
        return memory[name]
    for step in schedule(tag) if steps is None else steps:
        if step[0]=='result':
            s.require(not produced,'single fully initialized helper result');produced=True
            memory['frame'][1680:2721]=original.copy();continue
        if step[0]=='destroy':
            s.require(not destroyed and not written,'old state destruction before any placement')
            destroyed=True;memory['owner'][16:1152]=[('destroyed',i) for i in range(16,1152)];continue
        if step[0]=='tag':memory['frame'][35]=step[1];continue
        if step[0]=='byte32':
            _,source,end=step;dst='frame';size=4;value=region('frame',source,1)[source]
            s.require(value is not None,'initialized zero-extension operand');values=[value,0,0,0]
        else:
            s.require(step[0]=='copy','known SHAKE byte transfer')
            _,src,source,dst,end,size=step;values=region(src,source,size)[source:source+size]
            s.require(None not in values,'initialized SHAKE transfer sources')
            s.require(src!=dst or source+size<=end or end+size<=source,'nonoverlapping memcpy transfers')
        target=region(dst,end,size)
        if dst=='owner':
            s.require(destroyed,'typed destruction before retained installation')
            for i,value in enumerate(values):
                if end+i in written:
                    s.require(target[end+i]==value,'overlapping stores retain identical source bytes');overlap+=1
                written.add(end+i)
        target[end:end+size]=values
    s.require(produced and destroyed and written==set(range(16,1058)), 'complete tag and SHAKE wrapper placement')
    s.require(memory['owner'][16:1058]==[tag]+original, 'every SHAKE wrapper byte preserves its exact result origin')
    s.require(memory['frame'][1680:2721]==original,'helper result survives every transfer, without false erasure claim')
    s.require(memory['owner'][:16]==before[:16] and memory['owner'][1152:]==before[1152:],
              'active constructor model does not mutate outside retained state')
    return dict(tag=tag,wrapper_bytes=1041,underlying_owner_bytes=1040,wrapper_span=[17,1058],
        helper_result_span=[1680,2721],same_source_overlap_bytes=overlap,
        exact_byte_origin_preserved=True,copy_source_destination_nonoverlap=True,
        helper_result_erased=False,private_frame_erasure_qualified=False,inactive_storage_span=[1058,1152])


def inspect(bodies,assembly,empty_construction,construction,storage):
    name,covered=check_shapes(bodies,assembly)
    s.require(empty_construction['caller']==name and empty_construction['empty_constructor_paths_qualified'],
              'actual empty-descriptor call paths replayed')
    s.require(empty_construction['geometry']['result_entirely_initialized'], 'complete helper result initialization')
    for bits in (128,256):
        helper=empty_construction['helpers'][str(bits)]
        s.require(helper['function']==empty.NAMES[bits] and helper['result_success_tag']==0 and
            helper['result_bytes']==1041 and helper['owner_bytes']==1040,'full initialized empty helper result and success mode')
    s.require(construction['function']==name and construction['successful_placement_destroys_previous_typed_state_first']
        and construction['successful_slot_and_phase_commit_after_state_copy'] and construction['rejection_clears_output_bytes']==1024,
        'actual placement, publication and rejection cleanup replayed')
    s.require(storage['state_destructor']['function']==life.DROP['scalar'] and
        storage['state_destructor']['typed_payload_cleanup_composed'],'reviewed retained-state destruction')
    return dict(function=name,reviewed_instruction_positions=covered,
        identities={str(tag):replay(tag) for tag in (5,6)},
        mode_byte_separate_from_underlying_owner=True,helper_error_restores_plan_pointer=True,
        helper_error_status=6,constructor_success_branch_from_proven_zero_mode=True,
        scalar_shake_constructor_joins_qualified=True,all_constructor_paths_qualified=False,
        private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
