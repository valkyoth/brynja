"""Four fixed scalar constructors and active-owner transfers in the saved image.

Inactive enum storage is deliberately not treated as initialized secret state.
Runtime copy/ABI preservation and final private-window retirement remain open.
"""
import windows_enclave_sha3_batch_empty as empty

life,s,L=empty.life,empty.s,empty.L
LABELS={1:27,2:37,3:35,4:36}


def initialize(tag):
    lines=[f'.B{LABELS[tag]}:']
    for begin,end,descending in ((832,1024,True),(304,464,False)):
        offsets=range(begin,end,16)
        if descending:offsets=reversed(list(offsets))
        lines += [f'movaps %xmm0, {at}(%rsp)' for at in offsets]+[f'movq $0, {end}(%rsp)']
    lines+=L('movq $0, 78(%rsp)|movq $0, 72(%rsp)|movaps %xmm0, 160(%rsp)|movaps %xmm0, 144(%rsp)|movq $0, 176(%rsp)')
    for begin,end in ((1040,1232),(656,816)):
        lines += [f'movaps %xmm0, {at}(%rsp)' for at in reversed(range(begin,end,16))]+[f'movq $0, {end}(%rsp)']
    lines+=L('movq $0, 110(%rsp)|movq $0, 104(%rsp)|movq $0, 94(%rsp)|movq $0, 88(%rsp)')
    lines += [f'movaps %xmm0, {at}(%rsp)' for at in reversed(range(480,640,16))]
    lines+=L(f'movq $0, 640(%rsp)|movaps %xmm0, 208(%rsp)|movaps %xmm0, 192(%rsp)|movq $0, 224(%rsp)|movb ${tag}, 35(%rsp)')
    return lines+([] if tag==2 else ['jmp .B38'])


METADATA=L('''.B38:|movl $0, 56(%rsp)|xorl %ebx, %ebx|xorl %r14d, %r14d
    xorl %r12d, %r12d|xorl %r15d, %r15d|movl $0, 40(%rsp)|movl $0, 36(%rsp)
    xorl %edi, %edi|movl $0, 48(%rsp)|movl $0, 64(%rsp)|xorl %ebp, %ebp''')


def staging():
    lines=L('''.B39:|movq 104(%rsp), %rax|movq 110(%rsp), %rcx
        movq %rcx, 294(%rsp)|movq %rax, 288(%rsp)
        movq 88(%rsp), %rax|movq 94(%rsp), %rcx|movq %rax, 248(%rsp)|movq %rcx, 254(%rsp)
        movq 72(%rsp), %rax|movq 78(%rsp), %rcx|movq %rax, 232(%rsp)|movq %rcx, 238(%rsp)''')
    for dest,source,width in ((5861,1040,200),(3240,656,168),(3072,480,168),(2904,304,168)):
        lines+=L(f'leaq {dest}(%rsp), %rcx|leaq {source}(%rsp), %rdx|movl ${width}, %r8d|callq memcpy')
    for source,dest in ((192,1296),(144,1248)):
        lines+=L(f'''movaps {source}(%rsp), %xmm0|movaps {source+16}(%rsp), %xmm1
            movaps %xmm0, {dest}(%rsp)|movaps %xmm1, {dest+16}(%rsp)
            movq {source+32}(%rsp), %rax|movq %rax, {dest+32}(%rsp)''')
    return lines+L('leaq 5661(%rsp), %rcx|leaq 832(%rsp), %rdx|movl $200, %r8d|callq memcpy|jmp .B47')


def check_shapes(bodies,assembly):
    name,_=empty.check_caller(bodies,assembly)
    lines=life.code(bodies[name]);parts={str(tag):initialize(tag) for tag in LABELS}
    parts.update(metadata=METADATA,staging=staging());covered=set()
    for key,part in parts.items():
        at=lines.index(part[0]);end=next((i for i in range(at+1,len(lines)) if lines[i].endswith(':')),len(lines))
        s.require(lines[at:end]==part,'complete scalar fixed constructor '+key)
        covered.update(range(at,end))
    # All four entries come directly from the zero-XMM descriptor dispatch.
    pred=empty.predecessors(lines);dispatch=lines.index('jmpq *%rax')
    for label in LABELS.values():
        s.require(pred[lines.index(f'.B{label}:')]=={dispatch},'fixed initialization entered only from zero-XMM dispatch')
    s.require(lines[lines.index('.B37:')+len(initialize(2))]=='.B38:', 'SHA3-256 falls through to common metadata')
    s.require(lines[lines.index('.B38:')+len(METADATA)]=='.B39:', 'metadata falls through to staging')
    return name,sorted(covered)


def schedule(tag):
    """Independent byte-transfer description of the checked straight-line path."""
    s.require(type(tag) is int and tag in LABELS,'one fixed SHA-3 identity')
    steps=[('zero','frame',at,size) for at,size in (
        (832,200),(304,168),(72,14),(144,40),(1040,200),(656,168),(104,14),(88,14),
        (480,168),(192,40),(56,4),(40,4),(36,4),(48,4),(64,4))]
    steps += [('tag',tag)]
    for source,dest in ((104,288),(110,294),(88,248),(94,254),(72,232),(78,238)):
        steps.append(('copy','frame',source,'frame',dest,8))
    for source,dest,size in ((1040,5861,200),(656,3240,168),(480,3072,168),
                             (304,2904,168),(192,1296,40),(144,1248,40),(832,5661,200)):
        steps.append(('copy','frame',source,'frame',dest,size))
    # Destruction acts on the retained owner, not the disjoint temporary frame.
    steps.append(('destroy',))
    for source,dest,size in ((35,16,1),(64,18,1),(288,19,8),(294,25,8),
        (48,33,1),(248,35,8),(254,41,8),(36,49,1),(40,50,1),(232,51,8),(238,57,8),
        (5861,65,200),(3240,265,168),(3072,433,168),(2904,601,168),
        (1296,769,40),(1248,809,40),(5661,849,200),(56,1056,1)):
        steps.append(('copy','frame',source,'owner',dest,size))
    steps += [('zero','owner',at,size) for at,size in ((17,1),(34,1),(1049,4),(1053,1),(1054,1),(1055,1))]
    return steps


def replay(tag,steps=None):
    """Active payload only; protocol publication and inactive stores are separate."""
    s.require(type(tag) is int and tag in LABELS,'fixed constructor model identity')
    memory={'frame':[None]*7168,'owner':[('old',at) for at in range(2400)]}
    old=memory['owner'].copy();destroyed=False;written=set();same_source_overlap=0
    def region(name,at,size):
        s.require(name in memory and type(at) is int and type(size) is int and size>0 and
            (32 if name=='frame' else 16)<=at and at+size<=(7168 if name=='frame' else 1057),
            'bounded active owner/local region, excluding outgoing home area and saved XMM6')
        return memory[name]
    for step in schedule(tag) if steps is None else steps:
        if step[0]=='destroy':
            s.require(not destroyed and not written,'old state destroyed exactly once before placement')
            destroyed=True;memory['owner'][16:1152]=[('destroyed',at) for at in range(16,1152)];continue
        if step[0]=='tag':memory['frame'][35]=step[1];continue
        if step[0]=='zero':
            _,dst,end,size=step;values=[0]*size
        else:
            s.require(step[0]=='copy','known fixed transfer')
            _,src,at,dst,end,size=step;source=region(src,at,size)
            s.require(src!=dst or at+size<=end or end+size<=at,'nonoverlapping copy regions')
            values=source[at:at+size];s.require(None not in values,'active bytes read only after initialization')
        target=region(dst,end,size)
        if dst=='owner':
            s.require(destroyed,'retained state destruction precedes installation')
            for i,value in enumerate(values):
                if end+i in written:
                    s.require(target[end+i]==value,'overlapping active writes agree');same_source_overlap+=1
                written.add(end+i)
        target[end:end+size]=values
    s.require(destroyed and written==set(range(16,1057)),'every tag and active payload byte installed after destruction')
    s.require(memory['owner'][16:1057]==[tag]+[0]*1040,'correct fixed tag and completely zero initial owner')
    s.require(memory['owner'][:16]==old[:16] and memory['owner'][1152:]==old[1152:],
              'no mutation outside retained state in constructor model')
    return dict(tag=tag,active_owner_bytes=1040,tag_and_payload_span=[16,1057],
        overlapping_active_writes=same_source_overlap,all_active_sources_initialized=True,
        source_destination_nonoverlap=True,old_state_destroyed_before_install=True,
        inactive_storage_span=[1057,1152],inactive_storage_initialization_qualified=False,
        stack_copy_erasure_qualified=False,runtime_and_separate_stack_page_allocation_required=True)


def inspect(bodies,assembly,construction,storage):
    name,covered=check_shapes(bodies,assembly)
    s.require(construction['function']==name and construction['successful_placement_destroys_previous_typed_state_first']
        and construction['successful_slot_and_phase_commit_after_state_copy'], 'replayed final placement and publication')
    s.require(storage['state_destructor']['function']==life.DROP['scalar'] and
        storage['state_destructor']['typed_payload_cleanup_composed'], 'reviewed state destruction before installation')
    return dict(function=name,reviewed_instruction_positions=covered,
        identities={str(tag):replay(tag) for tag in LABELS},
        preserved_registers=['rbx','rbp','rdi','rsi','r12','r13','r14','r15'],
        active_fixed_constructor_initialization_qualified=True,
        all_constructor_paths_qualified=False,private_frame_erasure_qualified=False,
        shared_runtime_completion_package=8)
