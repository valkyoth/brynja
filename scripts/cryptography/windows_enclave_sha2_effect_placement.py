"""Place conditional finish effects in the emitted caller/child frame geometry.

This joins the independently checked effects; it does not infer original live
pointer values from their symbolic names. External allocation separation,
pointer-slot lifetimes and private callee frames still require composition.
"""
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_frame_cell as cells
import windows_enclave_sha2_simd_authority as authority


def child_frame(body):
    lines=s.lines(body);end=lines.index('.seh_endprologue')
    prologue=[v for v in lines[:end] if not v.startswith('.') and not v.endswith(':')]
    registers=('rbp','r15','r14','r13','r12','rsi','rdi','rbx')
    s.require(prologue==['pushq %'+r for r in registers]+['subq $1192, %rsp','leaq 128(%rsp), %rbp'],
              'exact child stack allocation, save order and frame base')
    # CALL contributes the return slot; eight pushes and allocation then move
    # RSP downward. RBP is 128 above that. This also recovers args 5/6 at 32/40.
    origin=-8-8*len(registers)-1192+128
    s.require(origin+1168==32 and origin+1176==40,'child incoming argument slots match caller ABI')
    return origin


def placements(bodies,lane):
    narrow=lane=='simd256';resident=bodies[authority.role(bodies,'resident')]
    allocation=11992 if narrow else 12984
    s.sequences(resident,[f'movl ${allocation}, %eax|callq __chkstk|subq %rax, %rsp|'
        f'.seh_stackalloc {allocation}|leaq 128(%rsp), %rbp|.seh_setframe %rbp, 128|'
        '.seh_endprologue|andq $-32, %rsp|movq %rsp, %rbx'])
    # Rounding RSP downward grows the allocation; its minimum end relative to
    # aligned RBX is allocation, for all possible pre-alignment residues.
    rows={'frame':dict(root='resident-frame',offset=0,bounds=[0,allocation])} if narrow else {
        'frame':dict(root='resident-frame',offset=child_frame(bodies[authority.role(bodies,'executor')]),bounds=[-128,1064]),
        'workspace':dict(root='resident-frame',offset=7200,bounds=[0,5760]),
        'control':dict(root='resident-frame',offset=144,bounds=[0,32]),
        'executor':dict(root='resident-frame',offset=120,bounds=[0,24])}
    if not narrow:
        # Parent owns these objects throughout the synchronous child call.
        # The existing digest/authority review binds the intervening transfers;
        # this check explicitly joins caller offsets to callee ABI slots.
        s.sequences(resident,['leaq 7200(%rbx), %rdi',
            '.Ltmp70:|leaq 144(%rbx), %rax|movq %rax, 40(%rsp)|movq %rdi, 32(%rsp)|'
            'leaq 4640(%rbx), %rcx|leaq 120(%rbx), %rdx|leaq 192(%rbx), %r8|'
            'leaq 352(%rbx), %r9|vzeroupper|callq '+authority.role(bodies,'executor')])
        occupied=[]
        for name,row in rows.items():
            lo,hi=(row['offset']+n for n in row['bounds'])
            s.require(lo<hi and (hi<=-72 if name=='frame' else 0<=lo<hi<=allocation),
                      'parent and child object allocations stay in their frames')
            s.require(all(not cells.overlaps((lo,hi),span) for span in occupied),
                      'distinct child/control/executor/workspace ranges')
            occupied.append((lo,hi))
    # These are separately owned objects, not proved nonaliasing by naming them.
    rows.update(authority=dict(root='resident-page',offset=0,bounds=[0,18]),
                input=dict(root='worker-input',offset=0,bounds=[0,1024]))
    return rows


def place(region,layout):
    s.require(region['object'] in layout,'every effect object has an explicit placement')
    row=layout[region['object']];span=region['span']
    s.require(len(span)==2 and all(type(v) is int for v in span) and
              row['bounds'][0]<=span[0]<=span[1]<=row['bounds'][1],
              'effect stays inside its assigned object')
    return dict(root=row['root'],span=[n+row['offset'] for n in span])


def collect(frame,primitive,transfer,control):
    calls=primitive['calls']+transfer['calls']+control['calls']
    terminal=control['failstop_paths'];inventory=frame['calls_pending_indirect_effect_composition']
    assigned=sorted([dict(line=v['line'],target=v['target']) for v in calls+terminal],key=lambda v:v['line'])
    s.require(assigned==inventory,'complete single assignment of all intervening calls')
    s.require(not control['unassigned_call_effects'],'no missing returning call contract')
    effects=[]
    for call in calls:
        if 'footprints' in call:
            effects.extend((direction,dict(object=obj,span=[lo,hi]))
                           for direction,obj,lo,hi in call['footprints'])
        else:
            for direction in ('reads','writes'):effects.extend((direction,region) for region in call[direction])
    stores=frame['conditional_indirect_store_effects']['stores']
    s.require(len(stores)==len(frame['non_frame_stores_pending']), 'all indirect stores composed')
    effects.extend(('writes',dict(object=row['object'],span=row['span'])) for row in stores)
    return calls,terminal,effects


def inspect(bodies,lane,frame,primitive,transfer,control):
    layout=placements(bodies,lane);cell=place(dict(object='frame',span=frame['cell']),layout)
    calls,terminal,effects=collect(frame,primitive,transfer,control)
    mapped=[]
    for direction,region in effects:
        target=place(region,layout)
        s.require(direction in ('reads','writes'),'assigned memory effect direction')
        if direction=='writes' and target['root']==cell['root']:
            s.require(not cells.overlaps(target['span'],cell['span']),
                      'composed caller/child writes cannot overlap the saved pointer')
        mapped.append((direction,target['root'],*target['span']))
    home=[0,32] if lane=='simd256' else [-128,-96]
    placed_home=place(dict(object='frame',span=home),layout)
    s.require(not cells.overlaps(placed_home['span'],cell['span']),'outgoing ABI home space excludes saved pointer')
    return dict(placements=layout,saved_cell=cell,outgoing_home_space=placed_home,
        conditional_returning_calls=len(calls),conditional_indirect_stores=len(frame['non_frame_stores_pending']),
        distinct_effects=[list(v) for v in sorted(set(mapped))],terminal_paths=len(terminal),
        caller_and_child_frame_relative_nonoverlap_checked=True,
        external_allocations_disjoint_from_stack_required=True,
        original_pointer_slot_lifetimes_and_terminal_preconditions_pending=True,
        private_callee_frames_and_whole_window_cleanup_pending=True,whole_frame_qualified=False)
