"""Normal vector-call stack bounds and early wide callback-slot provenance.

This composes actual callee frames, not merely their names. Indirect writes
through caller arguments, compact-index lifetimes and unwind remain distinct
obligations. A private stack bound is not a stack-erasure claim.
"""
import windows_enclave_sha2_callee_stack as stack
import windows_enclave_sha2_slot_origins as origins
import windows_enclave_sha2_simd_vector as vector
import windows_enclave_sha2_simd_authority as authority
import windows_enclave_sha2_control_effects as control
s=stack.s


def closure(bodies,roots,indirect):
    pending=list(roots);frames={}
    while pending:
        name=pending.pop()
        if name in frames:continue
        s.require(name in bodies and not name.startswith('?'),'normal vector callee body is present')
        frames[name]=stack.inspect_body(bodies[name],name,set(bodies),indirect)
        pending.extend(row[1] for row in frames[name]['calls']+frames[name]['tail_calls'])
    depths={name:stack.depth(name,frames) for name in sorted(roots)}
    return frames,depths


def early_callbacks(bodies,assembly,callback):
    name=authority.role(bodies,'executor');lines=s.lines(bodies[name])
    tables=origins.source.paths.jump_tables(assembly,lines)
    initial=origins.definitions(lines,name,tables)
    indexed=origins.indexed_effects(lines,initial,tables)
    states=origins.definitions(lines,name,tables,(920,960,984),indexed)
    seed=origins.unique(lines,'leaq 512(%rdi), %rax')+1
    s.require(lines[seed]=='movq %rax, 984(%rbp)','saved state pointer initialization')
    end=origins.unique(lines,'.B182:')
    data=origins.unique(lines,'movq %rcx, 960(%rbp)')
    target=data+1
    # The control object and its readonly table were bound in the parent.
    # Here every reaching definition of the saved target/data is checked;
    # finding an expected instruction somewhere in the body is insufficient.
    s.require(lines[target-6:target+1]==[
        'movq 1176(%rbp), %rax','movq (%rax), %rcx','movq 8(%rax), %rax',
        'movq 32(%rax), %rax','.Ltmp38:','movq %rcx, 960(%rbp)',
        'movq %rax, 920(%rbp)'],'original control callback capture')
    base=target-6;table=target-4;load=target-3
    s.require(states[target]['rax']=={load} and states[load]['rax']=={table}
              and states[table]['rax']=={base} and states[data]['rcx']=={base+1}
              and states[base+1]['rax']=={base},'unclobbered callback capture definitions')
    origins.require_origin(lines,states,table,'rax','control',0,{})
    sites=[at for at in range(seed+1,end) if lines[at]=='callq *920(%rbp)']
    s.require(len(sites)==2,'both early callback invocations')
    for at in sites:
        s.require(lines[at-2:at]==['movq 960(%rbp), %rcx','vzeroupper'],
                  'early callback data reload')
        s.require(states[at][920]=={target} and states[at-2][960]=={data},
                  'every early callback target/data path retains the original capture')
    reads=[at for at in range(seed+1,end) if '984(%rbp)' in lines[at]]
    s.require([lines[at] for at in reads]==['addq 984(%rbp), %rcx',
              'addq 984(%rbp), %r8','addq 984(%rbp), %rcx'],
              'complete early saved-state-pointer use population')
    for at in reads:origins.require_slot(lines,states,at,984,512,{984:512})
    copy=s.one(bodies,r'secret_memory18copy_secret_region$');session=authority.role(bodies,'session')
    expected=[callback,copy,copy,callback,session,copy];calls=[]
    for at in range(seed+1,end):
        if not lines[at].startswith('callq '):continue
        raw=lines[at][6:];resolved=callback if raw=='*920(%rbp)' else raw
        calls.append(dict(line=at,target=resolved,operand=raw))
    s.require([v['target'] for v in calls]==expected,'complete earlier vector-phase call population')
    return dict(begin=seed+1,end=end,calls=calls,callback_sites=sites,
        callback_target_slot=920,callback_data_slot=960,state_pointer_uses=reads,
        direct_callback_definitions_checked=True,indirect_slot_preservation_required=True)


def inspect(bodies,assembly,lane,control_review):
    s.require(lane in ('simd256','simd512'),'known vector stack lane')
    vector.inspect(bodies,lane);authority.session(bodies,lane)
    leaves=control_review['leaf_targets'];session=authority.role(bodies,'session')
    control.leaf(bodies,leaves['callback'],['xorl %eax, %eax','retq'])
    control.leaf(bodies,leaves['compiled'],['movl %ecx, %eax','xorb $1, %al','retq'])
    roots={session,s.one(bodies,r'secret_memory18copy_secret_region$'),leaves['callback']}
    frames,depths=closure(bodies,roots,{(session,'*8(%r14)'):leaves['compiled']})
    s.require(len(frames)==12,'complete vector/copy/cancellation normal closure')
    # CALL itself stores a return address below the parent's current RSP.
    sp=0 if lane=='simd256' else -128
    low=sp-8+min(depths.values());home=[sp,sp+32]
    slots=(88,112,184) if lane=='simd256' else (920,960,984,1040,1048,1168,1176)
    for slot in slots:
        s.require(not origins.source.cells.overlaps((low,sp),(slot,slot+8))
                  and not origins.source.cells.overlaps(home,(slot,slot+8)),
                  'vector private frames and outgoing home exclude saved slots')
    result=dict(functions=frames,root_relative_low=depths,normal_callee_count=len(frames),
        caller_frame_relative_stack_span=[low,sp],outgoing_home_span=home,
        protected_slots=list(slots),normal_stack_effects_disjoint=True,
        argument_memory_effects_and_physical_separation_required=True,
        indirect_revalidator_identity_and_lifetime_required=True,
        arbitrary_unwind_qualified=False,individual_stack_erasure_qualified=False,
        whole_frame_qualified=False)
    if lane=='simd512':result['early_calls']=early_callbacks(bodies,assembly,leaves['callback'])
    return result
