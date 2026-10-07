"""Narrow admission/authority/predicate interfaces joined to original owners.

The stack probe remains a shared runtime obligation, not an empty-effect leaf.
These normal helper contracts do not establish enclosing private-frame erasure.
"""
import windows_enclave_sha2_parent_authority as shared
import windows_enclave_sha2_narrow_lifetimes as life
p,n,o,s=shared.p,life.n,life.o,life.s


def prepare(bodies,assembly):
    name=s.one(bodies,r'Resident6digest$');lines=s.lines(bodies[name])
    states,edges,_=n.prepare(lines,assembly,name)
    return name,lines,states,edges


def predicate(bodies,assembly):
    name,lines,states,edges=prepare(bodies,assembly)
    construction=life.input_construction(lines,states,edges)
    callee=s.one(bodies,r'mask_is_zero$');at=o.unique(lines,'callq '+callee)
    p.storage.exact(bodies[callee],[
        'movzbl %dl, %edx','movzbl (%rcx), %r10d','andl %edx, %r10d',
        'sete %al','movzbl %al, %eax','xorl %r10d, %r10d','retq'])
    head=construction['loop_head'];start=head+3
    expected=['movq -9(%rdi,%r15), %rsi','cmpq $1024, %rsi','ja .B27',
        'movq -17(%rdi,%r15), %r13','movzbl -1(%rdi,%r15), %r14d',
        'testq %rsi, %rsi','je .B11','leal -1(%r14), %eax','cmpb $7, %al',
        'ja .B13','cmpb $7, %r14b','ja .B3','leaq -1(%rsi), %rax',
        'movb $-1, %dl','movl %r14d, %ecx','shrb %cl, %dl',
        'addq %r13, %rax','movq %rax, %rcx','callq '+callee]
    s.require(lines[start:at+1]==expected,'narrow predicate uses original bounded final-byte address and mask')
    n.straight(edges,head,at)
    step=o.unique(lines,'addq $40, %r12')
    cut=shared.output.admission.p.filtered(edges,edges=[(step,head)])
    for branch in (head+2,start+2,start+6,start+9,start+11):
        shared.output.admission.p.guarded_path(cut,head,at,(branch,branch+1))
    n.trace(lines,states,start,'rdi',lambda site,loc:site==-1 and loc=='r9')
    seed=o.unique(lines,'movl $17, %r15d');advance=o.unique(lines,'addq $24, %r15')
    s.require(states[start]['r15']=={seed,advance} and states[at]['rcx']=={at-1} and
              states[at]['rdx']=={at-3},'same bounded header index, checked pointer and mask at entry')
    return dict(line=at,target=callee,role='bounded_tail_predicate',source_offsets=construction['source_offsets'],
        actual_read_bytes=1,length_range=[1,1024],last_bits_range=[1,7],
        footprints=[['reads','input',0,1024]])


def callsites(bodies,assembly,helpers):
    name,lines,states,edges=prepare(bodies,assembly)
    original=life.authority(lines,states,edges,bodies)
    capture=original['owner_initializer']-1;load=original['authority_field_load']
    def owner(at,reg):
        return n.trace(lines,states,at,reg,lambda site,loc:site==capture and loc=='rax',(152,))
    def authority(at,reg):
        return n.trace(lines,states,at,reg,lambda site,loc:site==load and loc=='r15',(88,))
    at=o.unique(lines,'callq '+helpers['operation'])
    s.require(states[at]['rdx']==states[at]['r8']=={-1} and
              states[at]['rcx']=={at-2} and states[at]['r9']=={at-1} and
              lines[at-2:at]==['leaq 6688(%rbx), %rcx','xorl %r9d, %r9d'],
              'operation takes original owner and sequence, phase zero and private result')
    n.straight(edges,at-2,at)
    calls=[dict(line=at,target=helpers['operation'],role='operation',footprints=[
        ['reads','owner',8,16],['reads','owner',272,281],['reads','authority',8,18],
        ['writes','owner',0,1],['writes','owner',16,281],['writes','authority',16,17],
        ['writes','frame',6688,6697]])]
    callbacks=[i for i,line in enumerate(lines) if line=='callq *8(%r15)']
    s.require(len(callbacks)==3,'all three narrow direct compiled callbacks')
    for at in callbacks:
        roots=authority(at,'r15');definitions=states[at]['rcx']
        s.require(len(definitions)==1,'one actual callback backend argument')
        field=next(iter(definitions));s.require(lines[field]=='movzbl 17(%r15), %ecx','original authority backend byte')
        authority(field,'r15');n.straight(edges,field,at)
        calls.append(dict(line=at,target='*8(%r15)',resolved=helpers['compiled'],role='compiled',
                          authority_loads=roots,backend_load=field,footprints=[]))
    checks=[i for i,line in enumerate(lines) if line=='callq '+helpers['check']]
    s.require(len(checks)==2,'both narrow pre/post-output checks')
    for at in checks:
        definitions=states[at]['rcx'];s.require(len(definitions)==1,'one check authority definition')
        field=next(iter(definitions));s.require(lines[field]=='movq 8(%rax), %rcx','check original owner authority')
        owner(field,'rax');n.straight(edges,field,at)
        calls.append(dict(line=at,target=helpers['check'],role='check',
                          footprints=[['reads','authority',8,18],['writes','authority',16,17]]))
    start=o.unique(lines,'leaq 16(%rsi), %rcx');at=start+2
    s.require(lines[start:at+1]==['leaq 16(%rsi), %rcx','movl $256, %edx','callq '+s.ZERO],
              'owner rejection clears exactly the original 256-byte output')
    owner(start,'rsi');n.straight(edges,start,at)
    calls.append(dict(line=at,target=s.ZERO,role='owner_clear',footprints=[['writes','owner',16,272]]))
    s.require(len(calls)==7,'seven distinct narrow authority/owner calls')
    return calls


PREREQUISITES=(
    ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
    ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
    ('simd_narrow_pointer_lifetimes','normal_cfg_pointer_definition_lifetimes_checked'),
    ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
    ('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked'),
    ('simd_descriptor_normal_effects','selected_normal_helpers_conditionally_preserve_descriptors'))


def inspect(bodies,assembly,prior):
    s.require(all(prior[k][v] is True for k,v in PREREQUISITES),'fresh narrow lifetime, metadata and helper reviews')
    compiled=prior['simd_control_call_effects']['leaf_targets']['compiled']
    helpers=shared.contracts(bodies,compiled,'simd256')
    calls=callsites(bodies,assembly,helpers)+[predicate(bodies,assembly)]
    name,lines,_,_=prepare(bodies,assembly);p.bind_calls(lines,calls)
    normal=prior['simd_descriptor_normal_effects']
    s.require(normal['function']==name,'same narrow caller effect inventory')
    protected=normal['protected_descriptors']+[dict(root='resident-frame',span=v) for v in
                                               ([88,96],[152,160],[544,864])]
    layout={'frame':dict(root='resident-frame',offset=0,bounds=[0,11992]),
        'owner':dict(root='resident-page',offset=24,bounds=[0,288]),
        'authority':dict(root='resident-page',offset=0,bounds=[0,18]),
        'input':dict(root='worker-input',offset=0,bounds=[0,1024])}
    mapped=p.exclude([e for c in calls for e in p.footprints(c)],protected,layout)
    indirect={(helpers[k],'*8(%rax)'):compiled for k in ('operation','check')}
    frames={};todo=[v.get('resolved',v['target']) for v in calls]
    while todo:
        target=todo.pop()
        if target in frames:continue
        proof=p.stack.inspect_body(bodies[target],target,set(bodies),indirect)
        frames[target]=proof;todo.extend(v[1] for v in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==5,'operation, check, callback, zeroizer and predicate normal closure')
    span=[-8+min(p.stack.depth(v.get('resolved',v['target']),frames) for v in calls),0]
    p.stack_exclude(span,protected);p.stack_exclude([0,32],protected)
    probe=o.unique(lines,'callq __chkstk')
    calls.append(dict(line=probe,target='__chkstk',role='shared_stack_probe',argument_bytes=11992,
                      shared_runtime_register_and_stack_contract_required=True,stack_effects_qualified=False))
    p.bind_calls(lines,calls)
    pending={(v['line'],v['target']) for v in normal['unassigned_calls']}
    s.require({(v['line'],v['target']) for v in calls}<=pending,'nine previously unassigned narrow sites')
    remaining=p.inventory(lines,normal['assigned']+normal['terminal_calls']+calls)
    return dict(function=name,helpers=helpers,assigned=calls,mapped_effects=mapped,
        normal_stack_span=span,normal_callee_count=len(frames),protected_live_objects=protected,
        remaining_narrow_calls=remaining,assigned_narrow_returning_interfaces=len(normal['assigned'])+len(calls),
        original_admission_authority_and_tail_arguments_joined=True,
        shared_runtime_calls=[dict(line=probe,target='__chkstk')],shared_completion_package=8,
        whole_frame_qualified=False,shared_prerequisites=normal['shared_prerequisites'])
