"""Last wide-parent interfaces: probe, bounded tail read and child handoff.

Assignment is not whole-frame qualification: __chkstk remains a shared runtime
contract, and the child's remaining private-frame erasure assignment stays open.
Existing child helper, metadata and result reviews are joined, not replaced by
an invented empty effect or by treating every child call as harmless.
"""
import windows_enclave_sha2_parent_outputs as output
p,n,o,s=output.p,output.n,output.o,output.s


def predicate(bodies,assembly):
    name,lines,edges,states,_=output.prepare(bodies,assembly)
    callee=s.one(bodies,r'mask_is_zero$');at=o.unique(lines,'callq '+callee)
    p.storage.exact(bodies[callee],[
        'movzbl %dl, %edx','movzbl (%rcx), %r10d','andl %edx, %r10d',
        'sete %al','movzbl %al, %eax','xorl %r10d, %r10d','retq'])
    admitted=output.admission.admission(bodies,assembly,s.one(bodies,r'Executor13digest_secret$'))
    seed=o.unique(lines,'addq $20, %rdi');step=o.unique(lines,'addq $24, %rdi')
    capture=o.unique(lines,'movq %r9, %rdi');head=o.unique(lines,'.B5:')
    s.require(states[capture]['r9']=={-1} and states[seed]['rdi']=={capture} and
              states[head]['rdi']=={seed,step} and step+1==admitted['step'],
              'original header cursor advances once per published input')
    n.straight(edges,step,admitted['step']);n.g.dominates(edges,0,seed,head)
    cut=output.admission.p.filtered(edges,edges=[(admitted['step'],head)])
    n.g.dominates(cut,head,admitted['publication'],step)
    s.require(step not in n.g.reachable(cut,step+1),'no repeated header advance in one input iteration')
    start=head+3
    expected=['movq -12(%rdi), %r13','cmpq $1024, %r13','ja .B24',
        'movq -20(%rdi), %r12','movzbl (%rdi), %r14d','testq %r13, %r13','je .B11',
        'leal -1(%r14), %eax','cmpb $7, %al','ja .B13','cmpb $7, %r14b','ja .B3',
        'leaq -1(%r13), %rax','movb $-1, %dl','movl %r14d, %ecx','shrb %cl, %dl',
        'addq %r12, %rax','movq %rax, %rcx','callq '+callee]
    s.require(lines[start:at+1]==expected,'one-byte predicate uses the checked original final byte')
    n.straight(edges,head,at)
    for branch in (start+2,start+6,start+9,start+11):
        output.admission.p.guarded_path(cut,head,at,(branch,branch+1))
    s.require(states[start]['rdi']==states[start+3]['rdi']==states[start+4]['rdi']=={seed,step},
              'length, pointer and tail fields use the same original current header')
    s.require(states[at]['rcx']=={at-1} and states[at]['rdx']=={at-3},
              'checked address and mask survive to predicate entry')
    frame=p.stack.inspect_body(bodies[callee],callee,set(bodies),{})
    s.require(not frame['calls'] and not frame['tail_calls'],'predicate has no hidden helper calls')
    return dict(line=at,target=callee,role='bounded_tail_predicate',
        header_capture=capture,header_seed=seed,header_step=step,
        header_offsets=[20+24*i for i in range(4)],length_range=[1,1024],last_bits_range=[1,7],
        address='original current lane pointer + admitted length - 1',
        footprints=[['reads','input',0,1024]],actual_read_bytes=1,
        normal_stack_span=[-8+frame['local_low'],0])


def child_interface(bodies,assembly,prior):
    name,lines,edges,_,spans=output.prepare(bodies,assembly)
    handoff=prior['simd_wide_descriptor_handoff'];child=handoff['child']['function']
    at=o.unique(lines,'callq '+child);probe=o.unique(lines,'callq __chkstk')
    tables=o.source.paths.jump_tables(assembly,lines)
    states=o.definitions(lines,name,tables,(32,40),spans,bases=n.BASES,call_clobbers={probe:{'rax'}})
    expected=['leaq 144(%rbx), %rax','movq %rax, 40(%rsp)','movq %rdi, 32(%rsp)',
        'leaq 4640(%rbx), %rcx','leaq 120(%rbx), %rdx','leaq 192(%rbx), %r8',
        'leaq 352(%rbx), %r9','vzeroupper','callq '+child]
    s.require(lines[at-8:at+1]==expected,'all six original child ABI arguments')
    n.straight(edges,at-8,at)
    for reg,origin in [('rcx',at-5),('rdx',at-4),('r8',at-3),('r9',at-2),(32,at-6),(40,at-7)]:
        s.require(states[at][reg]=={origin},'no bypass or overwrite of child argument')
    n.trace(lines,states,at-6,'rdi',lambda site,loc:site>=0 and loc=='rdi' and
            lines[site]=='leaq 7200(%rbx), %rdi')
    s.require(handoff['parent']['child_call']==at and handoff['parent']['function']==name and
              handoff['child']['non_error_return_preserves_original_descriptors'] is True,
              'same result-tag guarded original descriptor handoff')
    normal=prior['simd_descriptor_normal_effects'];extra=prior['simd_wide_output_effects']
    child_lines=s.lines(bodies[child]);assigned=normal['assigned']+extra['assigned']
    p.bind_calls(child_lines,assigned+extra['terminal_calls'])
    s.require(normal['function']==extra['function']==child and len(assigned)==36 and
              not p.inventory(child_lines,assigned+extra['terminal_calls']),
              'complete once-only child helper contracts plus admitted unreachable terminal')
    # Reuse actual mapped helper effects. Do not pretend the child result writes
    # preserve a previously live returned object: its lifetime starts on success.
    protected=[dict(root='resident-frame',span=v) for v in ([64,72],[192,352],[352,416])]
    mapped=normal['mapped_effects']+extra['mapped_effects']
    for direction,root,lo,hi in mapped:
        s.require(direction in ('reads','writes') and type(lo) is int and type(hi) is int and lo<hi,
                  'nonempty mapped child helper effects')
        if direction=='writes':
            s.require(all(root!=v['root'] or not p.p.cells.overlaps((lo,hi),v['span']) for v in protected),
                      'child helpers cannot corrupt parent input, owner or original output descriptors')
    layout=p.p.placements(bodies,'simd512');s.require(layout['frame']['offset']==-1136,'same child ABI frame')
    # The result occupies 104 bytes and is disjoint from every protected object.
    for store in handoff['child']['stores']:
        lo,hi=store['span'];s.require(0<=lo<hi<=104,'bounded original hidden result store')
        p.exclude([('writes',dict(object='result',span=[lo,hi]))],protected,
                  {'result':dict(root='resident-frame',offset=4640,bounds=[0,104])})
    return dict(line=at,target=child,role='reviewed_child_interface',argument_offsets=dict(
        result=4640,executor=120,inputs=192,outputs=352,workspace=7200,control=144),
        child_returning_calls=len(assigned),terminal_calls=extra['terminal_calls'],
        mapped_helper_effects=mapped,protected_parent_objects=protected,
        original_result_store_count=len(handoff['child']['stores']),
        child_private_frame_assignment_and_erasure_pending=True)


PREREQUISITES=(
    ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
    ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
    ('simd_wide_descriptor_handoff','conditional_direct_descriptor_handoff_checked'),
    ('simd_wide_output_effects','all_child_normal_calls_assigned'),
    ('simd_admitted_overflow_paths','selected_overflow_unreachable_for_admitted_preserved_inputs'),
    ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
    ('simd_parent_authority_effects','operation_original_owner_result_and_authority_callers_joined'),
    ('simd_parent_setup_effects','setup_arguments_extents_and_temporal_noninterference_checked'))


def inspect(bodies,assembly,prior):
    s.require(all(prior[key][field] is True for key,field in PREREQUISITES),
              'fresh complete parent/child argument, allocation, admission and metadata reviews')
    name,lines,edges,_,_=output.prepare(bodies,assembly)
    at=p.result.fixed_parent_frame(lines,edges)
    probe=dict(line=at,target='__chkstk',role='shared_stack_probe',argument_bytes=12984,
        before_aligned_private_frame=True,shared_runtime_register_and_stack_contract_required=True,
        stack_effects_qualified=False)
    mask=predicate(bodies,assembly);child=child_interface(bodies,assembly,prior)
    calls=[probe,mask,child];p.bind_calls(lines,calls)
    previous=prior['simd_parent_setup_effects']
    s.require(sorted((v['line'],v['target']) for v in calls)==
              sorted((v['line'],v['target']) for v in previous['remaining_parent_calls']),
              'exact remaining three parent interfaces, no dropped obligation')
    assigned=prior['simd_descriptor_normal_effects']['parent']['assigned']+calls
    for key in ('output','authority','setup'):assigned+=prior['simd_parent_'+key+'_effects']['assigned']
    s.require(len(assigned)==27 and not p.inventory(lines,assigned),'every parent call interface assigned once')
    return dict(function=name,assigned=calls,assigned_parent_call_count=len(assigned),remaining_parent_calls=[],
        all_parent_call_interfaces_assigned=True,all_parent_memory_and_stack_effects_qualified=False,
        shared_runtime_calls=[dict(line=at,target='__chkstk')]+previous['shared_runtime_calls'],
        child_private_frame_assignment_and_erasure_pending=True,whole_frame_qualified=False,
        shared_completion_package=8,shared_prerequisites=previous['shared_prerequisites'])
