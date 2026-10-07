"""Wide final-copy and error-clear callsites joined to live owned allocations.

The four original destination pointers are constructed inside a live parent
frame, hence nonnull. Only their four preflight null edges are excluded from
the conditional analysis; every other branch remains. This is not a generic
arbitrary-descriptor API proof or a whole-frame erasure claim.
"""
import windows_enclave_sha2_normal_effects as normal
import windows_enclave_sha2_simd_commit as commit
import windows_enclave_sha2_simd_reuse as reuse
import windows_enclave_sha2_control_effects as control
n,o,s=normal.n,normal.o,normal.s
d=normal.result.d
SLOTS=(976,1024,984,1016,960)


def nonnull_preflight(lines,edges):
    """Four infeasible null edges under the original live descriptor contract.

Keep instruction indices unchanged so all reaching definitions remain bound to
actual emitted instructions. No capacity, error or copy-result edge is removed.
"""
    admitted=lines[:];excluded=[]
    for i,label in enumerate((243,247,251,255)):
        at=o.unique(lines,f'je .B{label}')
        s.require(lines[at-1]==f'cmpq $0, {816+16*i}(%rbp)',
                  'only the corresponding original destination null predicate is excluded')
        n.straight(edges,at-1,at)
        admitted[at]='nop';excluded.append(dict(branch=at,target=lines.index(f'.B{label}:')))
    return admitted,excluded


def descriptor_load(lines,states,at,register,offset,slots=()):
    return n.trace(lines,states,at,register,
        lambda site,location: site>=0 and isinstance(location,str) and
        lines[site]==f'movq {offset}(%rbp), %{location}',slots,base='rbp')


def exports(bodies,assembly):
    commit.wide(bodies)
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);edges=d.graph(lines,assembly)
    admitted,excluded=nonnull_preflight(lines,edges)
    tables=o.source.paths.jump_tables(assembly,admitted)
    raw=o.definitions(admitted,name,tables,SLOTS)
    states=o.definitions(admitted,name,tables,SLOTS,o.indexed_effects(admitted,raw,tables))
    graph=d.graph(admitted,assembly);copy=s.one(bodies,r'secret_memory18copy_secret_region$');rows=[]
    for i in range(4):
        begin=o.unique(lines,f'.B{256+3*i}:');end=o.unique(lines,f'.B{259+3*i}:')
        calls=[at for at in range(begin,end) if lines[at]=='callq '+copy]
        s.require(len(calls)==1,'one final-copy call per output lane');at=calls[0]
        n.straight(edges,begin,at)
        destination=descriptor_load(admitted,states,at,'rcx',816+16*i)
        capacity=descriptor_load(admitted,states,at,'rdx',824+16*i)
        length=descriptor_load(admitted,states,at,'r9',824+16*i,SLOTS)
        o.require_workspace(admitted,states,at,'r8',1024+64*i,
                            {976:1024,1024:1152,984:1216})
        load=length[0]
        s.require(len(length)==1,'one original length load feeds this final copy')
        guard=load+(5 if i<2 else 6)
        s.require(lines[guard]=='ja .B14' and lines[guard-2]=='cmpq $63, %rax',
                  'unsigned decremented width must fit 1 through 64')
        n.straight(edges,load,guard)
        n.g.success_edge(graph,0,guard,at)
        s.require(lines[load+1]==('leaq -1(%r9), %rax' if i==0 else
                  'leaq -1(%r12), %rax' if i==1 else f'movq %rax, {1016 if i==2 else 960}(%rbp)') and
                  (i<2 or lines[load+2]=='decq %rax'),'same loaded width is range checked')
        rows.append(dict(line=at,target=copy,role='final_copy',lane=i,
            destination_loads=destination,capacity_loads=capacity,length_load=load,width_guard=guard,
            width_range=[1,64],footprints=[['reads','workspace',1024+64*i,1088+64*i],
                ['writes','resident_output',64*i,64*(i+1)]]))
    return dict(function=name,calls=rows,excluded_null_edges=excluded,
        original_nonnull_parent_destinations_required=True,
        all_other_normal_edges_retained=True,capacities_and_lengths_share_preserved_descriptor_fields=True)


def clears(bodies,assembly,descriptors):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);edges=d.graph(lines,assembly)
    loop=d.r.loop(lines,edges,o.unique(lines,'.B16:')+4,'.B17','.B18','.B21','rsi',
                  ('816(%rbp,%rsi)','824(%rbp,%rsi)'),64)
    s.require(descriptors['loops']==[loop],'same complete checked dynamic clearing loop')
    calls=[at for at,line in enumerate(lines) if loop['seed']<=at<=loop['exit']+3 and line=='callq '+s.ZERO]
    s.require(len(calls)==2 and calls[0]==loop['call'],'complete output-error-region zeroizer population')
    at=calls[1];start=o.unique(lines,'.B21:')
    s.require(lines[start:at+1]==['.B21:','movl $8, %edx','movq %rdi, %rcx','callq '+s.ZERO],
              'identity-only clear has exactly eight bytes and the saved address')
    n.straight(edges,start,at)
    tables=o.source.paths.jump_tables(assembly,lines);raw=o.definitions(lines,name,tables)
    states=o.definitions(lines,name,tables,indexed=o.indexed_effects(lines,raw,tables))
    origin=n.trace(lines,states,at,'rcx',lambda site,location:site>=0 and
        isinstance(location,str) and lines[site]==f'leaq 880(%rbp), %{location}',base='rbp')
    s.require(states[at]['rdx']=={start+1},'exact positive identity-clear length survives to the call')
    reuse.zeroizer(bodies)
    return dict(calls=[dict(line=calls[0],target=s.ZERO,role='dynamic_output_clear',
        indices=loop['index_offsets'],length_range=[1,64],footprints=[['writes','resident_output',0,256]]),
        dict(line=at,target=s.ZERO,role='identity_clear',pointer_origins=origin,length=8,
             footprints=[['writes','frame',880,888]])],null_and_empty_dynamic_slots_skipped=True)


def callbacks(bodies,assembly,leaves):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);edges=d.graph(lines,assembly)
    tables=o.source.paths.jump_tables(assembly,lines);raw=o.definitions(lines,name,tables,(1048,))
    states=o.definitions(lines,name,tables,(1048,),o.indexed_effects(lines,raw,tables))
    compiled=o.unique(lines,'callq *8(%rax)');load=compiled-10
    s.require(lines[load:compiled+1]==['movq (%r15), %rax','testq %rax, %rax','je .B8',
        'cmpb $1, 16(%rax)','movq %r15, 1048(%rbp)','jne .B12','movzbl 17(%rax), %ecx',
        '.Ltmp36:','movq %rax, 1024(%rbp)','vzeroupper','callq *8(%rax)'],
        'actual authority field, backend byte and indirect instruction sequence')
    n.straight(edges,load,compiled)
    o.require_origin(lines,states,load,'r15','executor',0,{1048:('executor',0)})
    s.require(states[compiled]['rax']=={load} and states[compiled]['rcx']=={load+6},
              'first revalidator uses the original authority and its backend field')
    cancel=o.unique(lines,'callq *%rax');base=cancel-7
    s.require(lines[base:cancel+1]==['movq 1176(%rbp), %rax','movq (%rax), %rcx',
        'movq 8(%rax), %rax','movq 32(%rax), %rax','.Ltmp38:','movq %rcx, 960(%rbp)',
        'movq %rax, 920(%rbp)','callq *%rax'],'actual original control/vtable slot callback')
    n.straight(edges,base,cancel)
    o.require_origin(lines,states,base+2,'rax','control',0,{})
    s.require(states[cancel]['rax']=={base+3} and states[base+3]['rax']=={base+2} and
              states[cancel]['rcx']=={base+1} and states[base+1]['rax']=={base},
              'first cancellation target and data retain the original control capture')
    control.leaf(bodies,leaves['compiled'],['movl %ecx, %eax','xorb $1, %al','retq'])
    control.leaf(bodies,leaves['callback'],['xorl %eax, %eax','retq'])
    return [dict(line=compiled,target='*8(%rax)',resolved=leaves['compiled'],role='compiled',footprints=[]),
            dict(line=cancel,target='*%rax',resolved=leaves['callback'],role='cancel',footprints=[])]


def inspect(bodies,assembly,prior):
    descriptors=prior['simd_dynamic_clearing_descriptors'];geometry=descriptors['geometry']
    physical=prior['simd_physical_allocation_lifetimes'];handoff=prior['simd_wide_descriptor_handoff']
    joined=prior['simd_descriptor_normal_effects'];primitive=prior['simd_primitive_contracts']
    s.require(descriptors['normal_direct_descriptor_write_lifetimes_checked'] is True and
        descriptors['exact_pointer_length_pair_and_all_loop_indices_checked'] is True and
        geometry['exact_lane_pointers_and_widths'] is True and geometry['ordered_disjoint_in_bounds'] is True and
        geometry['maximum_slot_bytes']==64 and geometry['scratch_bytes']==256 and
        physical['conditional_physical_separation'] is True and physical['constructor_result_and_worker_use_joined'] is True and
        handoff['conditional_direct_descriptor_handoff_checked'] is True and
        joined['selected_normal_helpers_conditionally_preserve_descriptors'] is True and
        prior['simd_metadata_preservation']['conditional_input_and_authority_field_preservation_checked'] is True and
        prior['simd_helper_slot_origins']['direct_cfg_origins_and_preservation_checked'] is True and
        primitive['prior_semantic_review_replayed'] is True,
        'current geometry, original lifetimes, primitive and prior effect prerequisites')
    copied=exports(bodies,assembly);cleared=clears(bodies,assembly,descriptors)
    leaves=prior['simd_control_call_effects']['leaf_targets']
    leaf_calls=callbacks(bodies,assembly,leaves)
    name=copied['function'];lines=s.lines(bodies[name]);calls=copied['calls']+cleared['calls']+leaf_calls
    normal.bind_calls(lines,calls)
    prior_pending=joined['unassigned_calls'];keys={(v['line'],v['target']) for v in calls}
    s.require(len(keys)==8 and keys<={(v['line'],v['target']) for v in prior_pending},
              'eight distinct previously unassigned child returning calls')
    remaining=[v for v in prior_pending if (v['line'],v['target']) not in keys]
    terminal=prior['simd_admitted_overflow_paths']
    s.require(len(remaining)==1 and remaining[0]['target'].endswith('panic_const_shr_overflow') and
              terminal['selected_overflow_unreachable_for_admitted_preserved_inputs'] is True and
              lines[remaining[0]['line']+1]=='ud2','only the separately proved unreachable terminal remains')
    s.require(not normal.inventory(lines,joined['assigned']+calls+remaining),
              'every normal child call assigned once, terminal listed separately')
    layout=normal.p.placements(bodies,'simd512')|{
        'resident_output':dict(root='resident-frame',offset=1376,bounds=[0,256])}
    s.require(handoff['parent']['original_descriptor_argument']==[352,416] and
              handoff['parent']['returned_descriptors']==[4640,4704], 'same parent descriptor locations')
    protected=joined['protected_descriptors']+[normal.p.place(dict(object='frame',span=[slot,slot+8]),layout)
                                              for slot in SLOTS]
    mapped=normal.exclude([e for call in calls for e in normal.footprints(call)],protected,layout)
    # A preceding final copy cannot invalidate subsequent source or width slots.
    # Source reads live in the workspace; destinations are a distinct parent
    # output allocation, not child locals or that workspace.
    frames={};todo=[v.get('resolved',v['target']) for v in calls]
    while todo:
        callee=todo.pop()
        if callee in frames:continue
        proof=normal.stack.inspect_body(bodies[callee],callee,set(bodies),{})
        frames[callee]=proof;todo.extend(v[1] for v in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==5,'complete copy-wrapper, copy-bytes, zeroizer and two leaf callbacks stack closure')
    span=[-136+min(normal.stack.depth(v.get('resolved',v['target']),frames) for v in calls),-128]
    normal.stack_exclude(span,protected,layout['frame']['offset'])
    normal.stack_exclude([-128,-96],protected,layout['frame']['offset'])
    return dict(function=name,final_copies=copied,clears=cleared,callbacks=leaf_calls,assigned=calls,
        mapped_effects=mapped,protected_descriptors_and_future_copy_slots=protected,
        normal_stack_span=span,normal_callee_count=len(frames),remaining_child_calls=[],terminal_calls=remaining,
        child_returning_call_count=len(joined['assigned'])+len(calls),all_child_normal_calls_assigned=True,
        original_destination_source_and_length_lifetimes_conditionally_joined=True,
        final_copy_and_error_clear_effects_conditionally_disjoint=True,
        parent_helper_noninterference_and_shared_ABI_required=True,
        shared_prerequisites=physical['prerequisites'],whole_frame_qualified=False)
