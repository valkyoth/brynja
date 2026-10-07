"""Conditional admitted-input proof for the saved wide .B302 shift panic.

This joins parent publication and child scalar selection, not arbitrary caller
or helper memory effects. The parent supplies fresh field/allocation reviews;
Win64 nonvolatile preservation and shared protected-window obligations remain.
"""
import re
import windows_enclave_sha2_failstop as p
n,o,g,s=p.n,p.o,p.g,p.s


def inventory(bodies,assembly):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name])
    graph=g.graph(lines,o.source.paths.jump_tables(assembly,lines))
    at=o.unique(lines,'.B302:');guard=o.unique(lines,'ja .B302')
    s.require(lines[guard-1]=='cmpb $7, %bl' and
        re.fullmatch(r'callq \S*panic_const_shr_overflow',lines[at+1]) is not None and
        lines[at+2]=='ud2','wide out-of-slice shift overflow terminal')
    n.straight(graph,guard-1,guard);n.straight(graph,at,at+2)
    s.require(n.predecessors(graph,at)=={guard},'complete wide overflow terminal entries')
    return dict(function=name,selected_slice_direct_overflow_calls=0,
        whole_function_overflow_paths=1,guard=guard,terminal_call=at+1,
        admitted_input_unreachability_join_pending=True,
        returning_effects_assigned=False,whole_frame_qualified=False)


def admission(bodies,assembly,child):
    name=s.one(bodies,r'Resident6digest$');lines=s.lines(bodies[name])
    tables=o.source.paths.jump_tables(assembly,lines);graph=g.graph(lines,tables)
    probe=o.unique(lines,'callq __chkstk')
    states=o.definitions(lines,name,tables,bases=n.BASES,call_clobbers={probe:{'rax'}})
    seed=o.unique(lines,'movl $34, %r15d');head=o.unique(lines,'.B5:')
    step=o.unique(lines,'addq $40, %r15');publish=o.unique(lines,'movb %r14b, 182(%rbx,%r15)')
    end=o.unique(lines,'.B14:')
    p.single_entry(graph,seed,end-1)
    s.require(lines[seed+1]=='jmp .B5' and lines[head+1:head+3]==[
        'cmpq $194, %r15','je .B14'],'parent four-descriptor publication limit')
    n.straight(graph,head,head+2)
    s.require(n.predecessors(graph,head)=={seed+1,step} and
        states[head]['r15']==states[step]['r15']==states[publish]['r15']=={seed,step},
        'only exact seed and stride define every publication index')
    cut=p.filtered(graph,edges=[(step,head)])
    g.dominates(cut,head,publish,step)
    p.guarded_path(cut,head,publish,(head+2,head+3))
    s.require(publish not in g.reachable(cut,publish+1) and graph[step]==[head],
              'no publication or increment replay within one parent iteration')
    load=o.unique(lines,'movzbl (%rdi), %r14d');zero=o.unique(lines,'xorl %r14d, %r14d')
    s.require(states[publish]['r14']=={load,zero} and
        lines[load+1:load+6]==['testq %r13, %r13','je .B11',
        'leal -1(%r14), %eax','cmpb $7, %al','ja .B13'],
        'every published byte is zero or passes the unsigned one-through-eight predicate')
    n.straight(graph,load,load+5)
    s.require(states[load+3]['r14']=={load} and states[load+4]['rax']=={load+3},
              'admission comparison uses this lane byte')
    p.guarded_path(graph,load,publish,(load+5,load+6),exclude=(zero,))
    s.require(zero in g.reachable(graph,0) and publish in g.reachable(graph,zero),
              'zero publication is reachable')
    call=o.unique(lines,'callq '+child)
    s.require(lines[call-3]=='leaq 192(%rbx), %r8' and states[call]['r8']=={call-3},
              'child receives original parent descriptor array')
    p.guarded_path(graph,0,call,(head+2,end))
    # Seed 34, one publication before each +40, stop exactly at 194. This
    # establishes all four original descriptors, not merely a bounded index.
    return dict(function=name,seed=seed,step=step,publication=publish,source_byte=load,
        zero_definition=zero,child_call=call,publication_indices=[34,74,114,154],
        descriptor_offsets=[192+40*i for i in range(4)],field_offset=24,
        admitted_last_bits=p.byte_domains())


def scalar_index(lines,states,graph):
    start=o.unique(lines,'.B182:');seed=start+12
    s.require(lines[seed]=='xorl %edx, %edx','scalar byte-offset starts at zero')
    head=o.unique(lines,'.B184:');step=o.unique(lines,'addq $40, %rdx')
    save=o.unique(lines,'movq %rdx, 1000(%rbp)');reload=o.unique(lines,'movq 1000(%rbp), %r14')
    restore=reload+o.unique(lines[reload:],'movq %r14, %rdx');back=restore+2
    p.single_entry(graph,seed-1,back)
    s.require(lines[seed+3]=='jmp .B184' and lines[step+1:head]==[
        'incq %r14','cmpq $160, %rdx','je .B233'],
        'scalar loop increments by forty and stops after four descriptors')
    n.straight(graph,step,head-1)
    s.require(lines[head+1:head+7]==['movq 1040(%rbp), %rax',
        'movzwl 32(%rax,%rdx), %eax','movl %eax, 1008(%rbp)',
        'cmpl $65535, %eax','je .B183','movq %rdx, 1000(%rbp)'],
        'absent lane skips work without changing the byte-offset')
    n.straight(graph,head,save)
    s.require(lines[back]=='jmp .B183' and n.predecessors(graph,step-1)=={head+5,back} and
        n.predecessors(graph,head)=={seed+3,head-1},'complete scalar iteration entry population')
    s.require(states[head]['rdx']==states[save]['rdx']=={seed,step} and
        states[step]['rdx']=={seed,step,restore} and states[restore]['r14']=={reload} and
        states[reload][1000]=={save},'work path restores exactly the saved current descriptor index')
    cut=p.filtered(graph,edges=[(head+5,step-1),(back,step-1)])
    g.dominates(cut,head,save,reload);g.dominates(cut,head,reload,restore)
    g.dominates(cut,head,restore,back)
    for at in (save,reload,restore):
        s.require(at not in g.reachable(cut,at+1),'no scalar update replay within one iteration')
    return dict(loop_head=head,seed=seed,step=step,save=save,reload=reload,restore=restore,
        scalar_lane_offsets=[0,40,80,120],exhausted_offset=160)


def partial(lines,states,graph,index):
    load=o.unique(lines,'movzbl 24(%rax,%rcx), %ebx');check=o.unique(lines,'cmpb $7, %bl')
    s.require(lines[load-2:load]==['movq 1040(%rbp), %rax','movq 1000(%rbp), %rcx'] and
        states[load]['rax']=={load-2} and states[load]['rcx']=={load-1} and
        states[load-1][1000]=={index['save']},'partial-bit field uses the current original scalar lane')
    o.require_origin(lines,states,load-2,1040,'inputs',0,{1040:('inputs',0)})
    s.require(lines[load+1:load+3]==['testb $-9, %bl','jne .B201'] and
        lines[check+1]=='ja .B302','zero/eight bypass the partial-bit path')
    n.straight(graph,load-2,load+2);n.straight(graph,check,check+1)
    s.require(states[load+1]['rbx']==states[check]['rbx']=={load},
              'same admitted tail byte survives copy and every reaching path')
    head=index['loop_head'];g.dominates(graph,0,head,check)
    g.dominates(graph,head,index['save'],load)
    p.guarded_path(graph,head,check,(load+2,o.unique(lines,'.B201:')))
    return dict(field_load=load,field_offset=24,descriptor_stride=40,overflow_guard=check+1,
        possible_compare_values=list(range(1,8)),original_input_argument_checked=True,
        nonvolatile_rbx_and_helper_noninterference_required=True)


def inspect(bodies,assembly,prior):
    s.require(prior['simd_control_call_effects']['failstop_paths']==[],
              'wide selected slice contains no direct overflow-panic call')
    result=inventory(bodies,assembly);name=result['function'];lines=s.lines(bodies[name])
    tables=o.source.paths.jump_tables(assembly,lines);graph=g.graph(lines,tables)
    states=o.definitions(lines,name,tables,slots=(1000,1040))
    spans=o.indexed_effects(lines,states,tables)
    states=o.definitions(lines,name,tables,slots=(1000,1040),indexed=spans)
    fields=prior['simd_metadata_preservation'];physical=prior['simd_physical_allocation_lifetimes']
    s.require(fields['function']==name and
        fields['conditional_input_and_authority_field_preservation_checked'] is True and
        physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True,
        'wide admission requires the same preserved physical inputs and live owners')
    admitted=admission(bodies,assembly,name);index=scalar_index(lines,states,graph)
    tail=partial(lines,states,graph,index)
    return result|dict(admitted_tail=admitted,scalar_index=index,partial_tail=tail,
        indexed_stack_writes=spans,admitted_input_unreachability_join_pending=False,
        selected_overflow_unreachable_for_admitted_preserved_inputs=True,
        shared_prerequisites=physical['prerequisites'],
        caller_frame_erasure_or_OS_window_qualification=False)
