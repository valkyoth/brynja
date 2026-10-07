"""Join the two narrow SIMD overflow guards to admitted, preserved inputs.

This is a conditional proof for the saved private caller, not a general panic
effect contract. The parent must supply its fresh metadata/allocation reviews;
shared Win64 ABI, helper and protected-window obligations remain explicit.
"""
import re
import windows_enclave_sha2_narrow_cfg as n
import windows_enclave_sha2_allocation_stack as stack
o,g,s=n.o,n.g,n.s


def filtered(graph,*,nodes=(),edges=()):
    return {a:[b for b in targets if b not in nodes and (a,b) not in edges]
            for a,targets in graph.items() if a not in nodes}


def single_entry(graph,first,last):
    incoming={(a,b) for a,targets in graph.items() for b in targets
              if first<=b<=last and not first<=a<=last}
    s.require(incoming=={(first-1,first)},'no bypass into fail-stop induction region')


def guarded_path(graph,start,use,edge,*,exclude=()):
    # Exclusions denote explicit alternative value definitions, not an assumed
    # infeasible branch. The caller must account for every excluded definition.
    stack.require_edge(filtered(graph,nodes=exclude),start,use,edge)


def byte_domains():
    nonempty=[v for v in range(256) if ((v-1)&255)<=7]
    empty=[v for v in range(256) if v==0]
    partial=[v for v in sorted(set(nonempty+empty)) if v&0xf7]
    s.require(nonempty==list(range(1,9)) and empty==[0] and partial==list(range(1,8)),
              'all byte values preserve the admitted partial-bit bound')
    return dict(byte_values=256,nonempty=nonempty,empty=empty,partial=partial)


def iterator(lines,states,graph):
    head=o.unique(lines,'.B66:');first=head-3
    s.require(lines[first:head]==['xorl %eax, %eax','xorl %edx, %edx','movq $0, 80(%rbx)'],
              'iterator and lane counters start together at zero')
    end=o.unique(lines,'.B78:')+2
    single_entry(graph,first,end);n.straight(graph,first,head-1)
    s.require(lines[head+1:head+7]==['cmpq $7, %rdx','ja .B69','cmpq $-1, %rax',
        'je .B190','leaq 1(%rdx), %r9','leaq (%rdx,%rdx,4), %r8'],
        'unsigned bounded lane guard precedes iterator overflow guard and increment')
    n.straight(graph,head,head+6)
    inc=first+o.unique(lines[first:end+1],'incq %rax')
    restore=first+o.unique(lines[first:end+1],'movq %r9, %rdx')
    step=head+5
    s.require(states[head]['rax']==states[inc]['rax']=={first,inc} and
              states[head]['rdx']==states[step]['rdx']=={first+1,restore} and
              states[restore]['r9']=={step},'all induction definitions retain the same lane number')
    backs={o.unique(lines,'je .B66'),o.unique(lines,'jmp .B66')}
    s.require(n.predecessors(graph,head)=={head-1,*backs},'complete iterator backedge population')
    cut=filtered(graph,edges=[(b,head) for b in backs])
    guarded_path(cut,head,inc,(head+2,head+3))
    g.dominates(cut,head,step,inc);g.dominates(cut,head,inc,restore)
    for back in backs:
        s.require(back not in g.reachable(cut,inc+1,removed_node=restore),
                  'an increment cannot return without the matching lane restore')
    for at in (step,inc,restore):
        s.require(at not in g.reachable(cut,at+1),
                  'no update replay without a fresh bounded loop iteration')
    # Base n=0. Updates are paired, occur once and require n<=7; a CFG path
    # without updates preserves both counters (including the conservatively
    # followed exhausted-iterator branch). Headers contain 0..8; the overflow
    # comparison sees only 0..7. No pointer-null predicate is assumed here.
    return dict(loop_head=head,guard=head+4,initializers=[first,first+1],
        next_lane=step,iterator_increment=inc,lane_restore=restore,
        header_values=list(range(9)),overflow_compare_values=list(range(8)),
        backedges=sorted(backs),guard_is_iterator_not_active_compact_count=True)


def admitted_tail(lines,states,graph):
    load=o.unique(lines,'movzbl -1(%rdi,%r15), %r14d')
    zero=o.unique(lines,'xorl %r14d, %r14d')
    publish=o.unique(lines,'movb %r14b, -8(%r12)')
    s.require(states[publish]['r14']=={load,zero},'every published last-bit value has one of two admitted origins')
    s.require(lines[load+1:load+6]==['testq %rsi, %rsi','je .B11',
        'leal -1(%r14), %eax','cmpb $7, %al','ja .B13'],
        'exact unsigned byte admission predicate')
    n.straight(graph,load,load+5)
    s.require(states[load+3]['r14']=={load} and states[load+4]['rax']=={load+3},
              'range predicate reads this lane byte without register/flag substitution')
    guarded_path(graph,load,publish,(load+5,load+6),exclude=(zero,))
    s.require(zero in g.reachable(graph,0) and publish in g.reachable(graph,zero),
              'zero-valued alternate publication is real, not vacuous')
    # The separate pointer/field review binds all eight publications and their
    # preservation; neither an uninitialized lane nor a later clobber qualifies.
    return dict(source_byte=load,zero_definition=zero,publication=publish,
        nonempty_guard=load+5,admitted_last_bits=byte_domains())


def partial_tail(lines,states,graph):
    load=o.unique(lines,'movzbl 568(%rbx,%rax), %edi')
    check=o.unique(lines,'cmpb $7, %dil');branch=check+1
    s.require(lines[load-1]=='movq 80(%rbx), %rax' and states[load]['rax']=={load-1},
              'partial-bit load uses the current preserved scalar descriptor')
    s.require(lines[load+1:load+3]==['testb $-9, %dil','jne .B163'] and
              lines[branch]=='ja .B190','aligned zero/eight tails bypass the partial-bit path')
    n.straight(graph,load-1,load+2);n.straight(graph,check,branch)
    s.require(states[load+1]['rdi']==states[check]['rdi']=={load},
              'same admitted byte survives every path and the nonvolatile ABI copy call')
    start=o.unique(lines,'.B146:')
    g.dominates(graph,0,start,check)
    guarded_path(graph,start,check,(load+2,o.unique(lines,'.B163:')))
    g.dominates(graph,start,load,check)
    s.require(states[load-1][80]==states[start][80],
              'last-bit load uses the same bounded scalar-lane counter')
    return dict(field_load=load,field_offset=24,descriptor_stride=40,
        partial_selection=load+2,overflow_guard=branch,possible_compare_values=list(range(1,8)),
        copy_call_preserves_nonvolatile_rdi_required=True)


def terminal(lines,graph,guards):
    at=o.unique(lines,'.B190:')
    s.require(n.predecessors(graph,at)==set(guards),'exact two incoming overflow-panic edges')
    s.require(re.fullmatch(r'callq \S*panic_const_add_overflow',lines[at+1]) is not None and
              lines[at+2]=='ud2','overflow path remains a nonreturning fail-stop')
    n.straight(graph,at,at+2)
    return dict(label='.B190',call=at+1,target=lines[at+1][6:],incoming_guards=guards,
        returning_effects_assigned=False)


def compose(prior,name):
    fields=prior['simd_metadata_preservation'];physical=prior['simd_physical_allocation_lifetimes']
    pointers=prior['simd_narrow_pointer_lifetimes'];indices=prior['simd_compact_indices']
    s.require(fields['function']==pointers['function']==indices['function']==name,
              'same saved narrow function in all supporting reviews')
    s.require(fields['conditional_input_and_authority_field_preservation_checked'] is True and
        physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True and
        pointers['normal_cfg_pointer_definition_lifetimes_checked'] is True,
        'admission proof needs current preserved physical input lifetimes')
    s.require(pointers['input_construction']['destination_offsets']==list(n.INPUTS) and
        pointers['scalar_inputs']['scalar_lane_offsets']==[40*i for i in range(8)] and
        indices['public_identity_combinations']==6561 and indices['active_count_exact'] is True,
        'complete eight-lane initialization, selection and independent compaction replay')
    return dict(input_fields_preserved=True,physical_lifetimes_joined=True,
        original_input_and_scalar_lane_selection_joined=True,
        shared_prerequisites=physical['prerequisites'])


def inspect(bodies,assembly,lane,prior):
    if lane=='simd512':
        s.require(prior['simd_control_call_effects']['failstop_paths']==[],
                  'wide selected slice contains no direct overflow-panic call')
        # The selected slice branches to a terminal outside its interval. An
        # empty local call list must not become a whole-function absence claim.
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
    s.require(lane=='simd256','assigned SIMD fail-stop route')
    name=s.one(bodies,r'Resident6digest$');lines=s.lines(bodies[name])
    states,graph,_=n.prepare(lines,assembly,name)
    count=iterator(lines,states,graph);admission=admitted_tail(lines,states,graph)
    tail=partial_tail(lines,states,graph)
    return dict(function=name,iterator=count,admitted_tail=admission,partial_tail=tail,
        terminal=terminal(lines,graph,[count['guard'],tail['overflow_guard']]),
        composition=compose(prior,name),selected_finish_overflow_paths=2,
        selected_overflow_unreachable_for_admitted_preserved_inputs=True,
        caller_frame_erasure_or_OS_window_qualification=False,whole_frame_qualified=False)
