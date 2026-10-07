"""Wide parent operation-result/authority contracts and six actual callsites.

Exact helper bodies retain admission, clearing and quarantine branches. Caller
root identity, indirect callback target and normal stack effects are joined;
remaining setup/child helpers and shared runtime/ABI remain prerequisites.
"""
import windows_enclave_sha2_parent_outputs as output
p,n,o,s=output.p,output.n,output.o,output.s


def code(text):return text.strip().split('|')


def contracts(bodies,compiled,lane='simd512'):
    s.require(lane in ('simd256','simd512'),'exact authority contract lane')
    narrow=lane=='simd256'
    out,phase,sequence,pointer=(16,280,272,8) if narrow else (24,288,280,16)
    names=output.child.control.authority
    operation=names.role(bodies,'owner');check=names.role(bodies,'check')
    output.child.control.leaf(bodies,compiled,['movl %ecx, %eax','xorb $1, %al','retq'])
    output.child.reuse.zeroizer(bodies)
    clear=f'leaq {out}(%rbx), %rcx|movl $256, %edx|callq '+s.ZERO+'|'
    invalidate=('movb $2, (%rbx)|' if narrow else 'movw $-1, (%rbx)|')+\
        f'movb $2, {phase}(%rbx)|movq {pointer}(%rbx), %rax|movb $0, 16(%rax)|'
    p.storage.exact(bodies[operation],code(
        'pushq %rbp|pushq %rsi|pushq %rdi|pushq %rbx|subq $56, %rsp|leaq 48(%rsp), %rbp|'
        f'movq $-2, (%rbp)|movq %rdx, %rbx|movq %rcx, %rsi|cmpb %r9b, {phase}(%rdx)|jne .B15|'
        f'movq %r8, %rdi|movq {sequence}(%rbx), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|'
        'testb %al, %cl|jne .B2|'+clear+invalidate+
        'movb $1, (%rsi)|movb $2, 8(%rsi)|jmp .B14|.B15:|'+clear+invalidate+
        f'movb $0, (%rsi)|movb $2, 8(%rsi)|jmp .B14|.B2:|movq {pointer}(%rbx), %rax|'
        'cmpb $1, 16(%rax)|jne .B9|movq %rbx, -16(%rbp)|movzbl 17(%rax), %ecx|'
        'movq %rax, -8(%rbp)|callq *8(%rax)|nop|testb %al, %al|movq -16(%rbp), %rbx|'
        'movq -8(%rbp), %rax|je .B9|cmpb $0, 17(%rax)|jne .B10|cmpb $1, 16(%rax)|jne .B9|'
        'xorl %ecx, %ecx|callq *8(%rax)|nop|testb %al, %al|movq -16(%rbp), %rbx|'
        f'movq -8(%rbp), %rax|je .B9|movq %rdi, {sequence}(%rbx)|movq %rbx, (%rsi)|'
        'movb $0, 8(%rsi)|jmp .B14|.B9:|movb $0, 16(%rax)|.B10:|movb $5, (%rsi)|'
        'movb $2, 8(%rsi)|'+clear+invalidate+
        '.B14:|addq $56, %rsp|popq %rbx|popq %rdi|popq %rsi|popq %rbp|retq'))
    p.storage.exact(bodies[check],code(
        'pushq %rbp|subq $48, %rsp|leaq 48(%rsp), %rbp|movq $-2, -8(%rbp)|'
        'cmpb $1, 16(%rcx)|jne .B7|movq %rcx, %rax|movzbl 17(%rcx), %ecx|'
        'movq %rax, -16(%rbp)|callq *8(%rax)|nop|testb %al, %al|movq -16(%rbp), %rcx|'
        'je .B7|movb $5, %al|cmpb $0, 17(%rcx)|jne .B8|cmpb $1, 16(%rcx)|jne .B7|'
        'movq %rcx, %rax|xorl %ecx, %ecx|callq *8(%rax)|nop|movl %eax, %ecx|'
        'movb $-1, %al|testb %cl, %cl|movq -16(%rbp), %rcx|jne .B8|.B7:|'
        'movb $0, 16(%rcx)|movb $5, %al|.B8:|addq $48, %rsp|popq %rbp|retq'))
    # These complete bodies have no hidden memory instructions, alternative
    # returns or indirect targets. Saved pointer spills are bounded separately;
    # no claim that individual compiler slots are erased is made here.
    return dict(operation=operation,check=check,compiled=compiled,
        success_returns_original_owner_pointer=True,result_error_tag=2,result_success_tag=0,
        operation_result_bytes=9,cleared_owner_output=[out,out+256],authority_health_byte=16,
        independent_phase_sequence_wrap_health_kernel_and_callback_rejections=True)


def callsites(bodies,assembly,helpers):
    name,lines,edges,_,spans=output.prepare(bodies,assembly)
    tables=o.source.paths.jump_tables(assembly,lines);probe=o.unique(lines,'callq __chkstk')
    states=o.definitions(lines,name,tables,(64,88),spans,bases=n.BASES,call_clobbers={probe:{'rax'}})
    at=o.unique(lines,'callq '+helpers['operation'])
    s.require(lines[at-2:at]==['leaq 7200(%rbx), %rcx','xorl %r9d, %r9d'] and
              states[at]['rcx']=={at-2} and states[at]['r9']=={at-1} and
              states[at]['rdx']==states[at]['r8']=={-1},
              'operation receives original owner/sequence, initial phase and private result storage')
    n.straight(edges,at-2,at)
    capture=o.unique(lines,'movq 7200(%rbx), %rax')
    n.straight(edges,at,capture-7)
    output.owner_pointer(lines,edges,states,capture+1,'rax')
    rows=[dict(line=at,target=helpers['operation'],role='operation',footprints=[
        ['reads','owner',16,24],['reads','owner',280,289],['reads','authority',8,18],
        ['writes','owner',0,2],['writes','owner',24,289],['writes','authority',16,17],
        ['writes','parent',7200,7209]])]
    load=o.unique(lines,'movq 16(%rax), %r8')
    output.owner_pointer(lines,edges,states,load,'rax')
    targets=[i for i,line in enumerate(lines) if line=='callq *8(%r8)']
    s.require(len(targets)==2,'both parent compiled-target callbacks')
    for at in targets:
        roots=n.trace(lines,states,at,'r8',lambda site,loc:site==load and loc=='r8',(88,))
        definitions=states[at]['rcx'];s.require(len(definitions)==1,'one backend byte definition')
        field=next(iter(definitions))
        s.require(lines[field]=='movzbl 17(%r8), %ecx','actual backend byte from same authority')
        n.trace(lines,states,field,'r8',lambda site,loc:site==load and loc=='r8',(88,))
        n.straight(edges,field,at)
        rows.append(dict(line=at,target='*8(%r8)',resolved=helpers['compiled'],role='compiled',
                         authority_loads=roots,backend_load=field,footprints=[]))
    checks=[i for i,line in enumerate(lines) if line=='callq '+helpers['check']]
    s.require(len(checks)==2,'both parent pre/post-copy authority checks')
    for at in checks:
        source=next(iter(states[at]['rcx']))
        s.require(states[at]['rcx']=={source} and lines[source]=='movq 16(%rax), %rcx',
                  'check receives the actual admitted owner authority field')
        output.owner_pointer(lines,edges,states,source,'rax');n.straight(edges,source,at)
        rows.append(dict(line=at,target=helpers['check'],role='check',footprints=[
            ['reads','authority',8,18],['writes','authority',16,17]]))
    start=o.unique(lines,'leaq 24(%rsi), %rcx');at=start+2
    s.require(lines[start:at+1]==['leaq 24(%rsi), %rcx','movl $256, %edx','callq '+s.ZERO],
              'remaining owner-output clear has exact pointer offset and positive extent')
    output.owner_pointer(lines,edges,states,start,'rsi');n.straight(edges,start,at)
    rows.append(dict(line=at,target=s.ZERO,role='owner_clear',footprints=[['writes','owner',24,280]]))
    s.require(len(rows)==6,'six distinct parent authority/owner calls')
    return dict(function=name,calls=rows,operation_result_capture=capture,
        original_owner_and_sequence_arguments_checked=True,original_callback_and_backend_fields_checked=True)


def inspect(bodies,assembly,prior):
    physical=prior['simd_physical_allocation_lifetimes'];previous=prior['simd_parent_output_effects']
    normal=prior['simd_descriptor_normal_effects'];handoff=prior['simd_wide_descriptor_handoff']
    s.require(physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True and
        previous['parent_output_transfer_and_cleanup_arguments_checked'] is True and
        normal['selected_normal_helpers_conditionally_preserve_descriptors'] is True and
        handoff['conditional_direct_descriptor_handoff_checked'] is True and
        prior['simd_metadata_preservation']['conditional_input_and_authority_field_preservation_checked'] is True,
        'current physical owner, preserved metadata, descriptor and prior helper joins')
    compiled=prior['simd_control_call_effects']['leaf_targets']['compiled']
    helpers=contracts(bodies,compiled);joined=callsites(bodies,assembly,helpers);calls=joined['calls']
    lines=s.lines(bodies[joined['function']]);p.bind_calls(lines,calls)
    keys={(v['line'],v['target']) for v in calls}
    s.require(len(keys)==6 and keys<={(v['line'],v['target']) for v in previous['remaining_parent_calls']},
              'six previously unassigned distinct parent authority calls')
    layout={'parent':dict(root='resident-frame',offset=0,bounds=[0,12984]),
            'owner':dict(root='resident-page',offset=24,bounds=[0,296]),
            'authority':dict(root='resident-page',offset=0,bounds=[0,18])}
    protected=previous['protected_descriptors_and_owner_slot']
    mapped=p.exclude([v for call in calls for v in p.footprints(call)],protected,layout)
    indirect={(helpers[k],'*8(%rax)'):compiled for k in ('operation','check')}
    frames={};todo=[v.get('resolved',v['target']) for v in calls]
    while todo:
        callee=todo.pop()
        if callee in frames:continue
        proof=p.stack.inspect_body(bodies[callee],callee,set(bodies),indirect)
        frames[callee]=proof;todo.extend(v[1] for v in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==4,'complete operation/check/zeroizer/compiled normal stack closure')
    span=[-8+min(p.stack.depth(v.get('resolved',v['target']),frames) for v in calls),0]
    p.stack_exclude(span,protected);p.stack_exclude([0,32],protected)
    remaining=p.inventory(lines,normal['parent']['assigned']+previous['assigned']+calls)
    return dict(function=joined['function'],helpers=helpers,callsite_origins=joined,assigned=calls,
        mapped_effects=mapped,normal_stack_span=span,normal_callee_count=len(frames),
        remaining_parent_calls=remaining,assigned_parent_call_count=18,
        operation_original_owner_result_and_authority_callers_joined=True,
        remaining_setup_child_effects_and_shared_ABI_required=True,
        shared_prerequisites=physical['prerequisites'],whole_frame_qualified=False)
