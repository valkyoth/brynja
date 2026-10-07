"""Wide parent's final transfers/destructors, conditional on operation admission.

This binds actual normal call arguments, not merely callee names. Operation
result correctness and the remaining setup/check/child effects stay explicit
prerequisites; this is neither whole-frame nor whole-image qualification.
"""
import re
import windows_enclave_sha2_wide_outputs as child
import windows_enclave_sha2_wide_failstop as admission
p,n,o,s=child.normal,child.n,child.o,child.s


def prepare(bodies,assembly):
    name=s.one(bodies,r'Resident6digest$');lines=s.lines(bodies[name]);edges=child.d.graph(lines,assembly)
    probe=p.result.fixed_parent_frame(lines,edges)
    tables=o.source.paths.jump_tables(assembly,lines)
    kwargs=dict(bases=n.BASES,call_clobbers={probe:{'rax'}})
    raw=o.definitions(lines,name,tables,(64,),**kwargs)
    published=admission.admission(bodies,assembly,s.one(bodies,r'Executor13digest_secret$'))
    n.straight(edges,published['publication']-9,published['publication']+1)
    head=o.unique(lines,'.B21:');seed=head-2;step=head+9
    s.require(lines[seed:head]==['movl $224, %eax','.p2align 4'] and
              lines[step:step+3]==['addq $256, %rax','cmpq $2784, %rax','jne .B21'] and
              n.predecessors(edges,head)=={head-1,step+2},'ten-iteration parent scratch initialization')
    n.straight(edges,head,step+2);spans={}
    for i in range(8):
        at=head+1+i;offset=4416+32*i
        s.require(lines[at]==f'vmovups %ymm0, {offset}(%rbx,%rax)' and
                  raw[at]['rax']==raw[step]['rax']=={seed,step},'only the checked scratch-loop index')
        spans[at]=(offset+224,offset+2528+32)
    for at,line in enumerate(lines):
        if line.startswith('callq ') or at in spans:continue
        op,args=o.source.instruction(line)
        if o.source.store_span(op,args,n.BASES)!=o.source.INDEXED_FRAME:continue
        match=re.fullmatch(r'(\d+)\(%rbx,%r15\)',args[-1])
        s.require(match is not None and op in ('movq','movl','movw','movb'),
                  'only bounded parent descriptor-publication indexed stores')
        s.require(raw[at]['r15']=={published['seed'],published['step']} and
                  published['publication']-9<=at<=published['publication']+1,
                  'all indexed stores share the checked four-iteration publication index')
        width={'movq':8,'movl':4,'movw':2,'movb':1}[op];offset=int(match[1])
        spans[at]=(offset+34,offset+154+width)
        s.require(192<=spans[at][0]<spans[at][1]<=352,'publication writes confined to input descriptors')
    s.require(len(spans)==16,'complete eight publication and eight scratch initialization stores')
    states=o.definitions(lines,name,tables,(64,),spans,**kwargs)
    return name,lines,edges,states,spans


def owner_pointer(lines,edges,states,at,register):
    anchor=o.unique(lines,'movq 7200(%rbx), %rax')
    s.require(lines[anchor-9:anchor+2]==['movzbl 7208(%rbx), %eax','cmpb $2, %al','jne .B2',
        'movzbl 7200(%rbx), %eax','movb %al, (%rsi)','movb $-1, 24(%rsi)',
        'jmp .B29','.B2:','movb %al, 54(%rbx)','movq 7200(%rbx), %rax',
        'movq %rax, 64(%rbx)'],'owner pointer captured only after operation-result admission')
    n.straight(edges,anchor-2,anchor+1)
    admission.p.guarded_path(edges,0,anchor,(anchor-7,anchor-2))
    n.g.dominates(edges,0,anchor,at)
    return n.trace(lines,states,at,register,lambda site,loc:site==anchor and loc=='rax',(64,))


def transfers(bodies,assembly):
    name,lines,edges,states,indexed=prepare(bodies,assembly)
    copy=s.one(bodies,r'secret_memory18copy_secret_region$');rows=[]
    calls=[i for i,v in enumerate(lines) if v=='callq '+copy]
    s.require(len(calls)==4,'all four wide-parent copy calls')
    for i,at in enumerate(calls):
        off=352+16*i
        source=o.unique(lines,f'movq {off}(%rbx), %r8')
        size=o.unique(lines,f'movq {off+8}(%rbx), %rdx')
        s.require(lines[at-3:at]==['movq 64(%rbx), %rax',f'leaq {24+64*i}(%rax), %rcx',
                                  'movq %rdx, %r9'],'actual admitted owner destination and same copy length')
        n.straight(edges,at-3,at);owner_pointer(lines,edges,states,at-2,'rax')
        s.require(states[at]['r8']=={source} and states[at]['rdx']=={size} and
                  states[at]['r9']=={at-1},'source, capacity and length retain the same lane fields')
        check=size+(2 if i==3 else 1);branch=check+1
        s.require(lines[check]=='cmpq $64, %rdx' and lines[branch]==
                  ('jbe .B70' if i==0 else 'ja .B81' if i==3 else 'ja .B65'),
                  'unsigned lane length capacity check')
        n.straight(edges,size,branch)
        good=lines.index('.B70:') if i==0 else branch+1
        admission.p.guarded_path(edges,0,at,(branch,good))
        s.require(lines[source+1]=='testq %r8, %r8' and lines[source+2+(i==3)]==
                  ('je .B81' if i==3 else 'je .B80'),'actual source null rejection')
        null=source+2+(i==3);n.straight(edges,source,null)
        admission.p.guarded_path(edges,0,at,(null,null+1))
        rows.append(dict(line=at,target=copy,role='owner_output_copy',lane=i,
            source_load=source,length_load=size,width_guard=branch,width_range=[0,64],
            footprints=[['reads','parent',1376+64*i,1440+64*i],
                        ['writes','owner',24+64*i,88+64*i]]))
    return dict(function=name,calls=rows,indexed_write_extents=indexed,
                operation_result_contract_still_required=True)


def cleanup(bodies,assembly,handoff):
    name,lines,edges,states,_=prepare(bodies,assembly);names=p.storage.symbols(bodies)
    p.storage.wiping(bodies,'simd512');p.storage.output_drop(bodies,'simd512');child.reuse.zeroizer(bodies)
    rows=[]
    for at,line in enumerate(lines):
        if line!='callq '+s.ZERO or lines[at-1]!='movl $256, %edx' and lines[at-1]!='vzeroupper':continue
        first=at-3 if lines[at-1]=='vzeroupper' else at-2
        if lines[first]!='leaq 1376(%rbx), %rcx':continue
        s.require(lines[first:at]==['leaq 1376(%rbx), %rcx','movl $256, %edx']+
                  (['vzeroupper'] if first==at-3 else []),'exact parent output scratch clear')
        n.straight(edges,first,at)
        rows.append(dict(line=at,target=s.ZERO,role='output_scratch_clear',
                         footprints=[['writes','parent',1376,1632]]))
    s.require(len(rows)==2,'both success and failure scratch clears')
    for key,offset,size in (('scalar',11780,1170),('cpu',8480,3264)):
        at=o.unique(lines,'callq '+names[key]);n.straight(edges,at-1,at)
        origin=n.trace(lines,states,at,'rcx',lambda site,loc:site>=0 and isinstance(loc,str) and
                       lines[site]==f'leaq {offset}(%rbx), %{loc}')
        rows.append(dict(line=at,target=names[key],role=key+'_wipe',pointer_origins=origin,
                         footprints=[['writes','parent',offset,offset+size]]))
    s.require(handoff['function']==name,'same reviewed parent descriptor lifetimes')
    for at,offset in zip(handoff['normal_drops'],(4640,352),strict=True):
        s.require(lines[at-2:at+1]==[f'leaq {offset}(%rbx), %rcx','vzeroupper','callq '+names['output']],
                  'output drop receives its live preserved descriptor object')
        n.straight(edges,at-2,at)
        rows.append(dict(line=at,target=names['output'],role='output_drop',
            footprints=[['reads','parent',offset,offset+64],['writes','parent',offset+64,offset+72],
                        ['writes','parent',1376,1632]]))
    s.require(len(rows)==6,'two scratch clears, two internal wipes and two output destructors')
    return rows


def inspect(bodies,assembly,prior):
    joined=prior['simd_descriptor_normal_effects'];handoff=prior['simd_wide_descriptor_handoff']
    physical=prior['simd_physical_allocation_lifetimes'];descriptors=prior['simd_dynamic_clearing_descriptors']
    s.require(handoff['conditional_direct_descriptor_handoff_checked'] is True and
        physical['conditional_physical_separation'] is True and physical['constructor_result_and_worker_use_joined'] is True and
        descriptors['normal_direct_descriptor_write_lifetimes_checked'] is True and
        descriptors['exact_pointer_length_pair_and_all_loop_indices_checked'] is True and
        prior['simd_wide_output_effects']['all_child_normal_calls_assigned'] is True and
        prior['simd_primitive_contracts']['prior_semantic_review_replayed'] is True and
        joined['selected_normal_helpers_conditionally_preserve_descriptors'] is True,
        'fresh child, descriptor, allocation, primitive and prior effect proofs required')
    copied=transfers(bodies,assembly);calls=copied['calls']+cleanup(bodies,assembly,handoff['parent'])
    lines=s.lines(bodies[copied['function']]);p.bind_calls(lines,calls)
    keys={(v['line'],v['target']) for v in calls}
    s.require(len(keys)==10 and keys<={(v['line'],v['target']) for v in joined['parent']['pending']},
              'ten distinct previously unassigned parent calls')
    layout={'parent':dict(root='resident-frame',offset=0,bounds=[0,12984]),
            'owner':dict(root='resident-page',offset=24,bounds=[0,296])}
    protected=joined['protected_descriptors']+[dict(root='resident-frame',span=[64,72])]
    mapped=p.exclude([e for call in calls for e in p.footprints(call)],protected,layout)
    frames={};todo=[v['target'] for v in calls]
    while todo:
        callee=todo.pop()
        if callee in frames:continue
        proof=p.stack.inspect_body(bodies[callee],callee,set(bodies),{})
        frames[callee]=proof;todo.extend(v[1] for v in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==6,'copy pair, zeroizer, scalar/cpu wipe and output-drop stack closure')
    span=[-8+min(p.stack.depth(v['target'],frames) for v in calls),0]
    p.stack_exclude(span,protected);p.stack_exclude([0,32],protected)
    remaining=p.inventory(lines,joined['parent']['assigned']+calls)
    return dict(function=copied['function'],transfers=copied,assigned=calls,mapped_effects=mapped,
        protected_descriptors_and_owner_slot=protected,normal_stack_span=span,normal_callee_count=len(frames),
        remaining_parent_calls=remaining,assigned_parent_call_count=12,
        parent_output_transfer_and_cleanup_arguments_checked=True,
        operation_setup_checks_child_effects_and_shared_ABI_still_required=True,
        shared_prerequisites=physical['prerequisites'],whole_frame_qualified=False)
