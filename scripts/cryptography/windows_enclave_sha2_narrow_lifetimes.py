"""SHA-224/256 authority and per-lane pointer origins through normal CFG paths.

This discharges pointer-definition/lifetime obligations, not physical allocation
separation or authority/input field integrity against indirect aliases. Those
remain separately named obligations in the parent batch review.
"""
import re
import windows_enclave_sha2_narrow_cfg as n
import windows_enclave_sha2_simd_digest as digest
import windows_enclave_sha2_narrow_input_uses as input_uses
import windows_enclave_sha2_narrow_unwind as unwind
o,g,s=n.o,n.g,n.s


def operation_result(bodies):
    name=s.one(bodies,r'Owner9operation$');lines=s.lines(bodies[name])
    states=o.definitions(lines,name,{},(-16,),bases={'rbp':(0,0),'rsp':(-48,-48)})
    at=o.unique(lines,'movq %rbx, (%rsi)')
    n.trace(lines,states,at,'rbx',lambda site,loc:site==-1 and loc=='rdx',(-16,),base='rbp')
    n.trace(lines,states,at,'rsi',lambda site,loc:site==-1 and loc=='rcx',base='rbp')
    s.require(lines[at+1]=='movb $0, 8(%rsi)','operation publishes the original owner with success flag')
    # Review the full result-store population, not a coincidental matching write.
    stores=[line for line in lines if re.search(r', (?:8)?\(%rsi\)$',line)]
    s.require(stores==['movb $1, (%rsi)','movb $2, 8(%rsi)',
        'movb $0, (%rsi)','movb $2, 8(%rsi)','movq %rbx, (%rsi)',
        'movb $0, 8(%rsi)','movb $5, (%rsi)','movb $2, 8(%rsi)'],
        'only success publishes an owner pointer; all errors have rejected tag')
    return dict(function=name,owner_publication=at,original_rdx_owner_returned=True)


def authority(lines,states,edges,bodies):
    operation=s.one(bodies,r'Owner9operation$');call=o.unique(lines,'callq '+operation)
    load=o.unique(lines,'movq 6688(%rbx), %rax')
    # There are two reads from the result union: an error-byte read and this
    # pointer read. Only the non-error edge can reach the latter.
    s.require(lines[call-2:call]==['leaq 6688(%rbx), %rcx','xorl %r9d, %r9d'] and
        lines[call+1:call+4]==['movzbl 6696(%rbx), %eax','cmpb $2, %al','jne .B2'],
        'original operation result and checked success discriminant')
    s.require(states[call]['rdx']=={-1},'operation receives original resident owner argument')
    branch=call+3;target=o.unique(lines,'.B2:')
    s.require(load in g.reachable(edges,call) and
        load not in g.reachable(edges,call,removed_edge=(branch,target)),
        'no owner result load without successful operation')
    n.straight(edges,target,load+1)
    s.require(lines[load+1]=='movq %rax, 152(%rbx)' and states[load+1]['rax']=={load},
              'original operation owner saved before union storage is reused')
    def owner(at,reg):
        return n.trace(lines,states,at,reg,lambda site,loc:site==load and loc=='rax',(152,))
    owner_reads=n.reads(lines,152)
    s.require(len(owner_reads)==6,'complete owner-pointer reload population')
    for at in owner_reads:owner(at,152)
    field=o.unique(lines,'movq 8(%rax), %r15')
    owner(field,'rax')
    seed=o.unique(lines,'movq %r15, 88(%rbx)')
    auth_reads=n.reads(lines,88)
    s.require(len(auth_reads)==11,'complete saved-authority reload population')
    for at in [seed,*auth_reads]:
        n.trace(lines,states,at,'r15' if at==seed else 88,
                lambda site,loc:site==field and loc=='r15',(88,))
    # Cover field dereferences before/after reloads, including the direct session
    # argument and terminal quarantine stores. These are not merely MOV slots.
    uses=[]
    for at,line in enumerate(lines):
        if at not in states:continue
        for reg in ('r15','rax','rcx'):
            if not re.search(r'(?<![\w])(?:8|16|17)?\(%'+reg+r'\)',line):continue
            try:n.trace(lines,states,at,reg,lambda site,loc:site==field and loc=='r15',(88,))
            except ValueError:continue
            uses.append(dict(line=at,register=reg))
    session=s.one(bodies,r'Session14compress_bytes$');at=o.unique(lines,'callq '+session)
    n.trace(lines,states,at,'rcx',lambda site,loc:site==field and loc=='r15',(88,))
    s.require(len(uses)==20,'all authority field/callback uses retain the original pointer')
    return dict(operation_result=operation_result(bodies),owner_initializer=load+1,
        owner_reads=owner_reads,authority_field_load=field,authority_initializer=seed,
        authority_reads=auth_reads,authority_uses=uses,session_call=at,
        authority_field_contents_and_external_owner_lifetime_still_required=True)


def input_construction(lines,states,edges):
    head=o.unique(lines,'.B5:');store=o.unique(lines,'movq %r13, -32(%r12)')
    initial=o.unique(lines,'movl $17, %r15d');base=o.unique(lines,'leaq 576(%rbx), %r12')
    step=o.unique(lines,'addq $24, %r15');advance=o.unique(lines,'addq $40, %r12')
    load=o.unique(lines,'movq -17(%rdi,%r15), %r13')
    s.require(lines[head+1:head+3]==['cmpq $209, %r15','je .B14'] and
        lines[initial+1]=='jmp .B5' and lines[step+1]=='addq $40, %r12',
        'eight input lanes advance source/destination in lockstep')
    s.require(n.predecessors(edges,head)=={initial+1,advance},'no extra input-loop entry')
    for at in (head,store,load,step):
        s.require(states[at]['r15']=={initial,step},'input source index has only bounded induction definitions')
    for at in (head,store,advance):
        s.require(states[at]['r12']=={base,advance},'input destination has only matching pointer advances')
    s.require(states[store]['r13']=={load},'each input pointer uses this iteration original lane load')
    n.trace(lines,states,load,'rdi',lambda site,loc:site==-1 and loc=='r9')
    g.dominates(edges,0,base,head);g.success_edge(edges,head,head+2,store)
    # Starting after a publication must cross BOTH advances and the fresh guard
    # before another publication; a previous iteration's guard is insufficient.
    for required in (step,advance,load):
        s.require(store not in g.reachable(edges,store+1,removed_node=required),
                  'no input publication replay without fresh lane/load/advance')
    s.require(store not in g.reachable(edges,step,removed_edge=(head+2,head+3)),
              'every new input lane crosses the fresh non-exhausted guard')
    # No direct writer touches any input pointer field at any later phase.
    end=o.unique(lines,'.B14:')
    for slot in n.INPUTS:
        s.require(all(state[slot]=={-1} for at,state in states.items() if at>=end),
                  'no direct or bounded indexed write to constructed input pointers')
    return dict(source_load=load,publication=store,loop_head=head,
        source_offsets=[24*i for i in range(8)],destination_offsets=list(n.INPUTS),
        input_pointer_fields_preserved_against_direct_writes=True,
        indirect_alias_preservation_and_typed_input_validity_required=True)


def scalar_inputs(lines,states,edges):
    head=o.unique(lines,'.B146:')
    seed=o.unique(lines,'jmp .B146')-1;step=o.unique(lines,'addq $40, %rcx')
    save=step+2;load=o.unique(lines,'movq 544(%rbx,%rax), %rax');publish=load+1
    s.require(lines[step-1:step+5]==['movq 80(%rbx), %rcx','addq $40, %rcx',
        'incq 72(%rbx)','movq %rcx, 80(%rbx)','cmpq $320, %rcx','je .B178'],
        'scalar descriptor induction is exactly eight lanes')
    s.require(lines[seed]=='movq $0, 80(%rbx)' and lines[publish]=='movq %rax, 112(%rbx)',
              'scalar pointer initialized from indexed descriptor')
    s.require(n.predecessors(edges,head)=={seed+1,step+4},'only initial and guarded scalar-loop entries')
    s.require(states[head][80]==states[step-1][80]==states[load-1][80]=={seed,save},
              'scalar index not confused with later report-slot reuse')
    n.straight(edges,step-1,step+4)
    s.require(lines[load-1]=='movq 80(%rbx), %rax' and states[load]['rax']=={load-1}
              and states[publish]['rax']=={load},'scalar descriptor pointer loaded without substitution')
    g.dominates(edges,head,load-1,load)
    s.require(load not in g.reachable(edges,save,removed_edge=(step+4,head)),
              'every advanced scalar lane must pass exhaustion check')
    reads=n.reads(lines,112)
    by_role={'counter':[],'input':[],'output':[]}
    counter=next(i for i,v in enumerate(lines) if v=='movq $0, 112(%rbx)')
    counter_store=next(i for i in range(counter+1,publish) if lines[i]=='movq %rax, 112(%rbx)')
    output=o.unique(lines,'leaq 7840(%rbx), %rax')+1
    absent=o.unique(lines,'.B208:')+1
    s.require(lines[output]=='movq %rax, 112(%rbx)' and lines[absent]=='movq $0, 112(%rbx)',
              'later output lifetime has its own pointer/absent initialization')
    for at in reads:
        defs=states[at][112]
        if at<publish:
            s.require(defs and defs<={counter,counter_store},'counter reads never treated as pointers')
            by_role['counter'].append(at)
        elif at<output:
            s.require(defs=={publish},'all scalar input reads have the current lane initializer only')
            g.dominates(edges,head,publish,at)
            by_role['input'].append(at)
        else:
            s.require(defs=={output,absent},'output reads cannot inherit earlier input/counter values')
            by_role['output'].append(at)
    s.require({k:len(v) for k,v in by_role.items()}=={'counter':2,'input':3,'output':2},
              'complete three-lifetime slot112 read population')
    expected=['addq 112(%rbx), %r8','movq 112(%rbx), %rax','movq 112(%rbx), %rcx']
    s.require([lines[i] for i in by_role['input']]==expected,'exact scalar pointer consumption roles')
    # The scalar block-copy loop retains its start/end pointer registers across
    # Win64 calls, advancing only the start by one block per successful iteration.
    start_ptr=o.unique(lines,'addq %rax, %rdi');end_ptr=o.unique(lines,'addq %rax, %r12')
    advance=o.unique(lines,'jne .B155')-3;copy=o.unique(lines,'.B155:')+5
    s.require(lines[start_ptr-1]=='shlq $6, %rdi' and lines[end_ptr-1]=='movq 112(%rbx), %rax',
              'block start/end use scalar input base')
    s.require(states[start_ptr]['rax']==states[end_ptr]['rax']=={end_ptr-1} and
        states[copy]['rdi']==states[advance]['rdi']=={start_ptr,advance} and
        states[advance+2]['r12']=={end_ptr},'block pointer progression retains original input provenance')
    s.require(lines[advance]=='addq $64, %rdi' and
              lines[advance+2:advance+4]==['cmpq %r12, %rdi','jne .B155'],
              'block-copy loop has exact endpoint comparison')
    block=o.unique(lines,'.B155:')
    s.require(n.predecessors(edges,block)=={block-1,advance+3},'no unassigned scalar-block loop entry')
    return dict(pointer_load=load,initializer=publish,scalar_lane_offsets=[40*i for i in range(8)],
        slot112_lifetimes=by_role,block_start=start_ptr,block_end=end_ptr,block_advance=advance,
        original_input_length_and_bounds_contract_required=True)


def inspect(bodies,assembly,ir):
    digest.admission(bodies,'simd256')
    name=s.one(bodies,r'Resident6digest$');lines=s.lines(bodies[name])
    states,edges,spans=n.prepare(lines,assembly,name)
    pointers=authority(lines,states,edges,bodies)
    return dict(function=name,authority=pointers,
        unwind_pointer_lifetimes=unwind.inspect(bodies,assembly,ir,lines,states,pointers),
        input_construction=input_construction(lines,states,edges),
        scalar_inputs=scalar_inputs(lines,states,edges),
        input_consumers=input_uses.inspect(lines,states,edges,bodies),
        indexed_frame_writes={str(k):list(v) for k,v in spans.items()},
        reachable_instructions=len(states),normal_cfg_pointer_definition_lifetimes_checked=True,
        indirect_effect_composition_and_original_allocation_validity_required=True,
        input_fields_and_authority_field_integrity_against_aliases_required=True,
        chkstk_and_nonvolatile_abi_contract_required=True,whole_frame_qualified=False)
