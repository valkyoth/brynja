"""Join original receiver, resident and executor allocations on the saved route.

This is conditional on serialized transport, Win64 preservation and an admitted
stack window. It does not assert OS residency or complete window reclamation.
"""
import re
import windows_enclave_sha3_simd_descriptor_moves as moves
import windows_enclave_sha3_simd_exception_effects as previous
import windows_enclave_sha2_allocation_lifetimes as allocations
import windows_enclave_sha2_allocation_stack as stack
import windows_enclave_sha3_simd_worker as worker
s,life=moves.s,moves.life


def lifetime_edges(bodies,assembly,n):
    body=bodies['RetainedWork'];lines=s.lines(body);graph=stack.edges(lines,assembly)
    consume=lines.index('callq '+n['receive']);live,page=n['live'],n['identity']
    checks=['testq %rcx, %rcx|je .B8','testq %rsi, %rsi|je .B11',f'cmpq %rdx, {page}(%rip)|jne .B49']
    start=lines.index('testq %rdx, %rdx');end=lines.index(f'movq {live}(%rip), %rsi')
    guards=[at for at in range(start,end) if lines[at].startswith(('je ','jne ','ja '))]
    s.require(len(guards)==5,'all outer page/window admission guards')
    for sequence in checks:
        s.sequences(body,[sequence]);guards.append(lines.index(sequence.split('|')[-1]))
    local=[at for at in range(lines.index('.B23:'),consume) if lines[at].startswith(('je ','jne ','ja '))]
    s.require(len(local)==6,'all worker-buffer bounds guards')
    for at in guards+local:stack.require_edge(graph,0,consume,(at,at+1))
    at=lines.index('cmpq $3, %rcx');s.require(lines[at+1]=='jne .B23','close is not an input-consuming operation')
    stack.require_edge(graph,0,consume,(at+1,lines.index('.B23:')))
    for at in (lines.index('.B12:'),lines.index('.B17:'),lines.index(f'movq $0, {live}(%rip)')):
        s.require(consume not in stack.reachable(graph,at),'construction or retirement cannot reenter input use')
    return dict(admission_edges=len(guards)+len(local)+1,consume=consume,
        constructor_publication_and_retirement_separate_from_digest=True)


def fixed_frame(code,allocation,probe):
    saves=previous.shape.SAVES
    prefix=['pushq %'+r for r in saves]
    prefix+=([f'movl ${allocation}, %eax','callq __chkstk','subq %rax, %rsp'] if probe else [f'subq ${allocation}, %rsp'])
    prefix+=['leaq 128(%rsp), %rbp']
    s.require(code[:len(prefix)]==prefix,'actual fixed frame establishment and incoming register saves')
    allowed={(len(saves)+2 if probe else len(saves),'subq %rax, %rsp' if probe else f'subq ${allocation}, %rsp'),
        (len(prefix)-1,'leaq 128(%rsp), %rbp')}
    returns=[i for i,line in enumerate(code) if line=='retq']
    s.require(len(returns)==1,'single shared balanced normal epilogue')
    tail=[f'addq ${allocation}, %rsp']+['popq %'+r for r in reversed(saves)]+['vzeroupper','retq']
    begin=returns[0]-len(tail)+1
    s.require(code[begin:returns[0]+1]==tail,'normal epilogue restores full allocation and original registers')
    allowed.add((begin,f'addq ${allocation}, %rsp'))
    for at,line in enumerate(code):
        op,_,rest=line.partition(' ');args=rest.split(', ')
        if op in ('pushq','popq'):
            s.require(at<len(saves) or begin<at<begin+9,'no hidden push/pop in a live allocation');continue
        if not op.startswith(('cmp','test','j')) and args[-1] in ('%rbp','%rsp','%ebp','%esp','%bp','%sp','%bpl','%spl'):
            s.require((at,line) in allowed,'fixed live stack/frame bases cannot be overwritten')
    return dict(local_rsp=-allocation-8*len(saves),rbp=128-allocation-8*len(saves),
        local_bytes=allocation,saved_register_bytes=8*len(saves))


def geometry(bodies,assembly,n,caller):
    outer=stack.inspect(bodies['RetainedWork'],assembly,8);_,outer_call=stack.call(outer,n['receive'])
    middle=stack.inspect(bodies[n['receive']],assembly,8);_,middle_call=stack.call(middle,n['digest'])
    s.require(outer['low']==outer_call['rsp']==-12792 and middle['low']==middle_call['rsp']==-1576,
        'actual live outer/receiver allocations at their nested calls')
    parent=fixed_frame(life.code(bodies[n['digest']]),9112,True)
    child=fixed_frame(life.code(bodies[n['executor']]),1128,False)
    receiver_rsp=-8+middle_call['rsp'];parent_entry=receiver_rsp-8
    parent_bp=parent_entry+parent['rbp'];child_entry=parent_entry+parent['local_rsp']-8
    child_bp=child_entry+child['rbp']
    s.require(child_bp-parent_bp==-1200,'same derived child/parent frame relation as all executor footprints')
    objects={key:[parent_bp+v for v in extent] for key,extent in caller['geometry']['executor_entry_objects'].items()}
    payload=[[64+1024*i,1088+1024*i] for i in range(12)];header=[12352,12736]
    descriptors=[receiver_rsp+1064,receiver_rsp+1512];result=[receiver_rsp+80,receiver_rsp+112]
    child_local=[child_entry+child['local_rsp'],child_entry-64]
    allocations.disjoint(payload+[header,descriptors,result,child_local]+list(objects.values()))
    s.require(all(parent_entry+parent['local_rsp']<=a<b<=parent_entry-64 for a,b in objects.values()),
        'all resident objects inside original allocated frame, not saves/return/home storage')
    s.require(child_local[1]<=min(a for a,_ in objects.values()),'executor locals below every original caller object')
    return dict(relative_to='RetainedWork RSP at receive call',worker_payload_slots=payload,header=header,
        receiver_descriptors=descriptors,receiver_result=result,parent_rbp=parent_bp,child_rbp=child_bp,
        child_locals=child_local,resident_objects=objects,authority_page=[0,24],owner_page=[24,1136],
        page_outside_complete_worker_window_required=True,aligned_call_abi_required=True)


def bridge(bodies,n,caller,receiver):
    body=bodies[n['receive']]
    s.sequences(body,[f'''movq 432(%rsp), %r8|movq 440(%rsp), %rax|movq {n['live']}+16(%rip), %rdx|
        movq %rax, 32(%rsp)|leaq 80(%rsp), %rcx|leaq 1064(%rsp), %r9|vzeroupper|callq {n['digest']}'''.replace('\n','').replace('        ','')])
    s.require(receiver['all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'] and
        receiver['descriptor_geometry']['active_call_regions_disjoint'] and
        receiver['descriptor_geometry']['lane_array']==[1064,1512], 'same local three-part receiver descriptor construction')
    code=life.code(bodies[n['digest']]);rows=[moves.transfer(code,lane) for lane in range(4)]
    for row in receiver['descriptor_geometry']['slots']:
        lane,part=row['lane'],row['part'];index=lane*3+part
        s.require(row['payload']==[1024*index,1024*(index+1)] and
            row['descriptor']==[1064+112*lane+32*part,1096+112*lane+32*part],
            'same original payload slice and descriptor field through repacking')
    return dict(repacked_lanes=rows,original_payload_fields=receiver['descriptor_geometry']['slots'],
        original_receiver_allocation_retained_through_nested_executor=True)


def inspect(bodies,assembly,caller,receiver,construction,services,exceptions):
    n=moves.digest.helpers.names(bodies)
    s.require(caller['functions']['executor']==services['function']==exceptions['function']==n['executor'] and
        services['all_executor_call_site_footprints_assigned'] and
        exceptions['original_guard_fields_live_at_all_synchronous_throw_sites'] and
        construction['publication_after_authority_and_owner_initialization'] and
        construction['placement']['authority_page_span']==[0,24] and
        construction['placement']['owner_page_span']==[24,1136],
        'complete original authority construction, normal effects and invoked guard captures')
    # The SIMD worker uses the exact same three-pointer publication/take ABI as
    # the reviewed SHA-256 worker, with its own closed symbol/reference scan.
    published=allocations.publication(bodies,'simd256')
    return dict(function=n['executor'],publication=published,lifetime_edges=lifetime_edges(bodies,assembly,n),
        physical_allocations=geometry(bodies,assembly,n,caller),receiver_bridge=bridge(bodies,n,caller,receiver),
        original_payload_and_authority_allocations_joined=True,
        conditional_page_payload_frame_nonoverlap_checked=True,
        serialized_nonreentrant_transport_and_runtime_abi_required=True,
        nested_callee_private_frame_effects_and_pointer_cell_preservation_still_required=True,
        complete_private_frame_erasure_qualified=False)
