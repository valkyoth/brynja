"""Join saved SIMD page/input owners to actual nested caller allocations.

Conditional on the linked serialized transport and its admitted stack window:
this is not an OS-allocation, reentrancy, erasure, or whole-image qualification.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_allocation_stack as stack
import windows_enclave_sha2_simd_constructor as constructor
import windows_enclave_sha2_simd_worker as worker
import windows_enclave_sha2_simd_authority as authority
import windows_enclave_sha2_effect_placement as placement
import windows_enclave_sha2_simd_digest as digest


def interval(low,size,limit):
    s.require(type(low) is type(size) is type(limit) is int and
              0<=low and 0<size and low+size<=limit,'complete nonwrapping allocation extent')
    return [low,low+size]


def disjoint(ranges):
    for i,a in enumerate(ranges):
        s.require(len(a)==2 and all(type(v) is int for v in a) and a[0]<a[1],'nonempty concrete extent')
        for b in ranges[:i]:s.require(a[1]<=b[0] or b[1]<=a[0],'distinct live allocation extents')


def live_symbols(bodies):
    text='\n'.join(s.lines(bodies['RetainedWork']))
    live=set(re.findall(r'(_RNv\w+worker4LIVE)(?:\+16)?\(%rip\)',text))
    page=set(re.findall(r'(_RNv\w+worker9LIVE_PAGE\.0)\(%rip\)',text))
    s.require(len(live)==len(page)==1,'one private resident and page identity')
    return live.pop(),page.pop()


def publication(bodies,lane):
    live,page=live_symbols(bodies);body=bodies['RetainedWork'];narrow=lane=='simd256'
    new=s.one(bodies,r'Resident3new$');done=46 if narrow else 47
    # Complete temporary bridge: page is preserved in RDI across construction,
    # and all three constructor-result pointers are copied before publication.
    s.sequences(body,[
        '.B12:|movl $4096, %r8d|movq %rdx, %rcx|movq %rdx, %rsi|xorl %edx, %edx|callq memset|'
        'leaq 40(%rsp), %rcx|movq %rsi, %rdi|movq %rsi, %rdx|callq '+new+'|'
        'cmpq $0, 40(%rsp)|je .B13|movq 56(%rsp), %rax|movq %rax, 80(%rsp)|'
        'vmovups 40(%rsp), %xmm0|vmovaps %xmm0, 64(%rsp)|'
        f'movq {live}(%rip), %rsi|testq %rsi, %rsi|je .B17',
        f'.B17:|movq 80(%rsp), %rax|movq %rax, {live}+16(%rip)|'
        f'vmovaps 64(%rsp), %xmm0|vmovups %xmm0, {live}(%rip)|'
        f'movq %rdi, {page}(%rip)|movl $1, %esi|jmp .B{done}'])
    # No other body can take a global metadata address or mutate the globals.
    # Known references are direct loads, identity checks, publication or take().
    writes=[];refs=0;receive=worker.role(bodies,'receive')
    allowed={f'movq $0, {live}(%rip)',f'movq $0, {page}(%rip)',
             f'movq %rax, {live}+16(%rip)',f'vmovups %xmm0, {live}(%rip)',f'movq %rdi, {page}(%rip)'}
    read=re.compile(r'(?:movq '+re.escape(live)+r'(?:\+16)?\(%rip\), %\w+|'
                    r'cmpq (?:\$0, '+re.escape(live)+r'|%rdx, '+re.escape(page)+r')\(%rip\))')
    for name,text in bodies.items():
        for line in s.lines(text):
            if live not in line and page not in line:continue
            refs+=1
            s.require(name in ('RetainedWork',receive),'resident metadata never escapes to nested workers')
            if line in allowed:
                s.require(name=='RetainedWork','only outer serialized worker mutates resident metadata')
                writes.append(line)
            else:s.require(read.fullmatch(line) is not None,'closed direct resident-metadata reference population')
    s.require(len(writes)==len(allowed) and set(writes)==allowed,'exact publication/take/retirement writes')
    return dict(resident=live,page=page,metadata_references=refs,metadata_writes=len(writes),
                authority_offset=0,owner_offset=24,serialized_no_reentry_contract_required=True)


def lifetime_edges(bodies,assembly,lane):
    lines=s.lines(bodies['RetainedWork']);graph=stack.edges(lines,assembly)
    receive=worker.role(bodies,'receive');consume=lines.index('callq '+receive)
    live,page=live_symbols(bodies);fail=47 if lane=='simd256' else 48
    checks=[f'cmpq %rdx, {page}(%rip)|jne .B{fail}',
            'testq %rcx, %rcx|je .B8','testq %rsi, %rsi|je .B11']
    # Every admission guard in the actual prefix has to succeed before receive.
    first=lines.index('testq %rdx, %rdx');end=lines.index(f'movq {live}(%rip), %rsi')
    guarded=[i for i in range(first,end) if lines[i].startswith(('je ','jne ','ja '))]
    s.require(len(guarded)==5,'complete page/window admission guard population')
    for sequence in checks:
        s.sequences(bodies['RetainedWork'],[sequence]);guarded.append(lines.index(sequence.split('|')[-1]))
    for at in guarded:stack.require_edge(graph,0,consume,(at,at+1))
    buffer_guards=[i for i in range(lines.index('.B23:'),consume) if lines[i].startswith(('je ','jne ','ja '))]
    s.require(len(buffer_guards)==6,'complete buffer-admission guard population')
    for at in buffer_guards:stack.require_edge(graph,0,consume,(at,at+1))
    at=lines.index('cmpq $3, %rcx');s.require(lines[at+1]=='jne .B23','operation three is retirement only')
    stack.require_edge(graph,0,consume,(at+1,lines.index('.B23:')))
    # Constructor publication and take/drop cannot subsequently use that page
    # in this invocation. No outside callback is permitted to reenter the worker.
    for label in ('.B12:', '.B17:'):
        s.require(consume not in stack.reachable(graph,lines.index(label)),
                  'construction/publication returns before any digest use')
    take=lines.index(f'movq $0, {live}(%rip)')
    s.require(consume not in stack.reachable(graph,take),'retired resident cannot reach digest use')
    return dict(admission_edges=len(guarded)+len(buffer_guards)+1,constructor_and_retirement_disjoint_from_use=True,
                consume=consume,nonreentrant_transport_and_OS_lifetime_required=True)


def caller_bridge(bodies,assembly,lane):
    narrow=lane=='simd256';name=worker.role(bodies,'receive');body=bodies[name]
    live,_=live_symbols(bodies);resident=authority.role(bodies,'resident')
    suffix=(f'movq 56(%rsp), %r8|movq 64(%rsp), %rax|movq {live}+16(%rip), %rdx|'
            'movq %rax, 32(%rsp)|leaq 208(%rsp), %rcx|movq %rsi, %r9|' if narrow else
            f'movq {live}+16(%rip), %rdx|movq 200(%rsp), %rax|movq %rax, 32(%rsp)|'
            'leaq 80(%rsp), %rcx|leaq 224(%rsp), %r9|movq 208(%rsp), %r8|')
    s.sequences(body,[suffix+'callq '+resident])
    lines=s.lines(body);graph=stack.edges(lines,assembly);consume=lines.index('callq '+resident)
    for at in range(consume-len(suffix.split('|'))+1,consume):
        stack.require_edge(graph,0,consume,(at,at+1))
    # The existing machine input-copy proof binds each source to its own 1024
    # byte slice and the complete typed descriptor construction. This bridge
    # now assigns those ABI arguments actual caller allocation coordinates.
    copies=worker.input_copies(bodies,lane)
    s.require(copies['lanes']==(8 if narrow else 4) and copies['exclusive_lane_stride']==1024,
              'same bounded typed lane-copy contract')
    prefix='PublicSha'+('256' if narrow else '512')+'SimdInput'
    sites=[i for i,line in enumerate(lines) if line=='callq '+prefix]
    offsets=[8192 if narrow else 4096]+[1024*i for i in range(8 if narrow else 4)]
    s.require(len(sites)==len(offsets),'every host-copy destination has an original payload origin')
    origins=[dict(call=at,payload_offset=off,
                  traversed_definitions=stack.pointer_origin(lines,graph,at,'rdx','rdx',off))
             for at,off in zip(sites,offsets,strict=True)]
    return dict(descriptors=[368,560] if narrow else [224,320],
                result=[208,240] if narrow else [80,112],owner_page_offset=24,
                source_contract='simd_worker.input_copies',copy_destination_origins=origins)


def geometry(bodies,assembly,lane,bridge):
    narrow=lane=='simd256';receive=worker.role(bodies,'receive');resident=authority.role(bodies,'resident')
    allocation=11992 if narrow else 12984;count=8 if narrow else 4
    digest.admission(bodies,lane);digest.staging(bodies,lane)
    inputs=[interval(64+1024*i,1024,8552 if narrow else 4328) for i in range(count)]
    header=interval(64+1024*count,288 if narrow else 160,8552 if narrow else 4328)
    disjoint(inputs+[header]);rows=[]
    for residue in (8,24):
        outer=stack.inspect(bodies['RetainedWork'],assembly,residue)
        _,call=stack.call(outer,receive);worker_sp=call['rsp']
        s.require(worker_sp==outer['low']==(-8600 if narrow else -4376),'fixed outer allocation at receive')
        middle_entry=-8;middle_mod=(residue+worker_sp-8)%32
        middle=stack.inspect(bodies[receive],assembly,middle_mod)
        _,call=stack.call(middle,resident);middle_sp=middle_entry+call['rsp']
        inner_entry=middle_sp-8;inner_mod=(residue+worker_sp+inner_entry)%32
        inner=stack.inspect(bodies[resident],assembly,inner_mod)
        _,call=stack.call(inner,authority.role(bodies,'owner'))
        s.require(call['rbx'] is not None and call['rsp']==call['rbx'],'resident allocation active at operation admission')
        base=inner_entry+call['rbx']
        descriptors=[middle_sp+v for v in bridge['descriptors']]
        result=[middle_sp+v for v in bridge['result']]
        local=[base,base+allocation]
        s.require(local[1]<=middle_sp-72,'aligned locals lie below caller home/return/register-save areas')
        disjoint(inputs+[header,descriptors,result,local])
        s.require(middle['low']==call_stack_low(lane),'fixed receive frame')
        layout=placement.placements(bodies,lane)
        concrete={name:[base+row['offset']+v for v in row['bounds']]
                  for name,row in layout.items() if row['root']=='resident-frame'}
        disjoint(list(concrete.values())+inputs+[header,descriptors,result])
        internal=({'inputs':[544,864],'workspace':[6688,11968],
                   'output_descriptors':[864,992],'output_scratch':[3936,4192]} if narrow else
                  {'inputs':[192,352],'output_descriptors':[352,416],'output_scratch':[1376,1632]})
        internal={name:[base+v for v in span] for name,span in internal.items()}
        s.require(all(local[0]<=lo<hi<=local[1] for lo,hi in internal.values()),'typed resident subobjects inside live allocation')
        disjoint(list(internal.values())+([] if narrow else list(concrete.values()))+inputs+[header,descriptors,result])
        if not narrow:
            _,child=stack.call(inner,authority.role(bodies,'executor'))
            s.require(child['rsp']==call['rbx'],'wide child called from same live resident frame')
        rows.append(dict(worker_entry_mod32=residue,receive_rsp=middle_sp,resident_rbx=base,
                         resident_locals=local,typed_descriptors=descriptors,result=result,objects=concrete,
                         resident_subobjects=internal))
    return dict(relative_to='RetainedWork RSP at receive call',input_slices=inputs,header=header,
                alignment_cases=rows,all_typed_arguments_disjoint_from_work_frames=True,
                worker_window_must_contain_nested_frames=True)


def call_stack_low(lane):return -696 if lane=='simd256' else -456


def inspect(bodies,assembly,lane):
    s.require(lane in ('simd256','simd512'),'known physical allocation route')
    created=constructor.inspect(bodies,lane);worker.entry(bodies,lane)
    s.require((created['authority_page_offset'],created['owner_page_offset'])==(0,24),
              'same actual placed authority/owner constructor')
    # Owner extents include all typed fields and alignment padding, not just
    # the output subobject. The whole page is retired, not independently freed.
    owner=interval(24,288 if lane=='simd256' else 296,4096)
    disjoint([[0,24],owner])
    lifecycle=publication(bodies,lane);edges=lifetime_edges(bodies,assembly,lane)
    bridge=caller_bridge(bodies,assembly,lane);layout=geometry(bodies,assembly,lane,bridge)
    return dict(page=dict(bytes=4096,authority=[0,24],owner=owner),publication=lifecycle,
                lifetime_edges=edges,caller_bridge=bridge,stack_geometry=layout,
                constructor_result_and_worker_use_joined=True,
                conditional_physical_separation=True,
                prerequisites=['serialized nonreentrant linked transport retains page through operation three',
                    'OS-admitted worker window contains all nested frames and callee stack extents',
                    'Win64 nonvolatile/call ABI, __chkstk and reviewed helper memory effects'],
                whole_frame_cleanup_pending=True,whole_frame_qualified=False)
