"""TupleHash export, retirement and finite private-storage assignments."""
import re
import windows_enclave_tuple_shapes as t
import windows_enclave_tuple_transfers as x

s=t.s


def worker(bodies,lane):
    body=bodies['RetainedWork'];drop=s.one(bodies,r'worker7BuffersE')
    start='.B11' if lane=='scalar' else '.B33'
    count=s.normal_returns(body,start,['callq '+drop])
    header=96 if lane=='scalar' else 112
    s.sequences(bodies[drop],[f'movl ${header}, %edx|callq '+s.ZERO,'movl $1024, %edx','jmp '+s.ZERO])
    receiver=s.one(bodies,r'worker7receive$');body=bodies[receiver]
    if lane=='scalar':
        s.sequences(body,['cmpq 2176(%r14), %r15|jne .B63|cmpq 2192(%r14), %rdi|'
            'jne .B63|cmpb %bl, 2203(%r14)|jne .B63',
            'callq PublicTupleOutput|testl %eax, %eax|je .B58',
            'movl $1024, %edx|movq %rbx, %rcx|callq '+s.ZERO+'|movq $0, 2192(%r14)|movb $0, 2203(%r14)',
            'movb $5, %al|cmpb $7, %sil|je .B60|movq %r14, %rcx|callq '+t.owner(bodies,'clear')+'|xorl %eax, %eax'])
    else:
        s.sequences(body,['cmpq 2032(%rcx), %rax|jne .B31','cmpq 2048(%rcx), %rax|jne .B31',
            'cmpb 2066(%rcx), %al|jne .B31',
            'callq PublicTupleOutput|testl %eax, %eax|jne .B30|movq 2056(%rdi), %rcx|callq '+s.one(bodies,r'15check_authority$'),
            'movl $1024, %edx|movq %rdi, %rcx|callq '+s.ZERO+'|movq $0, 2048(%rdi)|movb $0, 2066(%rdi)',
            'movb $5, %al|cmpb $7, %bl|je .B29|movq %rdi, %rcx|callq '+t.owner(bodies,'clear')+'|xorl %eax, %eax'])
    return dict(buffer_return_sites=count,header_bytes=header,payload_bytes=1024,
                export_exact_identity_width_tail=True,output_cleared_after_copy=True,
                more_resumes_reader=True,terminal_export_returns_empty=True,
                post_copy_authority_checked=(lane=='avx2'))


def full_page(bodies,lane):
    if lane=='scalar':
        name='RetainedWork';body=bodies[name];base,index,start='rcx','rdx','.B7'
        s.sequences(body,['movq $0, _RNvCsioyi6nyfLbb_19tuple_stream_worker4LIVE.0(%rip)|'
                          'xorl %edx, %edx|movl $4, %eax'])
        s.sequences(body,['callq '+t.owner(bodies,'quarantine'),'callq '+x.state_drop(bodies,lane)])
    else:
        name=s.one(bodies,r'Resident.*Drop4drop$');body=bodies[name];base,index,start='rsi','rax','.B5'
        s.sequences(body,['leaq 1024(%rdi), %rcx|callq '+s.one(bodies,r'drop_glue.*tuple_accelerated_state5StateE'),
            'movl $1, %edx|movq %rbx, %rcx|callq '+s.ZERO+'|movb $0, 2065(%rdi)|xorl %eax, %eax'])
    event=[f'movb $0, '+('' if n==0 else str(n))+f'(%{base},%{index})' for n in range(8)]
    event += [f'addq $8, %{index}',f'cmpq $4096, %{index}','jne '+start]
    s.sequences(body,['|'.join(event)]);s.normal_returns(body,start,event)
    if lane=='avx2':
        new=s.one(bodies,r'Resident3new$');b=bodies[new]
        s.sequences(b,['leaq 32(%rdi), %r15',
            'movq %rdi, (%rsi)|movq %rdi, 8(%rsi)|movq %r15, 16(%rsi)'])
        failure=[l.replace('%rsi,%rax','%rdi,%rax').replace('jne .B5','jne .B2') for l in event]
        s.sequences(b,['|'.join(failure)]);s.normal_returns(b,'.B2',failure)
    return dict(bytes=4096,owner_offset=0 if lane=='scalar' else 32,
                owner_bytes=2208 if lane=='scalar' else 2080,
                active_objects_destroyed_before_page_clear=True,inactive_bytes_cleared_on_retirement=True)


def scalar_panic(bodies,ir,lane):
    if lane!='scalar': return dict(panic_functions=[])
    name=s.one(bodies,r'Packer6append$');body=bodies[name]
    panic=s.one(bodies,r'panic_const_add_overflow$');fmt=s.one(bodies,r'panicking9panic_fmt$')
    abort=s.one(bodies,r'rust_begin_unwind$')
    s.sequences(body,['movq 8(%r8), %r14|leaq -1(%r14), %r15|xorl %ecx, %ecx',
        '.B16:|cmpq %rcx, %r14|je .B13|movq %rcx, %r12|incq %r12|je .B18',
        'movq %r12, %rcx|cmpb $-1, %al|je .B16',
        '.B18:|callq '+panic+'|ud2'])
    for caller,callee in ((panic,fmt),(fmt,abort),(abort,'PublicProbeAbort')):
        s.sequences(bodies[caller],['callq '+callee+'|ud2'])
        s.require('retq' not in s.lines(bodies[caller]),'fail-stop is never a normal cleanup return')
    abi=x.reuse.c.reuse.abi(ir,name)
    s.require('readonly align 8 captures(none) dereferenceable(32) %2' in abi,
              'typed private bit-string borrow, not a foreign slice entry')
    # enumerate increments an index only after index != len. For a valid Rust
    # byte slice len <= isize::MAX, index+1 <= len <= isize::MAX, not u64::MAX.
    # Worker decode further restricts supplied payloads to 1024; encoded suffix
    # and retained output lengths are bounded independently by prior checks.
    return dict(panic_functions=[panic,fmt,abort],source='typed slice enumerate increment',
                valid_slice_maximum=2**63-1,public_payload_maximum=1024,
                overflow_unreachable_for_valid_slice=True,abort_cleanup_claim=False)


def error_cleanup(bodies,lane):
    # These exact post-guard clear sequences are copied into every returning
    # failed operation. Guard decision/revocation paths are separately bound
    # and exercised by the compiled cancellation/revocation/unwind campaigns.
    result={}
    rows=[('begin','rsi'),('rehash','rsi'),('custom','rsi'),('finish_custom','rsi'),
          ('begin_item','rsi'),('fragment','rsi'),('finish_item','rsi'),('finish','rsi'),('squeeze','rsi')]
    if lane=='avx2':
        rows=[(n,{'begin':'rdi','rehash':'rdi','custom':'r14','finish':'r14','squeeze':'r15'}.get(n,r)) for n,r in rows]
    for role,register in rows:
        name=t.owner(bodies,role);body=bodies[name];event=t.clear_event(lane,register)
        # Retaining EAX across the final metadata writes does not alter erasure.
        before=event[:-1]
        if role=='begin_item':
            s.sequences(body,[f'leaq {t.offsets(lane)[5]}(%rsi), %r14'])
            before=['movl $1, %edx','movq %r14, %rcx']+before[2:]
        if role=='finish_item':
            s.sequences(body,[f'leaq {t.offsets(lane)[0]}(%rsi), %rdi'])
            before=before[:-3]+['movl $16, %edx','movq %rdi, %rcx','callq '+s.ZERO]
        if lane=='avx2' and role=='finish_custom': before=before[:2]+['vzeroupper']+before[2:]
        s.sequences(body,['|'.join(before),event[-1]])
        text='\n'.join(s.lines(body));sequence='\n'.join(before)
        s.require(text.count(sequence)==1,'one exact failed-operation cleanup block')
        transformed=text.replace(sequence,'reviewed_error_cleanup:\n'+sequence)
        result[name]=s.normal_returns(transformed,'reviewed_error_cleanup',before)
    return dict(returning_error_clear_blocks=result,full_allocation_erasure_claim=False)


def inspect(bodies,ir,lane):
    return dict(worker=worker(bodies,lane),page=full_page(bodies,lane),
                fail_stop=scalar_panic(bodies,ir,lane),errors=error_cleanup(bodies,lane),
                destructors=destructors(bodies,lane))


def destructors(bodies,lane):
    name=t.owner(bodies,'quarantine') if lane=='scalar' else s.one(bodies,r'Resident10quarantine$')
    s.sequences(bodies[name],[f'movb $8, {t.offsets(lane)[6]}(%rsi)'])
    s.normal_returns(bodies[name],name,t.clear_event(lane))
    guard=s.one(bodies,r'Operation.*Drop4drop$')
    s.sequences(bodies[guard],['testb $1, %dl|jne '+('.B2' if lane=='scalar' else '.B6')])
    if lane=='scalar':
        body=bodies[x.state_drop(bodies,lane)]
        wipe=s.one(bodies,r'HardenedFips202OwnerKj88_E4wipe')
        s.sequences(body,['cmpq $3, %rax|ja .B2',
            '.B5:|leaq 16(%rsi), %rbx|cmpb $1, 83(%rsi)|jne .B8',
            'leaq 84(%rsi), %rdi|movq %rdi, %rcx|callq '+wipe,
            '.B8:|movb $0, 83(%rsi)|leaq 80(%rsi), %rcx|movl $1, %edx|callq '+s.ZERO,
            'movw $768, 81(%rsi)|movb $0, 1124(%rsi)',
            '.B2:|addq $2, %rsi|.B3:|movq %rsi, %rcx','jmp '+wipe])
        # Expand the already-reproduced wipe tail call only for intraprocedural
        # return enumeration. Original body/reference/target bindings remain.
        tail='jmp '+wipe
        s.require(s.lines(body).count(tail)==1,'one reviewed destructor tail target')
        cfg='\n'.join(s.lines(body)).replace(tail,'callq '+wipe+'\nretq')
        s.normal_returns(cfg,'.B5',['leaq 80(%rsi), %rcx','movl $1, %edx','callq '+s.ZERO])
    else:
        body=bodies[s.one(bodies,r'drop_glue.*tuple_accelerated_state5StateE')]
        s.sequences(body,['movq 944(%rcx), %rax|cmpq $2, %rax|je .B6|cmpl $-1, %eax|je .B6',
            'leaq 624(%rcx), %rdi|movq %rdi, %rcx|callq '+s.one(bodies,r'Memory4wipe$'),
            'movb $-1, 938(%rsi)|movb $3, 962(%rsi)|movq %rdi, %rcx|vzeroupper|callq '+s.one(bodies,r'Memory4wipe$')])
        s.normal_returns(body,'.B4',['movq %rsi, %rcx','callq '+s.one(bodies,r'KeccakScratch4wipe$')])
    return dict(quarantine_always_clears=True,active_variants_use_typed_drop=True,
                inactive_padding='page retirement',unwind_guarantee='invoked funclets only')


def assignments(records,reused):
    # Roles record the bounded source/emitted-path review. They are not a proof
    # obtained by merely matching a function name. Frozen full bodies, contexts
    # and references must already have passed the enclosing checks.
    roles={
        'worker_and_wire':[r'^RetainedWork$',r'worker7receive$',r'Header6decode$'],
        'owner_lifecycle':[r'Owner\d+(?:begin|rehash|custom|finish_custom|begin_item|fragment|finish_item|finish|squeeze|clear|cancel|operation|quarantine)$'],
        'state_and_guards':[r'drop_glue.*StateE',r'Operation.*Drop4drop$',r'State\d+(?:setup|squeeze|finish_xof)$'],
        'resident':[r'Resident\d+(?:new|quarantine)$',r'Resident.*Drop4drop$'],
        'bit_framing':[r'Packer\d+(?:bits|append)$'],
        'bounded_unreachable_overflow_failstop':[r'panic_const_add_overflow$',r'panicking9panic_fmt$',r'rust_begin_unwind$']}
    result={}
    for role in ('exact_body_reference_abi_reuse','explicit_abi_changes','renamed_helpers'):
        for name in reused[role]:
            s.require(name in records and name not in result,'unique actual reproduced helper')
            result[name]='reproduced_kmac_sha3/'+role
    for name in sorted(set(records)-set(result)):
        match=['invoked_cleanup_funclet'] if name.startswith('?dtor$') else [
            role for role,patterns in roles.items() if any(re.search(p,name) for p in patterns)]
        s.require(len(match)==1,'one reviewed TupleHash function assignment: '+name)
        result[name]=match[0]
    s.require(set(result)==set(records),'complete finite TupleHash review assignment')
    return result


def storage(records,sizes,vectors,runtime,lane):
    if 'memcmp' in runtime:
        s.require(lane=='avx2' and len(runtime['memcmp']['callers'])==1 and
            runtime['memcmp']['callers'][0].endswith('operations12known_answer'),
            'comparison handles only public startup KAT')
    return dict(resident=dict(bytes=4096,owner_bytes=2208 if lane=='scalar' else 2080,
        owner_offset=0 if lane=='scalar' else 32,active_cleanup='typed state and pending/output/count clears',
        inactive_cleanup='full volatile page retirement',page_admission_and_release_package=8),
        transient=dict(window_bytes=65536,frames={n:dict(local_bytes=sizes[n],incoming_vector_saves=vectors[n],
            cleanup='enclosing window; typed scratch cleanup is additional') for n in sorted(records)},
            aggregate_moves_individually_erased=False,shared_runtime_frames_included=False,
            complete_window_reclamation_package=8),
        transport=dict(input='bounded owned worker buffer',export='explicit TupleHash digest/XOF export',
            source_and_declassified_host_buffers_protected=False,shared_sdk_boundary_package=8),
        mutable_globals='resident identity only; no secret payload allocation',arbitrary_exception_cleanup_qualified=False)
