"""Saved four-lane worker entry, retained-page identity and buffer retirement."""
import windows_enclave_sha3_simd_owner as owner

resident,life,s,L=owner.resident,owner.life,owner.s,owner.L


def names(bodies):
    n={role:s.one(bodies,p) for role,p in (
        ('receive',r'^_RNvCs.*keccak_simd_worker7receive$'),
        ('clear',r'^_RNvM.*keccak_simd_worker.*7Buffers5clear$'),
        ('drop',r'^_RINv.*drop_glue.*keccak_simd_worker.*7Buffers.*$'))}
    prefix=n['receive'].removesuffix('7receive')
    return n|{'live':prefix+'4LIVE','identity':prefix+'9LIVE_PAGE.0',
              'new':resident.names(bodies)['new']}


def page_clear(label):
    return ['xorl %eax, %eax']+[v.replace('%rdi','%rsi') for v in resident.page_clear(label)]


def buffers():
    return L(f'''pushq %rsi|subq $32, %rsp|movq %rcx, %rsi|addq $12288, %rcx|
        movl $384, %edx|callq {life.ZERO}|movl $12288, %edx|movq %rsi, %rcx|
        addq $32, %rsp|popq %rsi|jmp {life.ZERO}''')


def worker(n):
    live,page=n['live'],n['identity']
    code=L(f'''pushq %r15|pushq %r14|pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx|
        movl $12744, %eax|callq __chkstk|subq %rax, %rsp|testq %rdx, %rdx|
        setne %al|testl $4095, %edx|sete %r10b|testb %r10b, %al|je .B1|
        movq %r9, %rax|subq %r8, %rax|setb %r10b|cmpq $-4097, %rdx|ja .B1|
        testb %r10b, %r10b|jne .B1|cmpq $65536, %rax|jne .B1|
        leaq 4096(%rdx), %rax|cmpq %r8, %rax|seta %al|cmpq %rdx, %r9|
        seta %r10b|testb %r10b, %al|jne .B1|movq {live}(%rip), %rsi|
        testq %rcx, %rcx|je .B8|testq %rsi, %rsi|je .B11|
        cmpq %rdx, {page}(%rip)|jne .B49|cmpq $3, %rcx|jne .B23|
        movq {live}+16(%rip), %rdi|movq $0, {live}(%rip)''')
    code+=owner.clear('rdi')+page_clear(21)+L(f'''movq $0, {page}(%rip)|movl $4, %esi|
        jmp .B46|.B1:|movl $200, %esi|cmpq $0, {live}(%rip)|je .B46|
        movq {live}+16(%rip), %rdi''')+owner.clear('rdi')
    code+=L(f'''.B46:|movq %rsi, %rax|addq $12744, %rsp|popq %rbx|popq %rbp|
        popq %rdi|popq %rsi|popq %r14|popq %r15|retq|.B8:|testq %rsi, %rsi|
        je .B12|movq {live}+16(%rip), %rsi''')+owner.clear('rsi')
    code+=L(f'''movl $201, %esi|jmp .B46|.B11:|movl $202, %esi|jmp .B46|
        .B49:|movq {live}+16(%rip), %rsi''')+owner.clear('rsi')
    code+=L(f'''movl $203, %esi|jmp .B46|.B12:|movl $4096, %r8d|
        movq %rdx, %rcx|movq %rdx, %rsi|xorl %edx, %edx|callq memset|
        leaq 40(%rsp), %rcx|movq %rsi, %rdi|movq %rsi, %rdx|callq {n['new']}|
        cmpq $0, 40(%rsp)|je .B13|movq 56(%rsp), %rax|movq %rax, 80(%rsp)|
        vmovups 40(%rsp), %xmm0|vmovaps %xmm0, 64(%rsp)|
        movq {live}(%rip), %rsi|testq %rsi, %rsi|je .B17|
        movq {live}+16(%rip), %rbx''')+owner.clear('rbx')+page_clear(16)
    code+=L(f'''.B17:|movq 80(%rsp), %rax|movq %rax, {live}+16(%rip)|
        vmovaps 64(%rsp), %xmm0|vmovups %xmm0, {live}(%rip)|
        movq %rdi, {page}(%rip)|movl $1, %esi|jmp .B46|.B23:|
        movq %r8, %r15|movq %rcx, %r14|leaq 64(%rsp), %rbx|movq %rbx, %rdi|
        subq $-12288, %rdi|setb %bpl|movl $12672, %r8d|movq %rbx, %rcx|
        xorl %edx, %edx|movq %r9, %rsi|callq memset|movq %rsi, %rax|
        movl $204, %esi|cmpq %rax, %rdi|ja .B48|testb %bpl, %bpl|je .B48|
        cmpq %rbx, %r15|ja .B48|cmpq $-385, %rdi|ja .B48|cmpq %rdi, %r15|
        ja .B48|leaq 12736(%rsp), %rcx|cmpq %rax, %rcx|ja .B48|
        movq %r14, %rcx|leaq 64(%rsp), %rdx|callq {n['receive']}|
        movl %eax, %ebx|testb %al, %al|jne .B31|movq {live}+16(%rip), %rsi''')
    code+=owner.clear('rsi')+L(f'''.B31:|leaq 64(%rsp), %rcx|callq {n['clear']}|
        movl $12292, %eax|movl $205, %esi|.B32:''')
    code+=[v for i in range(60,64) for v in (f'cmpb $0, {i}(%rsp,%rax)','jne .B48')]
    code+=L(f'''cmpq $12672, %rax|je .B37|cmpb $0, 64(%rsp,%rax)|
        leaq 5(%rax), %rax|je .B32|.B48:|movq {live}+16(%rip), %rdi''')
    code+=owner.clear('rdi')+L(f'''.B45:|leaq 64(%rsp), %rcx|callq {n['drop']}|
        jmp .B46|.B13:|movl $207, %esi|jmp .B46|.B37:|movl $3, %eax|.B38:|
        cmpq $12291, %rax|je .B43''')
    code+=[v for i in range(61,64) for v in (f'cmpb $0, {i}(%rsp,%rax)','jne .B48')]
    return code+L('''cmpb $0, 64(%rsp,%rax)|leaq 4(%rax), %rax|je .B38|jmp .B48|
        .B43:|leaq 64(%rsp), %rdx|movl $1, %r8d|movq %rdi, %rcx|
        callq PublicKeccakSimdObserve|cmpl $1, %eax|jne .B48|
        movabsq $4294967296, %rax|orq %rax, %r14|testb %bl, %bl|
        movl $206, %esi|cmovneq %r14, %rsi|jmp .B45''')


def readback_offsets():
    header=[]
    for counter in range(12292,12673,5):
        header.extend(range(60+counter,64+counter))
        if counter!=12672:header.append(64+counter)
    payload=[counter+i for counter in range(3,12291,4) for i in range(61,65)]
    s.require(header==list(range(12352,12736)) and payload==list(range(64,12352)),
              'worker successful readback covers every buffer byte exactly once')
    return dict(header=[12352,12736],payload=[64,12352],header_reads=len(header),payload_reads=len(payload))


def entry_admits(page,low,high):
    """Unsigned predicates emitted before any worker page dereference."""
    mask=(1<<64)-1
    s.require(all(0<=v<=mask for v in (page,low,high)),'u64 entry operands')
    # setb from high-low captures underflow. The page+4096 limit is unsigned.
    return (page!=0 and page&4095==0 and page<=mask-4096 and high>=low
            and (high-low)&mask==65536 and not (page+4096>low and high>page))


def cleanup_paths(body,n):
    """Direct-CFG retirement obligations independent of full-body equality."""
    checks={
        'request_drop':('.B23',['callq '+n['drop']]),
        'received_buffers_clear':('.B31',['leaq 64(%rsp), %rcx','callq '+n['clear']]),
        'failed_bounds_readback_observer_quarantine':('.B48',owner.clear('rdi')),
        'failed_bounds_readback_observer_drop':('.B48',['callq '+n['drop']]),
        'observed_request_drop':('.B43',['callq '+n['drop']])}
    return {key:s.normal_returns(body,start,event) for key,(start,event) in checks.items()}


def inspect(bodies,ir,construction,checked_owner):
    n=names(bodies)
    s.require(construction['function']==n['new'] and
        construction['publication_after_authority_and_owner_initialization'] and
        construction['constructor_failure_clears_all_page_bytes'],'reviewed resident construction')
    s.require(construction['placement']['owner_page_span']==[24,1136] and
        construction['placement']['authority_page_span']==[0,24],'resident page subobjects')
    s.require(checked_owner['owner_authority_offset']==64 and
        checked_owner['rejected_operation_clears_output_and_quarantines'],'reviewed owner retirement')
    expected=worker(n)
    s.require(life.code(bodies['RetainedWork'])==expected,'complete SIMD retained worker')
    for role in ('clear','drop'):
        s.require(life.code(bodies[n[role]])==buffers(),'complete SIMD buffer retirement '+role)
    target='"target-cpu"="x86-64" "target-features"="'+resident.session.zero.SIMD_FEATURES+'"'
    abi='define noundef range(i64 4294967296, 208) i64 @RetainedWork('+(
        'i64 noundef %operation, ptr noundef %page, i64 noundef %low, i64 noundef %high, '
        'i64 noundef %_output) unnamed_addr { nounwind uwtable '+target+
        ' } personality ptr @__CxxFrameHandler3 {')
    s.require(life.reuse.abi(ir,'RetainedWork')==abi,'exact SIMD retained entry ABI')
    for role,arg in (('clear','self'),('drop','_1')):
        abi=f'define internal fastcc void @{n[role]}('+(
            f'ptr noalias nofree noundef nonnull dereferenceable(12672) %{arg}) unnamed_addr '+
            '{ nofree norecurse nounwind uwtable '+target+' } {')
        s.require(life.reuse.abi(ir,n[role])==abi,'exclusive full buffer retirement ABI')
    paths=cleanup_paths(bodies['RetainedWork'],n)
    return dict(functions=n,instruction_positions=len(expected),
        buffers_bytes=12672,worker_frame_bytes=12744,buffer_readback=readback_offsets(),
        post_buffer_construction_normal_return_sites=paths['request_drop'],cleanup_path_obligations=paths,
        page_bytes=4096,page_alignment=4096,stack_window_bytes=65536,
        page_stack_nonoverlap_checked=True,live_identity_checked_before_receive=True,
        constructor_triple_copied_without_changing_page_authority_owner=True,
        live_disarmed_before_close_clear=True,close_erases_page_before_identity_reset=True,
        receiver_failure_quarantines_then_retires_buffers=True,
        bounds_readback_and_observe_failure_quarantine_then_drop=True,
        return_after_buffer_drop_on_all_normal_request_paths=True,
        serialized_nonrecursive_C_entry_and_live_page_residency_required=True,
        receiver_must_not_mutate_live_metadata=True,shared_memory_runtime_semantics_required=True,
        fatal_abort_cleanup_claimed=False,receiver_nested_call_lifetimes_qualified=False,
        private_frame_erasure_qualified=False,shared_completion_package=8)
