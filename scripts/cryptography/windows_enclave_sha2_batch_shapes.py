"""Selected SHA-2 batch admission/cleanup contracts, not full chain closure."""
import windows_enclave_kmac_shapes as s
import windows_enclave_kmac_reuse as reuse
import windows_enclave_sha2_batch_lifecycle as lifecycle
import windows_enclave_sha_ni_state as state
import windows_enclave_sha2_batch_state as batch_state
import windows_enclave_sha2_batch_admission as placement
import windows_enclave_sha2_batch_iv as iv
import windows_enclave_sha2_simd_authority as simd_authority
import windows_enclave_sha2_simd_storage as simd_storage
import windows_enclave_sha2_simd_kernel as simd_kernel
import windows_enclave_sha2_simd_worker as simd_worker
import windows_enclave_sha2_simd_constructor as simd_constructor
import windows_enclave_sha2_simd_digest as simd_digest
import windows_enclave_sha2_simd_commit as simd_commit
import windows_enclave_sha2_simd_provenance as simd_provenance


def owner(bodies,role): return s.one(bodies,r'Owner\d+'+role+'$')


def abi(bodies,ir,lane):
    size,align={'scalar':(1784,8),'sha_ni':(2624,16),'simd256':(288,8),'simd512':(296,8)}[lane]
    rows={owner(bodies,'operation'):[f'align {align} dereferenceable({size}) %1',
        'range(i8 0, '+('5' if lane in ('scalar','sha_ni') else '2')+') %3']}
    if lane in ('scalar','sha_ni'):
        rows[owner(bodies,'begin')]=[f'align {align} dereferenceable({size}) %0',
            'readonly align 8 captures(none) dereferenceable(64) %2']
        for role in ('update','finish'):
            rows[owner(bodies,role)]=['range(i64 0, 1025) %4',f'align {align} dereferenceable({size}) %0']
        if lane=='sha_ni':
            rows[s.one(bodies,r'static_execution.*operations12known_answer$')]=['noundef zeroext i1']
            rows[s.one(bodies,r'Resident3new$')]=['align 8 captures(none) dereferenceable(24) %0',
                'align 4096 dereferenceable(4096) initializes((0, 16)) %1']
            rows[s.one(bodies,r'state.*State6finish$')]=[
                'align 16 captures(address) dereferenceable(2000) %0',
                'readonly align 8 captures(none) dereferenceable(32) %1',
                'range(i64 28, 33) %3']
    else:
        rows[s.one(bodies,r'Resident3new$')]=[
            'writeonly align 8 captures(none) dereferenceable(24) %0',
            'ptr noalias nofree noundef nonnull align 4096 dereferenceable(4096) %1']
        rows[s.one(bodies,r'Resident6digest$')]=[
            f'readonly align 8 captures(none) dereferenceable({192 if lane=="simd256" else 96}) %2']
        rows[s.one(bodies,r'Kernel8compiled$')]=['(i1 noundef zeroext %0)']
        rows[s.one(bodies,r'Session14compress_bytes$')]=[
            'nonnull dereferenceable(256) %0',
            'readonly captures(address, read_provenance) dereferenceable(512) %1',
            f'align 32 dereferenceable({2752 if lane=="simd256" else 3264}) %2']
        rows[s.one(bodies,r'engine7padding$')]=[
            f'align 32 dereferenceable({5280 if lane=="simd256" else 5760}) %0',
            'align 8 captures(none) dereferenceable(32) %1',
            'align 8 captures(none) dereferenceable(32) %2']
        if lane=='simd512':
            rows[s.one(bodies,r'Executor13digest_secret$')]=[
                'writeonly align 8 captures(none) dereferenceable(104) %0',
                'ptr noundef nonnull align 8 captures(none) %1',
                'readonly align 8 captures(address_is_null) dereferenceable(160) %2',
                'readonly align 8 captures(none) dereferenceable(64) %3',
                'align 32 dereferenceable(5760) %4',
                'align 8 captures(none) dereferenceable(32) %5']
    for name,tokens in rows.items():
        text=reuse.abi(ir,name)
        for token in tokens: s.require(token in text,'batch private ABI '+token)
    return rows


def sequential(bodies,lane):
    scalar=lane=='scalar';phase=1782 if scalar else 2616;seq=592 if scalar else 2600
    pointer='rdi' if scalar else 'rsi';destination='rsi' if scalar else 'rdi'
    op=bodies[owner(bodies,'operation')]
    s.sequences(op,[f'cmpb %r9b, {phase}(%rdx)|jne '+('.B3' if scalar else '.B10'),
        f'movq {seq}(%{pointer}), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B2',
        f'movq %r8, {seq}(%{pointer})|movq %{pointer}, (%{destination})'])
    output=80 if scalar else 2080
    event=[f'leaq {output}(%{pointer}), %rcx','movl $512, %edx','callq '+s.ZERO]
    starts=('.B3','.B8') if scalar else ('.B7','.B13','.B19')
    returns={label:s.normal_returns(op,label,event) for label in starts}
    clear=owner(bodies,'clear')
    s.normal_returns(bodies[clear],clear,[f'leaq {output}(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO])
    if scalar:
        s.sequences(op,['movq $0, (%rdi)|movq $0, 600(%rdi)|movw $4, 1782(%rdi)'])
        update=bodies[owner(bodies,'update')];finish=bodies[owner(bodies,'finish')]
        s.sequences(update,['cmpl $1, (%rbx)|jne .B13|cmpq %rdi, 8(%rbx)|jne .B13',
            'movq 600(%rbx), %rax|subq %r8, %rax|jae .B6',
            '.B6:|movq %rax, 600(%rbx)|movzbl 608(%rbx), %eax|cmpq $6, %rax|ja .B13'])
        s.sequences(finish,['cmpl $1, (%r15)|jne .B26|cmpq %rsi, 8(%r15)|jne .B26',
            'movq 600(%r15), %rax|movb $3, %dil|subq %r12, %rax|jb .B26',
            'movq %rsi, %r12|shlq $6, %r12',
            'callq '+s.one(bodies,r'state.*State6finish$')+'|movl %eax, %edi|cmpb $-1, %al|jne .B26',
            'orb %al, 1783(%r15)|movq $0, (%r15)|movb $1, 1782(%r15)'])
    else:
        s.sequences(op,['movq 2592(%rsi), %rax|cmpb $0, 9(%rax)|jne .B4|cmpb $1, 8(%rax)|jne .B4',
            'movb $2, 8(%rax)|movq $3, (%rax)',f'movb $4, {phase}(%rsi)'])
    return dict(exact_nonwrapping_sequence=True,phase_checked=True,output_bytes=512,
        rejection_return_sites=returns,authority_identity_and_health_checked=not scalar,
        scalar_active_slot_budget_and_result_commit_checked=scalar,
        full_state_transfer_and_lane_review_pending=True)


def simd(bodies,lane):
    width=256;phase=280 if lane=='simd256' else 288;seq=272 if lane=='simd256' else 280
    out=16 if lane=='simd256' else 24
    body=bodies[owner(bodies,'operation')]
    s.sequences(body,[f'cmpb %r9b, {phase}(%rdx)|jne .B15',
        f'movq {seq}(%rbx), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B2',
        f'movq %rdi, {seq}(%rbx)|movq %rbx, (%rsi)|movb $0, 8(%rsi)',
        f'movb $2, {phase}(%rbx)'])
    event=[f'leaq {out}(%rbx), %rcx',f'movl ${width}, %edx','callq '+s.ZERO]
    returns={label:s.normal_returns(body,label,event) for label in ('.B15','.B10')}
    s.sequences(body,['cmpb $1, 16(%rax)|jne .B9','movb $0, 16(%rax)'])
    return dict(exact_nonwrapping_sequence=True,phase_checked=True,output_bytes=width,
        rejection_return_sites=returns,authority_revoked_on_rejection=True,
        callback_and_lane_engine_review_pending=True)


def callback_targets(bodies,lane):
    """Constructor/leaf contracts only; not all indirect callsite provenance."""
    compiled=s.one(bodies,r'Kernel8compiled$')
    s.sequences(bodies[compiled],['movl %ecx, %eax|xorb $1, %al|retq'])
    s.require(len(s.lines(bodies[compiled]))==5,'complete typed capability leaf')
    names=[n for n in bodies if 'Owner6digests2_0' in n]
    s.require(len(names)==2,'closure and callable vtable thunk')
    for name in names:
        s.sequences(bodies[name],['xorl %eax, %eax|retq'])
        s.require(len(s.lines(bodies[name]))==4,'complete stateless false callback')
    factory=s.one(bodies,r'Resident3new$');body=bodies[factory]
    s.sequences(body,[
        'leaq '+compiled+'(%rip), %rax|movq %rax, 8(%rdi)|movw $1, 16(%rdi)',
        'xorl %ecx, %ecx|callq '+compiled+'|testb %al, %al|je .B13',
        'movq %rdi, '+('32' if lane=='simd256' else '40')+'(%rdi)',
        'movq %rdi, (%rsi)|movq %rdi, 8(%rsi)|movq '+
            ('%rbx' if lane=='simd256' else '%rax')+', 16(%rsi)|jmp .B17'])
    # Both constructor failures erase all 4096 backing bytes. This does not
    # erase the KAT frame or prove the later live-page retirement path.
    loop='|'.join(['movb $0, '+('' if i==0 else str(i))+'(%rdi,%rax)' for i in range(8)])
    for label in ('.B9','.B14'):
        s.sequences(body,[label+':|'+loop+'|addq $8, %rax|cmpq $4096, %rax|jne '+label])
    s.sequences(body,['xorl %eax, %eax|.p2align 4|.B9:',
        '.B13:|movb $0, 16(%rdi)|xorl %eax, %eax|'+
        ('.p2align 4|' if lane=='simd256' else '')+'.B14:'])
    return dict(typed_capability_leaf=compiled,stateless_false_callbacks=names,
        constructor=factory,authority_callback_offset=8,authority_page_offset=0,
        owner_page_offset=24,constructor_failure_erases_page_bytes=4096,
        all_indirect_callsite_provenance_qualified=False)


def sha_ni_finalizer(bodies):
    """Review the changed 28..32-byte finalizer, not equality to streaming."""
    name=s.one(bodies,r'state.*State6finish$');body=bodies[name]
    wipe=state.life.wiping.WIPE;scratch=state.life.SCRATCH
    s.sequences(body,[
        'movq %r9, %rdi|movq %r8, %rbx|movq %rdx, %r15|movq %rcx, %rsi',
        'vxorps %xmm0, %xmm0, %xmm0|vmovups %ymm0, 32(%rsp)',
        'movzbl (%rcx), %ebp|leaq 16(%rcx), %rdx|leaq 64(%rsp), %rcx|'
        'movl $1984, %r8d|testb $1, %bpl|je .B7|vzeroupper|callq memcpy',
        '.B7:|vzeroupper|callq memcpy',
        '.B2:|leaq 32(%rsp), %rcx|movq %rdi, %rdx|callq '+s.ZERO+'|'
        'leaq 864(%rsp), %rcx|callq '+wipe+'|movl $8, %r14d',
        '.B11:|callq '+s.ZERO+'|leaq 864(%rsp), %rcx|callq '+wipe+'|jmp .B12',
        '.B12:|movb $-1, %r15b|cmpq $0, 128(%rsp)|je .B15',
        '.B14:|leaq 144(%rsp), %rcx|callq '+scratch,
        '.B15:|cmpb $-1, %r15b|je .B20',
        'testq %r14, %r14|movl $1, %r8d|cmovneq %r14, %r8|movq %rdi, %r9|'
        'cmoveq %r14, %r9|movq %rbx, %rcx|movq %rdi, %rdx|callq '+state.COPY,
        'cmpb $-1, %al|sete %bl|negb %bl|testq %r14, %r14|je .B18|'
        'movq %r14, %rcx|movq %rdi, %rdx|callq '+s.ZERO,
        '.B4:|leaq 1952(%rsp), %rdx|movl $32, %r8d|jmp .B5',
        '.B9:|leaq 1952(%rsp), %rdx|movl $28, %r8d',
        '.B5:|movq %r14, %rcx|callq '+state.BYTES+'|movzbl 112(%rsp), %r15d|'
        'leaq 864(%rsp), %rcx|callq '+wipe+'|cmpq $0, 128(%rsp)|jne .B14|jmp .B15',
        'testb $1, (%rsi)|je .B22|movb $6, %bl|testb $1, %bpl|jne .B19|jmp .B23',
        '.B22:|movb $6, %bl|testb $1, %bpl|je .B19',
        '.B23:|leaq 816(%rsi), %rcx|callq '+wipe+'|cmpq $0, 80(%rsi)|je .B19|'
        'addq $96, %rsi|movq %rsi, %rcx|callq '+scratch+'|jmp .B19'])
    for width,label in ((32,4),(28,9)):
        s.sequences(body,[f'cmpq ${width}, %rdi|jne .B2|leaq 64(%rsp), %rcx|'
            f'movl ${width}, %r8d|movq %r15, %rdx|callq '+state.ENGINE+'|'
            f'cmpb $-1, %al|je .B{label}|movzbl %al, %r14d|leaq 32(%rsp), %rcx|movl ${width}, %edx'])
    cleared=s.normal_returns(body,name,['leaq 32(%rsp), %rcx','movl $32, %edx','callq '+s.ZERO])
    owner_wiped=s.normal_returns(body,name,['leaq 864(%rsp), %rcx','callq '+wipe])
    return dict(function=name,exact_variant_widths=[28,32],engine_copy_bytes=1984,
        all_normal_returns_clear_staging=cleared,all_normal_returns_wipe_copied_owner=owner_wiped,
        scratch_wiped_if_present=True,engine_success_precedes_publication=True,
        moved_from_copies_individually_erased=False,arbitrary_os_unwind_qualified=False)


def sha_ni_finish_caller(bodies):
    body=bodies[owner(bodies,'finish')];finish=s.one(bodies,r'state.*State6finish$')
    s.sequences(body,[
        'cmpl $1, 2000(%r13)|jne .B24|cmpq %rsi, 2008(%r13)|jne .B24',
        'movq 2064(%rbp), %r15|movq 2608(%r13), %rax|movb $3, %dil|subq %r15, %rax|jb .B24',
        'movzbl 2072(%rbp), %r14d|movq %rax, 2608(%r13)|testq %r15, %r15|je .B10|'
        'leal -1(%r14), %eax|movb $4, %dil|cmpb $7, %al|ja .B24|cmpb $7, %r14b|ja .B9',
        'leaq -1(%r15), %rax|movb $-1, %dl|movl %r14d, %ecx|shrb %cl, %dl|'
        'addq %rbx, %rax|movq %rax, %rcx|callq '+s.one(bodies,r'12mask_is_zero$')+'|cmpl $1, %eax|jne .B24',
        '.B9:|movzbl %r14b, %eax|leaq (%rax,%r15,8), %rax|addq $-8, %rax',
        '.B10:|movb $4, %dil|testb %r14b, %r14b|jne .B24',
        'cmpq $7, %rsi|ja .B23|movq 2016(%r13,%rsi,8), %rax|cmpq $2, %rax|je .B17|'
        'cmpq $1, %rax|jne .B23|movl $28, %edi|jmp .B18',
        '.B17:|movl $32, %edi',
        'movq $2, (%r13)|movq $0, 8(%r13)',
        'movq %rsi, %r12|shlq $6, %r12',
        'leaq 2080(%r13,%r12), %r8',
        'leaq -96(%rbp), %rcx|leaq 1904(%rbp), %rdx|movq %rdi, %r9|callq '+finish,
        'movl %eax, %edi|cmpb $-1, %al|movq 1936(%rbp), %r13|movzbl 1951(%rbp), %r12d|jne .B24',
        'movb $1, %al|movl %esi, %ecx|shlb %cl, %al|orb %al, 2617(%r13)|'
        'movq $0, 2000(%r13)|movb $1, 2616(%r13)|movb $-1, %dil|jmp .B31'])
    return dict(active_slot_checked=True,budget_decrement_checked=True,canonical_tail_checked=True,
        slots=8,output_slot_stride=64,selected_output_bytes=[28,32],input_bound_from_abi=1024,
        completion_committed_only_on_success=True,cleanup_funclet_review_pending=False)


def inspect(bodies,ir,lane):
    result=dict(private_abi=abi(bodies,ir,lane),
        admission=sequential(bodies,lane) if lane in ('scalar','sha_ni') else simd(bodies,lane))
    if lane.startswith('simd'):
        result['callback_targets']=callback_targets(bodies,lane)
        result['simd_authority']=simd_authority.inspect(bodies,lane)
        result['simd_storage']=simd_storage.inspect(bodies,lane)
        result['simd_kernel']=simd_kernel.inspect(bodies,lane)
        result['simd_worker']=simd_worker.inspect(bodies,lane)
        result['simd_constructor']=simd_constructor.inspect(bodies,lane)
        result['simd_digest_caller']=simd_digest.inspect(bodies,lane)
        result['simd_output_commit']=simd_commit.inspect(bodies,lane)
        result['simd_descriptor_provenance']=simd_provenance.inspect(bodies,ir,lane)
        result['simd_authority']['authority_session']['kernel_and_transpose_semantics_pending']=False
    else:
        result['lifecycle']=lifecycle.inspect(bodies,lane)
        result['state_transitions']=batch_state.inspect(bodies,lane)
        result['placement_and_plan']=placement.inspect(bodies,lane)
    if lane=='scalar': result['public_iv']=iv.inspect(bodies)
    if lane=='sha_ni':
        result['finalizer']=sha_ni_finalizer(bodies)
        result['finalizer_caller']=sha_ni_finish_caller(bodies)
    return result
