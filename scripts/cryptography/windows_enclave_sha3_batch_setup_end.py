"""AVX2 setup completion; scalar moved-state finalization remains separate."""
import windows_enclave_sha3_batch_receive as receive

life=receive.life
s=life.s
L=receive.L


def names(bodies):
    return {k:s.one(bodies,p) for k,p in (
        ('finish','Owner12finish_setup$'),('operation','Owner9operation$'),('wipe','Memory4wipe$'))}


def shape(n):
    result=L(f'''pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx|subq $56, %rsp
        movq %r8, %rdi|movq %rdx, %r8|movq %rcx, %rdx|leaq 40(%rsp), %rcx
        movb $2, %bl|movb $2, %r9b|callq {n['operation']}
        movzbl 48(%rsp), %ebp|cmpb $2, %bpl|jne .B2|movzbl 40(%rsp), %ebx|jmp .B26
        .B2:|movq 40(%rsp), %rsi|cmpl $1, 2232(%rsi)|jne .B22|cmpq %rdi, 2240(%rsi)|jne .B22
        movb $3, %bl|cmpq $7, %rdi|ja .B22|leaq (%rdi,%rdi,2), %rax
        movq 1024(%rsi,%rax,8), %rax|addq $-7, %rax|cmpq $1, %rax|ja .B18
        movb $6, %bl|cmpl $2, 2160(%rsi)|je .B22|cmpb $0, 2178(%rsi)|je .B8
        .B19:|movb $1, 2075(%rsi)|movq $0, 1832(%rsi)|leaq 1840(%rsi), %rcx|callq {n['wipe']}
        cmpb $-1, 2154(%rsi)|je .B21|leaq 2152(%rsi), %rcx|movl $1, %edx|callq {life.ZERO}
        movb $0, 2153(%rsi)|vpxor %xmm0, %xmm0, %xmm0
        vmovdqa %ymm0, 2080(%rsi)|vmovdqa %ymm0, 2112(%rsi)
        .B21:|movb $-1, 2154(%rsi)|movb $3, 2178(%rsi)
        .B22:|testb $1, %bpl|jne .B26|leaq 1216(%rsi), %rcx|vzeroupper|callq {life.DROP['avx2']}''')
    # Same logical clear stores as the checked lifecycle, using integer moves.
    result += [l.replace('vxorps','vpxor').replace('vmovaps','vmovdqa').replace('vmovups','vmovdqu')
               for l in life.clear_tail('avx2')]+life.quarantine('avx2',label=25)
    return result+L(f'''jmp .B26|.B8:|cmpb $0, 2075(%rsi)|jne .B19|cmpb $0, 2074(%rsi)|jne .B19
        movq 1792(%rsi), %rax|cmpb $1, 8(%rax)|jne .B19|movq (%rax), %rcx
        cmpq 1800(%rsi), %rcx|jne .B19|cmpb $4, 9(%rax)|jne .B19
        cmpb $2, 2154(%rsi)|jne .B19|movq 2080(%rsi), %rax|orq 2088(%rsi), %rax|jne .B19
        cmpb $0, 2153(%rsi)|jne .B19|vmovdqa 2112(%rsi), %xmm0
        vpxor 2128(%rsi), %xmm0, %xmm0|vptest %xmm0, %xmm0|jne .B19
        leaq 2080(%rsi), %rdi|leaq 2152(%rsi), %rcx|movl $1, %edx|callq {life.ZERO}
        movb $0, 2153(%rsi)|vpxor %xmm0, %xmm0, %xmm0
        vmovdqa %ymm0, 32(%rdi)|vmovdqa %ymm0, (%rdi)|movb $-1, 2154(%rsi)
        movb $1, 2178(%rsi)|.B18:|movb $3, 2249(%rsi)|movb $-1, %bl
        .B26:|movl %ebx, %eax|addq $56, %rsp|popq %rbx|popq %rbp|popq %rdi|popq %rsi|vzeroupper|retq''')


def check_shape(bodies):
    n=names(bodies);expected=shape(n)
    s.require(life.code(bodies[n['finish']])==expected,'complete AVX2 setup completion checks, transition and cleanup')
    return n,expected


def inspect(bodies,ir,prior,storage,transitions,receiver,chunks):
    s.require(prior['prior_semantics_replayed'] and storage['state_destructor']['typed_payload_cleanup_composed'] and
        storage['state_pointer_inside_owner'],'setup completion requires placed state and replayed cleanup')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
        transitions['unfinished_guard_clears_and_quarantines'],'setup completion requires actual operation semantics')
    s.require(chunks['normal_rejection_typed_cleanup_and_quarantine_composed'] and
        chunks['input_pointer_and_length_preserved'],'setup completion requires checked fragment callers')
    n,expected=check_shape(bodies)
    s.require(n['finish']==receiver['functions']['finish_setup'] and n['operation']==transitions['functions']['operation'],
        'actual receiver finish-setup and operation targets')
    receive.arguments(ir,receive.names(bodies,'avx2'),'avx2')
    s.require({n['wipe'],life.ZERO}<=set(prior['exact_body_reference_extent_and_abi']),
        'completion wipe helpers exactly match reproduced lower review')
    s.require('(ptr noalias nofree noundef nonnull dereferenceable(234) %0)' in life.reuse.abi(ir,n['wipe']),
        'actual nested failed-engine wipe extent')
    return dict(function=n['finish'],instructions_and_labels_checked=len(expected),
        required_outer_phase=2,required_core_phase=0,required_prefix_phase=2,
        active_slot_and_plan_identity_checked=True,prefix_required_for_identities=[7,8],
        remaining_u128_must_be_zero=True,pending_bit_count_must_be_zero=True,
        emitted_expected_full_u128_equality=True,inner_health_epoch_and_kernel_checked=True,
        prefix_pending_byte_volatile_clear_before_absorbing=True,prefix_logical_counts_reset=True,
        success_core_phase=1,success_outer_phase=3,cshake_success_transition_requires_complete_prefix=True,
        normal_failure_typed_cleanup_and_quarantine_composed=True,
        frame_bytes=56,saved_register_bytes=32,operation_result=[40,56],
        valid_initialized_state_required=True,scalar_setup_finalization_qualified=False,
        all_unwind_paths_qualified=False,private_frame_erasure_qualified=False,whole_image_qualified=False)
