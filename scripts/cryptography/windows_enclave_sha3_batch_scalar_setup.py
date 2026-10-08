"""Scalar setup finalization: full caller shape and moved-state composition.

Expected bodies are manually composed from the reviewed control-flow/layout,
not extracted from candidate assembly. Physical copies are not erased merely
because their enum discriminator is changed. Final stack retirement stays open.
"""
import windows_enclave_sha3_batch_receive as receive
import windows_enclave_sha3_batch_storage as storage
import windows_enclave_sha3_batch_setup_moves as moves

life=receive.life
s=life.s
L=receive.L
WIPE=storage.SCALAR_WIPE


def reset(integer=True):
    zero,store=('pxor','movdqa') if integer else ('xorps','movaps')
    return L(f'''movb $0, 243(%rsp)|leaq 240(%rsp), %rcx|movl $1, %edx|callq {life.ZERO}
        movw $768, 241(%rsp)|movb $0, 1284(%rsp)|{zero} %xmm0, %xmm0''')+[
        f'{store} %xmm0, {at}(%rsp)' for at in (176,192,208,224)]


def successful_setup(branch):
    """Both rates share complete-prefix checks but have disjoint moved regions."""
    wide=branch==8
    fail,absent,join,end=(38,41,37,42) if wide else (18,21,17,22)
    head,tail,bulk=(80,44,4420) if wide else (64,40,3432)
    return L(f'''leaq 32(%r14), %rdx|leaq 176(%rsp), %rcx|movl $1120, %r8d|callq memcpy
        cmpb $2, 242(%rsp)|jne .B{fail}|movq 200(%rsp), %rax|orq 192(%rsp), %rax|jne .B{fail}
        cmpb $0, 241(%rsp)|jne .B{fail}|movdqa 176(%rsp), %xmm0|pcmpeqb 224(%rsp), %xmm0
        pmovmskb %xmm0, %eax|cmpl $65535, %eax|jne .B{fail}|cmpb $1, 243(%rsp)|jne .B{absent}
        leaq 244(%rsp), %rdi|movzbl 244(%rsp), %ebx
        movq 101(%r14), %rax|movq 108(%r14), %rcx|movq %rax, {head}(%rsp)|movq %rcx, {head+7}(%rsp)
        movups 116(%r14), %xmm0|movaps %xmm0, 128(%rsp)
        leaq 148(%r14), %rdx|leaq {bulk}(%rsp), %rcx|movl $988, %r8d|callq memcpy
        movzwl 1137(%r14), %eax|movw %ax, {tail}(%rsp)|movzbl 1139(%r14), %eax|movb %al, {tail+2}(%rsp)
        movl $1040, %r8d|movq %rdi, %rcx|xorl %edx, %edx|callq memset
        movq %rdi, %rcx|callq {WIPE}|movzbl 1284(%rsp), %r15d
        cmpb $1, 243(%rsp)|jne .B{join}|movq %rdi, %rcx|callq {WIPE}
        cmpb $0, 243(%rsp)|je .B{join}|movq %rdi, %rcx|callq {WIPE}|.B{join}:''')+reset(False)+L(f'''
        movq {head}(%rsp), %rax|movq {head+7}(%rsp), %rcx|movq %rax, 96(%rsp)|movq %rcx, 103(%rsp)
        movdqa 128(%rsp), %xmm0|movdqu %xmm0, 111(%rsp)|xorl %r12d, %r12d|jmp .B{end}''')


def rejected_setup(branch):
    fail,absent,join,nextlabel=(38,41,42,45) if branch==8 else (18,21,22,25)
    return L(f'''.B{fail}:|cmpb $1, 243(%rsp)|jne .B{absent}
        leaq 244(%rsp), %rdi|movq %rdi, %rcx|callq {WIPE}
        cmpb $0, 243(%rsp)|je .B{absent}|movq %rdi, %rcx|callq {WIPE}|.B{absent}:''')+reset()+L(f'''
        movb $1, %r12b|xorl %ebx, %ebx|.B{join}:|cmpb $1, 243(%rsp)|jne .B{nextlabel}
        leaq 244(%rsp), %rdi|movq %rdi, %rcx|callq {WIPE}
        cmpb $0, 243(%rsp)|je .B{nextlabel}|movq %rdi, %rcx|callq {WIPE}|.B{nextlabel}:''')+reset()+L(f'''
        cmpb $0, 243(%rsp)|je .B{nextlabel+2}|leaq 244(%rsp), %rcx|callq {WIPE}
        .B{nextlabel+2}:|testb %r12b, %r12b|'''+('jne .B48' if branch==8 else 'je .B28'))


def moved_result(branch):
    head,tail,bulk,tag=(80,44,4420,6) if branch==8 else (64,40,3432,5)
    return L(f'''movups 96(%rsp), %xmm0|movups 111(%rsp), %xmm1
        movups %xmm1, 159(%rsp)|movaps %xmm0, 144(%rsp)
        movq {head}(%rsp), %rax|movq {head+7}(%rsp), %rcx|movq %rax, 48(%rsp)|movq %rcx, 55(%rsp)
        leaq 2444(%rsp), %rcx|leaq {bulk}(%rsp), %rdx|movl $988, %r8d|callq memcpy
        movzwl {tail}(%rsp), %eax|movw %ax, 36(%rsp)|movzbl {tail+2}(%rsp), %eax|movb %al, 38(%rsp)
        movb ${tag}, %dil''')


def shape(operation):
    begin=L(f'''pushq %r15|pushq %r14|pushq %r12|pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx
        movl $5408, %eax|callq __chkstk|subq %rax, %rsp
        movq %r8, %rsi|movq %rdx, %r8|movq %rcx, %rdx|leaq 1296(%rsp), %rcx
        movb $2, %bl|movb $2, %r9b|callq {operation}|movzbl 1304(%rsp), %ebp
        cmpb $2, %bpl|jne .B2|movzbl 1296(%rsp), %ebx|jmp .B56|.B2:
        movq 1296(%rsp), %r14|cmpl $1, (%r14)|jne .B50|cmpq %rsi, 8(%r14)|jne .B50
        movb $3, %bl|cmpq $7, %rsi|ja .B50|leaq (%rsi,%rsi,2), %rax
        movq 1152(%r14,%rax,8), %rax|addq $-7, %rax|cmpq $1, %rax|ja .B55
        leaq 16(%r14), %rsi|leaq 1296(%rsp), %rcx|movl $1136, %r8d|movq %rsi, %rdx|callq memcpy
        movb $0, 16(%r14)|movzbl 1296(%rsp), %eax|cmpl $7, %eax|je .B9|cmpl $8, %eax|jne .B8''')
    middle=L(f'''.B48:|movb $6, %bl|cmpb $6, 1296(%rsp)|ja .B50|.B49:
        leaq 1296(%rsp), %rcx|callq {life.DROP['scalar']}|.B50:|testb $1, %bpl|jne .B56
        leaq 16(%r14), %rcx|callq {life.DROP['scalar']}''')
    clear=[l.replace('xorps','pxor').replace('movaps','movdqa').replace('movups','movdqu')
           for l in life.clear_tail('scalar','r14')]+life.quarantine('scalar','r14')
    end=L(f'''.B53:|movq %rsi, %rcx|callq {life.DROP['scalar']}|movb %dil, 16(%r14)
        movb $0, 17(%r14)|movb %bl, 18(%r14)|movaps 144(%rsp), %xmm0|movups %xmm0, 19(%r14)
        movdqu 159(%rsp), %xmm0|movdqu %xmm0, 34(%r14)|movb %bl, 50(%r14)
        movq 48(%rsp), %rax|movq 55(%rsp), %rcx|movq %rax, 51(%r14)|movq %rcx, 58(%r14)
        leaq 66(%r14), %rcx|leaq 2444(%rsp), %rdx|movl $988, %r8d|callq memcpy
        movb %r15b, 1054(%r14)|movzbl 38(%rsp), %eax|movb %al, 1057(%r14)
        movzwl 36(%rsp), %eax|movw %ax, 1055(%r14)|cmpb $6, 1296(%rsp)|ja .B55
        leaq 1296(%rsp), %rcx|callq {life.DROP['scalar']}|.B55:|movb $3, 2384(%r14)
        movb $-1, %bl|.B56:|movl %ebx, %eax|addq $5408, %rsp
        popq %rbx|popq %rbp|popq %rdi|popq %rsi|popq %r12|popq %r14|popq %r15|retq''')
    return (begin+successful_setup(8)+['.B9:']+successful_setup(7)+L('.B8:|movb $2, %bl|jmp .B49')+
        rejected_setup(8)+moved_result(8)+['jmp .B53']+rejected_setup(7)+middle+clear+
        L('jmp .B56|.B28:')+moved_result(7)+end)


def check_shape(bodies):
    n={k:s.one(bodies,'Owner'+str(len(k))+k+'$') for k in ('finish_setup','operation')}
    expected=shape(n['operation'])
    s.require(life.code(bodies[n['finish_setup']])==expected,'complete scalar setup finalization and moved-state caller')
    return n,expected


def inspect(bodies,ir,prior,placement,transitions,receiver,chunks):
    s.require(prior['prior_semantics_replayed'] and placement['state_destructor']['typed_payload_cleanup_composed'] and
        placement['state_pointer_inside_owner'],'scalar setup requires replayed helpers and placed typed state')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
        transitions['unfinished_guard_clears_and_quarantines'],'scalar setup requires operation and rejection cleanup')
    s.require(chunks['normal_rejection_typed_cleanup_and_quarantine_composed'] and chunks['input_pointer_and_length_preserved'],
        'scalar setup requires checked fragment callers')
    n,expected=check_shape(bodies)
    s.require(n['finish_setup']==receiver['functions']['finish_setup'] and n['operation']==transitions['functions']['operation'],
        'scalar setup actual receiver and admission targets')
    receive.arguments(ir,receive.names(bodies,'scalar'),'scalar')
    s.require({WIPE,life.ZERO}<=set(prior['exact_body_reference_extent_and_abi']),
        'scalar setup wipe callees require freshly replayed exact semantics')
    for name,size in ((WIPE,1040),(life.DROP['scalar'],1136)):
        abi=life.reuse.abi(ir,name)
        s.require('dereferenceable('+str(size)+')' in abi and 'noalias' in abi and 'nounwind' in abi,
            'scalar setup full exclusive nonunwinding typed cleanup')
    return dict(function=n['finish_setup'],instructions_and_labels_checked=len(expected),
        moved_state_origins=[moves.replay(tag) for tag in (7,8)],
        frame_bytes=5408,saved_register_bytes=56,operation_result=[1296,1312],old_state=[1296,2432],
        operation_result_consumed_before_storage_reuse=True,state_tombstone_does_not_erase_payload=True,
        required_outer_phase=2,active_slot_and_identity_checked=True,setup_tags=[7,8],result_tags=[5,6],
        required_prefix_phase=2,remaining_u128_must_be_zero=True,pending_bit_count_must_be_zero=True,
        emitted_expected_full_u128_equality=True,inner_owner_must_be_present=True,
        setup_pending_byte_volatile_clear=True,normal_failure_typed_cleanup_and_quarantine_composed=True,
        success_outer_phase=3,valid_initialized_state_required=True,start_establishes_state_invariant_qualified=False,
        moved_copy_erasure_qualified=False,private_frame_erasure_qualified=False,all_unwind_paths_qualified=False,
        shared_memcpy_memset_chkstk_implementation_package=8,whole_image_qualified=False)
