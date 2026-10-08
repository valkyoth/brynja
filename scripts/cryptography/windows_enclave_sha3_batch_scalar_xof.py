"""Scalar batch XOF finalization: actual input, suffix and owner-field joins.

The changed caller is checked in full, not reused by symbol name. Valid initial
state/metadata remain preconditions. This is not squeeze or frame qualification.
"""
import windows_enclave_sha3_batch_receive as receive

life,s,L=receive.life,receive.life.s,receive.L


def names(bodies):
    result={'finish':s.one(bodies,'State10finish_xof$')}
    for rate in ('a8','88'):
        for kind in ('update','finalize'):
            result[kind+rate]=s.one(bodies,'OwnerKj'+rate+'_E'+str(len(kind))+kind)
    return result


def shape(n):
    saves=['r14','rsi','rdi','rbx']
    lines=[f'pushq %{r}' for r in saves]+L('''subq $40, %rsp|movzbl (%rcx), %r8d
        cmpl $6, %r8d|je .B7|movb $2, %al|cmpl $5, %r8d|jne .B33''')
    for label,empty,partial,update in ((None,12,19,20),(7,15,23,24)):
        if label:lines+=['.B7:']
        lines+=L(f'''movb $6, %al|cmpb $0, 1(%rcx)|jne .B33|movq (%rdx), %r9
            leaq 2(%rcx), %rsi|testq %r9, %r9|je .B{empty}
            movq 16(%rdx), %r8|movq 10(%rcx), %r10|shrq $3, %r8
            addq 2(%rcx), %r8|adcq $0, %r10|jb .B33|movzbl 24(%rdx), %edi
            movq 8(%rdx), %r8|movq %rcx, %r14|testb $-9, %dil|jne .B{partial}
            xorl %ebx, %ebx|jmp .B{update}''')
    lines+=L('''.B12:|movq %rcx, %r14|cmpb $1, 1038(%rcx)|jne .B17
        movb $3, 32(%rsp)|movq %rsi, %rcx|xorl %edx, %edx|jmp .B14
        .B15:|movq %rcx, %r14|cmpb $1, 1038(%rcx)|jne .B18
        movb $3, 32(%rsp)|movq %rsi, %rcx|xorl %edx, %edx|movb $4, %r9b|jmp .B31
        .B17:|movb $5, 32(%rsp)|movq %rsi, %rcx|xorl %edx, %edx|jmp .B28
        .B18:|movb $5, 32(%rsp)|movq %rsi, %rcx|xorl %edx, %edx|jmp .B30''')
    for partial,update,uncustom,rate in ((19,20,27,'a8'),(23,24,29,'88')):
        lines+=L(f'''.B{partial}:|cmpq $1, %r8|movq %r8, %rax|adcq $-1, %rax
            leaq (%r9,%rax), %rcx|xorl %ebx, %ebx|cmpq %rax, %r8
            cmovneq %rcx, %rbx|movq %rax, %r8|.B{update}:|movq %rsi, %rcx
            movq %r9, %rdx|callq {n['update'+rate]}|testb %al, %al|movb $6, %al
            jne .B33|cmpb $1, 1038(%r14)|jne .B{uncustom}|movb $3, 32(%rsp)
            movq %rsi, %rcx|movq %rbx, %rdx|movl %edi, %r8d''')
        if rate=='a8':lines+=L(f'.B14:|movb $4, %r9b|callq {n["finalizea8"]}|jmp .B32')
        else:lines+=L('movb $4, %r9b|jmp .B31')
    lines+=L(f'''.B27:|movb $5, 32(%rsp)|movq %rsi, %rcx|movq %rbx, %rdx
        movl %edi, %r8d|.B28:|movb $31, %r9b|callq {n['finalizea8']}|jmp .B32
        .B29:|movb $5, 32(%rsp)|movq %rsi, %rcx|movq %rbx, %rdx
        movl %edi, %r8d|.B30:|movb $31, %r9b|.B31:|callq {n['finalize88']}
        .B32:|leaq 34(%r14), %rcx|movl $16, %edx|callq {life.ZERO}
        leaq 1038(%r14), %rcx|movl $1, %edx|callq {life.ZERO}
        movb $1, 1(%r14)|movb $-1, %al|.B33:|addq $40, %rsp''')
    return lines+[f'popq %{r}' for r in reversed(saves)]+['retq']


def check_shape(bodies):
    n=names(bodies);expected=shape(n)
    s.require(life.code(bodies[n['finish']])==expected,'complete scalar XOF input/suffix/transition body')
    return n,expected


def input_partition(length,last):
    """Actual tail split arithmetic, on the bounded canonical caller domain."""
    s.require(type(length) is int and 0<=length<=1024 and type(last) is int and
        ((length==0 and last==0) or (length>0 and 1<=last<=8)),'canonical bounded final input')
    prefix=length;tail=None
    if last&247:
        prefix=(length-1+int(length<1))&((1<<64)-1)
        tail=prefix if prefix!=length else None
    return prefix,tail


def admit(counter,bits):
    """Emitted low-word add/high-word adc; it admits complete-byte growth."""
    s.require(type(counter) is int and 0<=counter<1<<128 and type(bits) is int and
              0<=bits<=8192,'u128 byte counter and bounded input bits')
    low=(counter&((1<<64)-1))+(bits>>3)
    high=(counter>>64)+int(low>=1<<64)
    return high<1<<64


def arguments(ir,n):
    owner='ptr noalias nofree noundef nonnull dereferenceable(1040)'
    for rate in ('a8','88'):
        update=life.reuse.abi(ir,n['update'+rate]);finalize=life.reuse.abi(ir,n['finalize'+rate])
        s.require('('+owner+' %0, ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) %1, '
            'i64 noundef range(i64 0, -9223372036854775808) %2)' in update and
            'zeroext i1 @' in update and 'nounwind' in update,'rate update actual unaligned owner/input/Boolean ABI')
        s.require('('+owner+' initializes((1032, 1033)) %0, '
            'ptr noalias nofree noundef readonly captures(address, read_provenance) dereferenceable_or_null(1) %1, '
            'i8 %2, i8 noundef range(i8 4, 32) %3, i8 noundef range(i8 3, 6) %4)' in finalize and
            'fastcc void @' in finalize and 'nounwind' in finalize,'optional tail and five-argument suffix ABI')


def inspect(bodies,ir,prior,caller):
    s.require(prior['prior_semantics_replayed'],'XOF transition requires replayed lower semantics')
    s.require(caller['input_pointer_preserved_to_descriptor'] and caller['partial_tail_only_after_nonempty_shape_check'] and
        caller['outer_rejection_clears_entire_output_and_quarantines'] and caller['maximum_input_bytes']==1024 and
        caller['maximum_input_bits']==8192 and caller['descriptor_bytes']==32 and
        caller['state_span']==[16,1152],'actual bounded descriptor/state and rejection caller')
    n,expected=check_shape(bodies);arguments(ir,n)
    s.require(n['finish']==caller['functions']['finish_xof'],'actual outer XOF call target')
    helpers=[n[k] for k in ('updatea8','update88','finalizea8','finalize88')]+[life.ZERO]
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),'five exactly replayed helpers')
    for name in helpers:
        abi=life.reuse.abi(ir,name)
        s.require('nounwind' in abi and life.reuse.accelerated.digest(abi.encode())==
            prior['exact_body_reference_extent_and_abi'][name]['abi_sha256'],'actual XOF helper ABI matches replay')
    return dict(function=n['finish'],instructions_and_labels_checked=len(expected),helpers=helpers,
        state_tags_to_rate={'5':168,'6':136},required_lifecycle=0,success_lifecycle=1,
        nested_owner_span=[2,1042],counter_span=[2,18],cshake_counter_clear_span=[34,50],
        mode_clear_span=[1038,1039],state_extent=1136,frame_bytes=40,saved_register_bytes=32,
        suffix_width_caller_stack_offset=32,suffix_width_callee_entry_offset=40,
        actual_some_input_pointer_nonnull=True,null_option_branch_not_empty_slice=True,
        full_prefix_and_optional_last_byte_are_inside_input=True,whole_byte_admission_uses_u128_carry=True,
        same_owner_and_rate_preserved_through_update_and_finalize=True,
        update_failure_returns_before_finalization=True,
        customized_suffix_and_width=[4,3],shake_suffix_and_width=[31,5],
        metadata_cleared_after_padding_before_lifecycle_commit=True,
        normal_paths_composed=True,outer_rejection_destroys_state_and_quarantines=True,
        valid_initialized_owner_and_customization_required=True,
        output_squeeze_qualified=False,state_construction_qualified=False,
        private_frame_erasure_qualified=False,all_unwind_paths_qualified=False,whole_image_qualified=False)
