"""Scoped SIMD authority/session checks; digest-engine provenance stays separate."""
import re
import windows_enclave_kmac_shapes as s


def role(bodies,name):
    patterns={'session':r'Session14compress_bytes$', 'owner':r'Owner9operation$',
              'check':r'^_RNvCs.*simd5check$', 'resident':r'Resident6digest$',
              'executor':r'Executor13digest_secret$', 'executor_check':r'Executor5check$',
              'padding':r'engine7padding$', 'scratch':r'crypto_cpu.*scratch.*Workspace4wipe$'}
    return s.one(bodies,patterns[name])


def population(bodies,lane):
    """Reject unassigned new indirect sites without claiming all listed sites reviewed."""
    expected={role(bodies,'session'):['callq *8(%r14)']*2,
              role(bodies,'owner'):['callq *8(%rax)']*2,
              role(bodies,'check'):['callq *8(%rax)']*2,
              role(bodies,'padding'):['callq *32(%rax)']}
    if lane=='simd256':
        expected[role(bodies,'resident')]=['callq *8(%r15)']*3+['callq *32(%rax)']*2+['callq *8(%rax)']
    else:
        expected[role(bodies,'resident')]=['callq *8(%r8)']*2
        expected[role(bodies,'executor_check')]=['callq *8(%rdx)']
        expected[role(bodies,'executor')]=['callq *8(%rax)','callq *%rax',
            'callq *920(%rbp)','callq *920(%rbp)','callq *32(%rax)','callq *32(%rax)']
    actual={n:[l for l in s.lines(b) if l.startswith('callq *')] for n,b in bodies.items()}
    actual={n:v for n,v in actual.items() if v}
    s.require(actual==expected,'complete ordered SIMD indirect-call population')
    return expected


def site(body,number,operand,before,after):
    s.sequences(body,[before+f'|.Ltmp{number}:|callq {operand}|nop|.Ltmp{number+1}:|'+after])


def session(bodies,lane):
    narrow=lane=='simd256';name=role(bodies,'session');body=bodies[name]
    wipe=role(bodies,'scratch');kernel=s.one(bodies,r'hardened_batch3x8615compress_secret$')
    load=s.one(bodies,r'transfer9transposeKj8_Kb1_');blocks=s.one(bodies,r'transfer9transposeKj10_Kb1_')
    store=s.one(bodies,r'transfer9transposeKj8_Kb0_');tmp=28 if narrow else 26
    factor=4 if narrow else 2;offset=2304 if narrow else 2816
    s.sequences(body,[
        'movq %r9, %r15|movq %rcx, %r14|cmpb $1, 16(%rcx)|jne .B12|'
        'movq %r8, %rdi|movq %rdx, %rsi|movq %r15, -16(%rbp)|movzbl 17(%r14), %ecx|'
        f'.Ltmp{tmp}:|movq %r14, -8(%rbp)|callq *8(%r14)|nop|.Ltmp{tmp+1}:|'
        'testb %al, %al|movq -8(%rbp), %r14|movq -16(%rbp), %r15|je .B12',
        'movzbl 17(%r14), %ebx|movq %r15, %rcx|callq '+wipe+'|xorl $1, %ebx|'
        f'leaq {factor}(,%rbx,{factor}), %rbx|movq %r15, %rcx|movq %rsi, %rdx|'
        'movq %rbx, %r8|movl $1, %r9d|callq '+load+'|leaq 256(%r15), %rcx|'
        'movq %rdi, %rdx|movq %rbx, %r8|callq '+blocks+'|cmpb $0, 17(%r14)|je .B5|'
        'xorl %esi, %esi|jmp .B13|.B5:|movq %r15, %rcx|callq '+kernel])
    site(body,tmp+2,'*8(%r14)',
        'cmpb $1, 16(%r14)|jne .B12|movzbl 17(%r14), %ecx',
        'testb %al, %al|movq -8(%rbp), %r14|movq -16(%rbp), %r15|je .B12|'
        'movq (%r14), %rdi|cmpq $-1, %rdi|je .B9|incq %rdi')
    s.sequences(body,[
        'movzbl 17(%r14), %eax|xorl $1, %eax|'+f'leaq {factor}(,%rax,{factor}), %r8|'
        f'leaq {offset}(%r15), %rdx|movq %rsi, %rcx|movl $1, %r9d|callq '+store+'|'
        'movq %rdi, (%r14)|movq %r15, %rcx|callq '+wipe+'|movb $-1, %sil|jmp .B11',
        '.B12:|movb $0, 16(%r14)|movb $2, %sil|.B13:|movq %r15, %rcx|callq '+wipe+'|movb $0, 16(%r14)',
        '.B9:|movb $3, %sil|jmp .B13'])
    returns=s.normal_returns(body,'.B13',['movq %r15, %rcx','callq '+wipe,'movb $0, 16(%r14)'])
    return dict(function=name,health_checked_before_and_after_kernel=True,
        revalidator_field_offset=8,authority_frame_slot=-8,scratch_frame_slot=-16,
        kernel_tag=0,lanes=8 if narrow else 4,pretranspose_scratch_wipe=True,
        output_after_revalidation_and_checked_counter=True,success_wipes_scratch=True,
        failure_cleanup_return_sites=returns,kernel_and_transpose_semantics_pending=True,
        caller_supplied_authority_provenance_pending=True)


def checks(bodies,lane):
    narrow=lane=='simd256';name=role(bodies,'check');body=bodies[name];tmp=38 if narrow else 58
    s.sequences(body,[
        'cmpb $1, 16(%rcx)|jne .B7|movq %rcx, %rax|movzbl 17(%rcx), %ecx|'
        f'.Ltmp{tmp}:|movq %rax, -16(%rbp)|callq *8(%rax)|nop|.Ltmp{tmp+1}:|'
        'testb %al, %al|movq -16(%rbp), %rcx|je .B7|movb $5, %al|'
        'cmpb $0, 17(%rcx)|jne .B8|cmpb $1, 16(%rcx)|jne .B7|'
        f'.Ltmp{tmp+2}:|movq %rcx, %rax|xorl %ecx, %ecx|callq *8(%rax)|nop|.Ltmp{tmp+3}:|'
        'movl %eax, %ecx|movb $-1, %al|testb %cl, %cl|movq -16(%rbp), %rcx|jne .B8|'
        '.B7:|movb $0, 16(%rcx)|movb $5, %al'])
    op=bodies[role(bodies,'owner')];pointer=8 if narrow else 16;tmp=42 if narrow else 62
    s.sequences(op,[
        f'.B2:|movq {pointer}(%rbx), %rax|cmpb $1, 16(%rax)|jne .B9|'
        'movq %rbx, -16(%rbp)|movzbl 17(%rax), %ecx|'+
        f'.Ltmp{tmp}:|movq %rax, -8(%rbp)|callq *8(%rax)|nop|.Ltmp{tmp+1}:|'
        'testb %al, %al|movq -16(%rbp), %rbx|movq -8(%rbp), %rax|je .B9|'
        'cmpb $0, 17(%rax)|jne .B10|cmpb $1, 16(%rax)|jne .B9|'+
        f'.Ltmp{tmp+2}:|xorl %ecx, %ecx|callq *8(%rax)|nop|.Ltmp{tmp+3}:|'
        'testb %al, %al|movq -16(%rbp), %rbx|movq -8(%rbp), %rax|je .B9',
        '.B9:|movb $0, 16(%rax)'])
    result=dict(function=name,owner_authority_offset=pointer,owner_frame_slot=-16,
        authority_frame_slot=-8,compiled_target_tag_required=0,
        revalidation_must_succeed_before_operation_publication=True)
    if not narrow:
        extra=bodies[role(bodies,'executor_check')]
        s.sequences(extra,[
            'movb $4, %al|cmpb $0, 16(%rcx)|jne .B7|movq (%rcx), %rdx|'
            'movb $-1, %al|testq %rdx, %rdx|je .B7|cmpb $0, 16(%rdx)|je .B3|'
            'movzbl 17(%rdx), %ecx|.Ltmp56:|movq %rdx, -16(%rbp)|callq *8(%rdx)|nop|'
            '.Ltmp57:|testb %al, %al|movb $-1, %al|movq -16(%rbp), %rdx|jne .B7|'
            '.B3:|movb $0, 16(%rdx)|movb $2, %al'])
        result['wide_executor_check']=dict(rejects_quarantined_executor=True,
            absent_authority_allowed_by_private_helper=True,caller_present_authority_pending=True)
    return result


def handlers(bodies,lane):
    """Invoked funclet contracts only; parent xdata bindings are checked separately."""
    narrow=lane=='simd256';wipe=role(bodies,'scratch');checked={}
    groups=[('session',(-8,14),(-16,15),(-8,16)),('check',(-16,9),(-16,10)),
            ('owner',(-16,12),(-8,16),(-8,17))]
    if not narrow: groups.append(('executor_check',(-16,4)))
    for group,*entries in groups:
        parent=role(bodies,group)
        for slot,number in entries:
            name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@\?0\?'+re.escape(parent)+r'@')
            body=bodies[name];entry=f'.B{number}'
            s.sequences(body,['leaq 48(%rdx), %rbp|.seh_endprologue'])
            if group=='session' and number==15:
                event=['movq -16(%rbp), %rcx','callq '+wipe,
                       'movq -8(%rbp), %rax','movb $0, 16(%rax)']
            elif group=='owner' and number==12:
                output,phase,pointer=(16,280,8) if narrow else (24,288,16)
                event=['movq -16(%rbp), %rsi',f'leaq {output}(%rsi), %rcx',
                       'movl $256, %edx','callq '+s.ZERO,
                       'movb $2, (%rsi)' if narrow else 'movw $-1, (%rsi)',
                       f'movb $2, {phase}(%rsi)',f'movq {pointer}(%rsi), %rax','movb $0, 16(%rax)']
            else: event=[f'movq {slot}(%rbp), %rax','movb $0, 16(%rax)']
            s.sequences(body,['|'.join(event)])
            checked[name]=dict(parent=parent,parent_frame_adjustment=48,slot=slot,
                normal_return_sites=s.normal_returns(body,entry,event),events=event)
    return dict(invoked_funclets=checked,arbitrary_os_unwind_qualified=False,
        cleanup_state_order_review_pending=True)


def padding(bodies,lane):
    """Local padding contract; early failures still require caller workspace cleanup."""
    narrow=lane=='simd256';name=role(bodies,'padding');body=bodies[name]
    block,pad,state,scratch=(4872,5000,5128,4232) if narrow else (5348,5476,5604,4708)
    width=64 if narrow else 128
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    compress=s.one(bodies,r'hardened10compress'+('32' if narrow else '64')+r'6native6scalar$')
    s.sequences(body,[
        'movq %r8, %rsi|movq %rdx, %r14|movq %rcx, %rbx|'+
        f'leaq {block}(%rcx), %rdi|leaq {pad}(%rcx), %r8|movl ${width}, %edx|'+
        f'movl ${width}, %r9d|movq %rdi, %rcx|callq '+copy+'|cmpb $-1, %al|je .B2|'+
        '.B1:|movb $11, %al|jmp .B8',
        '.B2:|movq (%r14), %rcx|movq 8(%r14), %rax|callq *32(%rax)|'+
        'movl %eax, %ecx|movb $10, %al|testb %cl, %cl|jne .B8|'+
        'movq 16(%r14), %rax|testq %rax, %rax|je .B7|'+
        'movq 24(%r14), %rcx|cmpq $-1, %rcx|je .B1|incq %rcx|decq %rax|'+
        'movq %rax, 16(%r14)|movq %rcx, 24(%r14)|'+
        f'leaq {state}(%rbx), %rcx|addq ${scratch}, %rbx|movq %rdi, %rdx|'+
        'movq %rbx, %r8|callq '+compress+'|movl $640, %edx|movq %rbx, %rcx|callq '+s.ZERO+'|'+
        'movl $128, %edx|movq %rdi, %rcx|callq '+s.ZERO+'|'+
        'movq 16(%rsi), %rcx|movb $11, %al|cmpq $-1, %rcx|je .B8|incq %rcx|'+
        'movq %rcx, 16(%rsi)|movb $-1, %al|jmp .B8',
        '.B7:|movb $9, %al|.B8:'])
    return dict(function=name,cancellation_precedes_budget_charge=True,
        control_budget_offset=16,control_charged_offset=24,report_scalar_blocks_offset=16,
        nonwrapping_control_and_report_counters=True,padding_bytes=width,
        postcompression_scratch_wipe_bytes=640,postcompression_block_wipe_bytes=128,
        callback_object_provenance_pending=True,caller_early_failure_cleanup_pending=True,
        scalar_kernel_composition_pending=True)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'two SIMD authority profiles')
    calls=population(bodies,lane)
    covered={role(bodies,x) for x in ('session','owner','check')}
    if lane=='simd512': covered.add(role(bodies,'executor_check'))
    return dict(indirect_population=calls,authority_session=session(bodies,lane),
        authority_checks=checks(bodies,lane),callback_unwind=handlers(bodies,lane),
        padding_helper=padding(bodies,lane),
        locally_checked_authority_sites={n:calls[n] for n in sorted(covered)},
        remaining_digest_and_padding_sites={n:v for n,v in calls.items() if n not in covered},
        complete_callback_provenance_qualified=False)
