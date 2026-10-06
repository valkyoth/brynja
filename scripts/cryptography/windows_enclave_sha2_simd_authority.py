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


def digest_callers(bodies,lane):
    """Concrete callback sources in the saved callers; not generic alias analysis."""
    narrow=lane=='simd256';body=bodies[role(bodies,'resident')]
    slot,opslot,pointer,reg,tmp,fail=(152,6688,8,'r15',46,29) if narrow else (64,7200,16,'r8',66,25)
    s.sequences(body,[
        f'leaq {opslot}(%rbx), %rcx|xorl %r9d, %r9d|callq '+role(bodies,'owner'),
        f'movq {opslot}(%rbx), %rax|movq %rax, {slot}(%rbx)',
        f'.B14:|movq {slot}(%rbx), %rax|movq {pointer}(%rax), %{reg}|cmpb $1, 16(%{reg})|'+
        ('movq 160(%rbx), %rsi|' if narrow else '')+f'jne .B{fail}|movzbl 17(%{reg}), %ecx|'+
        f'.Ltmp{tmp}:|movq %{reg}, 88(%rbx)|callq *8(%{reg})|nop|.Ltmp{tmp+1}:|'+
        f'testb %al, %al|movq 88(%rbx), %{reg}|je .B{fail}|cmpb $1, 16(%{reg})|'+
        f'jne .B{fail}|movzbl 17(%{reg}), %ecx|.Ltmp{tmp+2}:|callq *8(%{reg})|nop|'+
        f'.Ltmp{tmp+3}:|testb %al, %al|movq 88(%rbx), %{reg}|je .B{fail}'])
    if narrow:
        s.sequences(body,[
            'movq 11968(%rbp), %rax|movq %rax, 256(%rbx)|movq $0, 264(%rbx)|'+
            'leaq 70(%rbx), %rax|movq %rax, 240(%rbx)|'+
            'leaq anon.ef352dd9f3401734e6e87c6e62594e02.0(%rip), %rax|movq %rax, 248(%rbx)',
            'cmpb $0, 16(%r15)|je .B33|movzbl 17(%r15), %ecx|.Ltmp50:|vzeroupper|'+
            'callq *8(%r15)|nop|.Ltmp51:|testb %al, %al|movq 88(%rbx), %r15|je .B33',
            'movq 240(%rbx), %rax|movq %rax, 56(%rbx)|movq 248(%rbx), %rax|movq %rax, 104(%rbx)',
            '.Ltmp54:|movq 56(%rbx), %rcx|movq 104(%rbx), %rax|callq *32(%rax)|nop|'+
            '.Ltmp55:|testb %al, %al|jne .B258',
            '.B178:|movq 240(%rbx), %rcx|movq 248(%rbx), %rax|.Ltmp60:|callq *32(%rax)|'+
            'nop|.Ltmp61:|testb %al, %al|je .B181',
            '.B181:|movq 88(%rbx), %rax|cmpb $0, 16(%rax)|je .B188|movq 88(%rbx), %rax|'+
            'movzbl 17(%rax), %ecx|.Ltmp62:|callq *8(%rax)|nop|.Ltmp63:|testb %al, %al|je .B188',
            'movq 88(%rbx), %rcx|movq (%rcx), %rdi|.Ltmp52:|leaq 7456(%rbx), %rdx|'+
            'leaq 6688(%rbx), %r8|movq %r14, %r9|callq '+role(bodies,'session')])
        for number in (56,58):
            s.sequences(body,[f'.Ltmp{number}:|leaq 6688(%rbx), %rcx|leaq 240(%rbx), %rdx|'+
                'leaq 2912(%rbx), %r8|callq '+role(bodies,'padding')])
        closure=s.one(bodies,r'^_RNC.*Owner6digests2_0')
        s.sequences(body,['leaq 70(%rbx), %rcx|callq '+closure])
        result=dict(control_frame_offset=240,data_frame_offset=70,authority_frame_offset=88,
            remaining_indirect_sites_locally_checked=6,padding_control_argument_checked=True)
    else:
        s.sequences(body,[
            'movl %r8d, %eax|movq %r8, %rcx|shrq $8, %rcx|movq %r8, %rdx|shrq $56, %rdx|'+
            'movb %dl, 127(%rbx)|shrq $40, %r8|movw %r8w, 125(%rbx)|movl %ecx, 121(%rbx)|'+
            'movq $1, 128(%rbx)|movw $512, 136(%rbx)|movb %al, 120(%rbx)',
            'movq 12960(%rbp), %r15|movq %r15, 160(%rbx)|movq $0, 168(%rbx)|'+
            'leaq 87(%rbx), %r15|movq %r15, 144(%rbx)|'+
            'leaq anon.3ef910c435fe6014901c474933ee5d22.0(%rip), %r15|movq %r15, 152(%rbx)',
            '.Ltmp70:|leaq 144(%rbx), %rax|movq %rax, 40(%rsp)|movq %rdi, 32(%rsp)|'+
            'leaq 4640(%rbx), %rcx|leaq 120(%rbx), %rdx|leaq 192(%rbx), %r8|'+
            'leaq 352(%rbx), %r9|vzeroupper|callq '+role(bodies,'executor')])
        executor=bodies[role(bodies,'executor')]
        s.sequences(executor,[
            'subq $1192, %rsp|.seh_stackalloc 1192|leaq 128(%rsp), %rbp|.seh_setframe %rbp, 128',
            'movq %r8, 1040(%rbp)|movq %rdx, %r15|movq %rcx, %rsi|movq 1168(%rbp), %rdi',
            '.B4:|movq (%r15), %rax|testq %rax, %rax|je .B8|cmpb $1, 16(%rax)|'+
            'movq %r15, 1048(%rbp)|jne .B12|movzbl 17(%rax), %ecx|.Ltmp36:|'+
            'movq %rax, 1024(%rbp)|vzeroupper|callq *8(%rax)|nop|.Ltmp37:|testb %al, %al|'+
            'movq 1048(%rbp), %r15|movq 1024(%rbp), %rax|je .B12',
            '.B98:|movq %r15, 1048(%rbp)|movq 1176(%rbp), %rax|movq (%rax), %rcx|'+
            'movq 8(%rax), %rax|movq 32(%rax), %rax|.Ltmp38:|movq %rcx, 960(%rbp)|'+
            'movq %rax, 920(%rbp)|callq *%rax|nop|.Ltmp39:|movb $10, %r14b|'+
            'testb %al, %al|movq 1168(%rbp), %rdi|movq 1048(%rbp), %r15|jne .B1',
            'movq (%rcx), %rax|movq %rax, 920(%rbp)|movq 8(%rcx), %rax|movq %rax, 1032(%rbp)',
            '.Ltmp46:|movq 920(%rbp), %rcx|movq 1032(%rbp), %rax|callq *32(%rax)|nop|'+
            '.Ltmp47:|testb %al, %al|jne .B227',
            '.B233:|movq 1176(%rbp), %rax|movq (%rax), %rcx|movq 8(%rax), %rax|'+
            '.Ltmp52:|vzeroupper|callq *32(%rax)|nop|.Ltmp53:|movl %eax, %r14d|'+
            'testb %al, %al|je .B237',
            'movq 1048(%rbp), %rax|movq (%rax), %rcx|movq (%rcx), %rbx|.Ltmp44:|'+
            'movq 1000(%rbp), %rdx|movq 1168(%rbp), %r8|movq 952(%rbp), %r9|callq '+role(bodies,'session'),
            '.B237:|.Ltmp54:|movq 1048(%rbp), %rcx|callq '+role(bodies,'executor_check')])
        for number in (40,42):
            s.sequences(executor,[f'.Ltmp{number}:|movq 960(%rbp), %rcx|vzeroupper|callq *920(%rbp)|'+
                f'nop|.Ltmp{number+1}:|testb %al, %al|jne .B227'])
        for number in (48,50):
            s.sequences(executor,[f'.Ltmp{number}:|movq %rdi, %rcx|leaq 784(%rbp), %r8|'+
                'callq '+role(bodies,'padding')])
        result=dict(control_frame_offset=144,data_frame_offset=87,authority_frame_offset=88,
            packed_executor_offset=120,executor_control_argument_frame_offset=1176,
            remaining_indirect_sites_locally_checked=8,padding_control_argument_checked=True)
    result.update(callbacks_internal_not_host_supplied=True,
        complete_alias_and_storage_composition_pending=True)
    return result


def digest_handlers(bodies,lane):
    """Review each remaining invoked handler, including armed conditional drops."""
    narrow=lane=='simd256';parent=role(bodies,'resident')
    output=s.one(bodies,r'output.*SecretBatchOutput.*Drop4drop$')
    workspace=s.one(bodies,r'hash_sha2.*workspace.*Workspace4wipe$')
    drop=s.one(bodies,r'^_RIN.*drop_glue.*workspace9WorkspaceE')
    entries={};checked={}
    revoke='movq 88(%rbx), %rax|movb $0, 16(%rax)'
    for number in ((275,276,279,280) if narrow else (95,96)):
        entries[(parent,number)]=([revoke],None)
    offset,flag,number,skip=(2912,71,272,274) if narrow else (352,55,91,93)
    entries[(parent,number)]=([f'leaq {offset}(%rbx), %rcx|callq '+output],
        (f'cmpb $0, {flag}(%rbx)',f'je .B{skip}'))
    scratch,work,number=(3936,6688,278) if narrow else (1376,7200,94)
    entries[(parent,number)]=([
        f'leaq {scratch}(%rbx), %rcx|movl $256, %edx|callq '+s.ZERO,
        f'leaq {work}(%rbx), %rcx|callq '+drop],None)
    pointer,flag,phase,output_offset,number,skip=(152,55,280,16,281,283) if narrow else (64,54,288,24,97,99)
    clear=f'movq {pointer}(%rbx), %rsi|leaq {output_offset}(%rsi), %rcx|movl $256, %edx|callq '+s.ZERO
    clear+=('|movb $2, (%rsi)' if narrow else '|movw $-1, (%rsi)')
    clear+=f'|movb $2, {phase}(%rsi)|movq {8 if narrow else 16}(%rsi), %rax|movb $0, 16(%rax)'
    entries[(parent,number)]=([clear],(f'testb $1, {flag}(%rbx)',f'jne .B{skip}'))
    if narrow:
        entries[(parent,277)]=(['leaq 6688(%rbx), %rcx|callq '+workspace,
            revoke,'leaq 864(%rbx), %rcx|callq '+output],None)
    else:
        executor=role(bodies,'executor')
        entries[(executor,303)]=(['movq 1024(%rbp), %rax|movb $0, 16(%rax)'],None)
        entries[(executor,304)]=([
            'movq 1168(%rbp), %rcx|callq '+workspace,
            'movq 1048(%rbp), %rax|movb $1, 16(%rax)',
            'leaq 816(%rbp), %rcx|callq '+output],None)
        body=bodies[s.one(bodies,r'^\?dtor\$304@.*'+re.escape(executor)+r'@')]
        s.sequences(body,['movq (%rax), %rax|testq %rax, %rax|je .B306|movb $0, 16(%rax)|.B306:'])
    for (caller,number),(events,guard) in entries.items():
        name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@.*'+re.escape(caller)+r'@')
        body=bodies[name];start=f'.B{number}'
        frame='leaq 128(%rdx), %rbp|.seh_endprologue'
        if caller==parent: frame+='|andq $-32, %rdx|movq %rdx, %rbx'
        s.sequences(body,[frame,*events])
        armed=body
        if guard:
            # Inspect the armed path without treating a permitted unarmed return
            # as proof of cleanup. The exact real guard and fallthrough are pinned.
            condition,branch=guard
            s.sequences(body,[condition+'|'+branch+'|'+events[0]])
            lines=s.lines(body);s.require(lines.count(branch)==1,'unique conditional cleanup skip')
            lines[lines.index(branch)]='nop';armed='\n'.join(lines)
        returns=[s.normal_returns(armed,start,e.split('|')) for e in events]
        checked[name]=dict(parent=caller,events=events,conditional_guard=guard,
            required_event_return_sites=returns,return_check_scope='armed' if guard else 'all')
    return checked


def cleanup_tables(assembly,bodies,lane):
    """Exact saved FH3 state chains, not an implementation of the OS dispatcher."""
    narrow=lane=='simd256'
    profiles={
        'session':(20 if narrow else 18,48,[(-1,15),(0,16),(0,14)],
                   [(28,2),(30,1),(31,-1)] if narrow else [(26,2),(28,1),(29,-1)]),
        'check':(28,40,[(-1,9),(-1,10)],
                 [(38,0),(40,1),(41,-1)] if narrow else [(58,0),(60,1),(61,-1)]),
        'owner':(29,48,[(-1,12),(0,17),(0,16)],
                 [(42,2),(44,1),(45,-1)] if narrow else [(62,2),(64,1),(65,-1)]),
        'resident':(35,11984,[(-1,281),(0,278),(1,272),(1,277),(3,275),(3,276),(0,279),(0,280)],
                    [(46,7),(48,6),(49,-1),(50,5),(52,3),(62,4),(64,2),(67,-1)]) if narrow else
                   (35,12976,[(-1,97),(0,94),(1,91),(0,95),(0,96)],
                    [(66,4),(68,3),(69,-1),(70,1),(72,2),(75,-1)])}
    if not narrow:
        profiles['executor']=(23,1184,[(-1,304),(0,303)],[(36,1),(38,0),(55,-1)])
        profiles['executor_check']=(24,40,[(-1,4)],[(56,0),(57,-1)])
    expected={};result={}
    for kind,(begin,frame,states,ips) in profiles.items():
        name=role(bodies,kind);funclets=[s.one(bodies,r'^\?dtor\$'+str(n)+r'@.*'+re.escape(name)+r'@')
                                      for _,n in states]
        prefix={p:p+name for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
        expected[prefix['$cppxdata$']]=['429065506',str(len(states)),prefix['$stateUnwindMap$']+'@IMGREL',
            '0','0',str(len(ips)+1),prefix['$ip2state$']+'@IMGREL',str(frame),'0','1']
        expected[prefix['$stateUnwindMap$']]=[v for (parent,_),f in zip(states,funclets)
                                                   for v in (str(parent),'"'+f+'"@IMGREL')]
        expected[prefix['$ip2state$']]=[f'.Lfunc_begin{begin}@IMGREL','-1']+[
            v for number,state in ips for v in (f'.Ltmp{number}@IMGREL',str(state))]
        chains={}
        for number,state in ips:
            chain=[]
            while state!=-1:
                s.require(0<=state<len(states) and funclets[state] not in chain,'finite assigned cleanup chain')
                chain.append(funclets[state]);state=states[state][0]
            chains[f'.Ltmp{number}']=chain
        result[name]=dict(frame_state_offset=frame,ordered_handlers_from_ip=chains)
    for label,want in expected.items():
        matches=list(re.finditer(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M))
        s.require(len(matches)==1,'unique saved cleanup table '+label)
        actual=[line.strip().split(None,1)[1] for line in matches[0][1].splitlines()]
        s.require(actual==want,'exact cleanup state/order table '+label)
    actual=set(re.findall(r'^(\$(?:cppxdata|stateUnwindMap|ip2state)\$[^:\n]+):',assembly,re.M))
    s.require(actual==set(expected),'complete SIMD cleanup-table population')
    return dict(parents=result,expected_tables=expected,compiler_cleanup_order_checked=True,
        bound_object_and_image_metadata_required=True,os_dispatcher_qualified=False,
        enclosing_storage_lifetimes_pending=True)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'two SIMD authority profiles')
    calls=population(bodies,lane)
    covered={role(bodies,x) for x in ('session','owner','check')}
    if lane=='simd512': covered.add(role(bodies,'executor_check'))
    unwind=handlers(bodies,lane);unwind['invoked_funclets'].update(digest_handlers(bodies,lane))
    s.require(set(unwind['invoked_funclets'])=={n for n in bodies if n.startswith('?dtor$')},
              'all emitted SIMD funclets assigned a cleanup role')
    return dict(indirect_population=calls,authority_session=session(bodies,lane),
        authority_checks=checks(bodies,lane),callback_unwind=unwind,
        padding_helper=padding(bodies,lane),
        digest_callback_sources=digest_callers(bodies,lane),
        locally_checked_authority_sites={n:calls[n] for n in sorted(covered)},
        remaining_digest_and_padding_sites={n:v for n,v in calls.items() if n not in covered},
        complete_callback_provenance_qualified=False)
