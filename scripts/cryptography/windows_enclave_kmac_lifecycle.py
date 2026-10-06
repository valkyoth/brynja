"""Saved KMAC lifecycle/placement checks; not a whole-image qualification."""
import windows_enclave_kmac_shapes as s

require=s.require


def owner(bodies,role):
    return s.one(bodies,r'Owner\d+'+role+'$')


def state_drop(bodies,lane):
    pattern=(r'drop_glue.*kmac_stream_state5StateEBF_$' if lane=='scalar' else
             r'drop_glue.*kmac_accelerated_state5StateEBF_$')
    return s.one(bodies,pattern)


def clear_sequence(bodies,lane,register):
    tag=([f'movb $0, 1024(%{register})'] if lane=='scalar' else
         [f'movq $0, 2040(%{register})',f'movq $2, 2032(%{register})'])
    return ['callq '+state_drop(bodies,lane),*tag,'movl $1024, %edx',
            f'movq %{register}, %rcx','callq '+s.ZERO,
            f'movq $0, {3288 if lane=="scalar" else 2152}(%{register})']


def clearing(bodies,lane):
    width,last,identity=(3288,3296,3298) if lane=='scalar' else (2152,2168,2170)
    name=owner(bodies,'clear');event=clear_sequence(bodies,lane,'rsi')
    s.sequences(bodies[name],['|'.join(event)+f'|movb $0, {last}(%rsi)|movb $-1, {identity}(%rsi)'])
    s.normal_returns(bodies[name],name,event)
    drop=s.one(bodies,r'Operation.*Drop4drop$')
    end='.B2' if lane=='scalar' else '.B4'
    s.sequences(bodies[drop],['testb $1, %dl|jne '+end,
        '|'.join(event)+f'|movw $2048, {last}(%rsi)|movb $-1, {identity}(%rsi)'])
    if lane=='avx2':
        s.sequences(bodies[drop],['movq 2160(%rcx), %rax|cmpb $2, 8(%rax)|je .B3|'
            'movb $2, 8(%rax)|movq $3, (%rax)'])
    else:
        quarantine=owner(bodies,'quarantine')
        s.normal_returns(bodies[quarantine],quarantine,event)
        s.sequences(bodies[quarantine],[f'movw $2048, {last}(%rsi)|movb $-1, {identity}(%rsi)'])
    return dict(state_drop=state_drop(bodies,lane),output_bytes=1024,width_offset=width,
                incomplete_operation_quarantines=True,active_state_not_full_allocation=True)


def operation(bodies,lane):
    name=owner(bodies,'operation');body=bodies[name]
    if lane=='scalar':
        s.sequences(body,['movzbl 3297(%rdx), %eax|andb $14, %al|cmpb $6, %al|jne .B1',
            'movq 3280(%rdi), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B4',
            'movq %r8, 3280(%rdi)|movq %rdi, (%rsi)|xorl %eax, %eax'])
        event=clear_sequence(bodies,lane,'rdi')
        require('\n'.join(s.lines(body)).count('\n'.join(event))==2,'both scalar operation rejections clear')
        s.normal_returns(body,'.B1',event)
    else:
        s.sequences(body,['movq 2144(%rsi), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|'
            'testb %al, %cl|jne .B22',
            'movq 2160(%rsi), %rax|movzbl 8(%rax), %ecx|movzbl 9(%rax), %edx|'
            'xorb $4, %dl|movl %ecx, %r9d|xorb $1, %r9b|orb %dl, %r9b|jne .B23',
            'movq %r8, 2144(%rsi)|movq %rsi, (%rdi)|movb $0, 8(%rdi)'])
        for start in ('.B21','.B15','.B25'):
            s.normal_returns(body,start,clear_sequence(bodies,lane,'rsi'))
    return dict(checked_nonwrapping_sequence=True,phase_admission=True,
                accelerated_authority_health_and_kernel=(lane=='avx2'),
                error_clears_retained_output=True)


def errors_and_transitions(bodies,lane):
    # These are the exact saved error blocks, after any guard decision. The
    # operation result and guard branches are independently checked above and
    # by the compiled rejection/unwind campaigns, not assumed arbitrary inputs.
    rows=([('update','.B14','rsi'),('finish','.B2','rsi'),('squeeze','.B2','rsi'),
           ('finish_setup','.B4','rsi'),('key','.B9','rsi'),
           ('begin_setup','.B2','rsi'),('rekey_setup','.B2','rsi'),
           ('customization','.B16','rsi'),('finish_customization','.B2','rsi'),
           ('finish_customization','.B43','rsi')] if lane=='scalar' else
          [('update','.B13','rsi'),('finish','.B29','r14'),('squeeze','.B10','r14'),
           ('finish_setup','.B7','rdi'),('key','.B10','rdi'),
           ('begin_setup','.B11','r14'),('rekey_setup','.B16','r15'),
           ('customization','.B15','rdi'),('finish_customization','.B43','r12')])
    result={}
    for role,start,register in rows:
        name=owner(bodies,role);event=clear_sequence(bodies,lane,register)
        result.setdefault(name,{})[start]=s.normal_returns(bodies[name],start,event)
    update,finish,squeeze=[bodies[owner(bodies,n)] for n in ('update','finish','squeeze')]
    if lane=='scalar':
        s.sequences(update,['cmpb $4, 3297(%rcx)|jne .B14',
            'testb %al, %al|jne .B14|movq %rdi, 2066(%rsi)|movq %r14, 2074(%rsi)|movb $-1, %bl'])
        s.sequences(finish,['movq %r12, 3288(%rsi)|movb %r15b, 3296(%rsi)|movb $-1, %dil|movb $7, %al',
                            '.B40:|movb $-1, %dil|movb $5, %al|jmp .B3'])
        s.sequences(squeeze,['cmpb $5, 3297(%rcx)|jne .B2',
            'movq %rdi, 3288(%rsi)|movb %r12b, 3296(%rsi)|orb $6, %bpl|movb $-1, %bl'])
        cancel=owner(bodies,'cancel')
        s.normal_returns(bodies[cancel],cancel,clear_sequence(bodies,lane,'rsi'))
        s.sequences(bodies[cancel],['movq %rdx, 3280(%rsi)|movb $-1, %bl|xorl %edi, %edi',
                                  'movb %dil, 3297(%rsi)'])
    else:
        s.sequences(update,['cmpb $2, 2113(%rsi)|jne .B7','.B5:|movb $-1, %bl|jmp .B14'])
        s.sequences(finish,['movq %rdi, 2152(%r14)|movb %bl, 2168(%r14)|movb $7, %al|jmp .B12',
            'movb $3, 2113(%r14)|movb $5, %al|.B12:|movb %al, 2169(%r14)|movb $-1, %al'])
        s.sequences(squeeze,['cmpb $3, 2113(%r14)|jne .B16',
            'movq %rdi, 2152(%rbx)|movb %sil, 2168(%rbx)|movb %al, 2169(%rbx)|movb $-1, %al'])
        cancel=owner(bodies,'cancel')
        s.normal_returns(bodies[cancel],'.B2',clear_sequence(bodies,lane,'rsi'))
        s.sequences(bodies[cancel],['movq $0, 2152(%rsi)|movw $0, 2168(%rsi)|movb $-1, 2170(%rsi)'])
    return dict(error_block_return_sites=result,streaming_phase=4,squeezing_phase=5,
                retained_more_phase=6,retained_final_phase=7,quarantined_phase=8,
                successful_cancellation_returns_empty=True)


def staging(bodies,lane):
    result={}
    if lane=='scalar':
        for role,offset,starts in (('finish',1103,['.B27','.B21','.B28']),
                                   ('squeeze',96,['.B19','.B32'])):
            name=owner(bodies,role)
            event=[f'leaq {offset}(%rsp), %rcx','movl $1024, %edx','callq '+s.ZERO]
            for start in starts: s.normal_returns(bodies[name],start,event)
            result[name]=dict(stack_offset=offset,bytes=1024,clear_on_staging_exits=True)
    else:
        name=s.one(bodies,r'sha3_accelerated_stateNtB5_5State7squeeze$');body=bodies[name]
        event=['leaq 32(%rsp), %rcx','movl $1024, %edx','callq '+s.ZERO]
        # One success path saves EAX between the count and call, but still
        # initializes both pointer and count and clears before any return.
        s.sequences(body,['|'.join(event),
            'leaq 32(%rsp), %rcx|movl $1024, %edx|movl %eax, %ebx|callq '+s.ZERO])
        alternative=['leaq 32(%rsp), %rcx','movl $1024, %edx','movl %eax, %ebx','callq '+s.ZERO]
        for start in ('.B24','.B15'): s.normal_returns(body,start,event,[alternative])
        result[name]=dict(stack_offset=32,bytes=1024,clear_on_staging_exits=True)
    return result


def full_page(bodies,lane):
    if lane=='scalar':
        body=bodies['RetainedWork'];base,index,start='rcx','rdx','.B7'
        s.sequences(body,['movq $0, _RNvCsaqpCAcTgG8H_18kmac_stream_worker4LIVE.0(%rip)|'
                          'xorl %edx, %edx|movl $4, %eax'])
        s.sequences(body,['callq '+owner(bodies,'quarantine')])
    else:
        name=s.one(bodies,r'Resident.*Drop4drop$');body=bodies[name]
        base,index,start='rsi','rax','.B3'
        s.sequences(body,['movq %rbx, %rcx|callq '+state_drop(bodies,lane)+'|xorl %eax, %eax'])
    writes=[f'movb $0, '+('' if n==0 else str(n))+f'(%{base},%{index})' for n in range(8)]
    event=writes+[f'addq $8, %{index}',f'cmpq $4096, %{index}','jne '+start]
    s.sequences(body,['|'.join(event)])
    s.normal_returns(body,start,event)
    return dict(bytes=4096,volatile_store_group_bytes=8,active_owner_drop_precedes_page_clear=True,
                inactive_enum_and_padding_cleared_on_retirement=True,
                arbitrary_exception_claim=False)


def inspect(bodies,lane):
    return dict(clearing=clearing(bodies,lane),operation=operation(bodies,lane),
                transitions=errors_and_transitions(bodies,lane),
                staging=staging(bodies,lane),resident_page=full_page(bodies,lane))
