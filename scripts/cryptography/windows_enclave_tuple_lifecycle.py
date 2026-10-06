"""TupleHash operation admission and finalization in the saved bodies."""
import windows_enclave_tuple_shapes as t

s=t.s


def operation(bodies,lane):
    name=t.owner(bodies,'operation');body=bodies[name]
    _,_,_,sequence,_,_,phase,_=t.offsets(lane)
    pointer='rdx' if lane=='scalar' else 'rsi'
    destination='rsi' if lane=='scalar' else 'rdi'
    success='.B16' if lane=='scalar' else '.B26'
    s.sequences(body,[f'movzbl {phase}(%rdx), %eax|cmpb %al, (%r9)|jne .B1',
        f'movq {sequence}(%{pointer}), %rax|incq %rax|setne %cl|cmpq %r8, %rax|'
        'sete %al|testb %al, %cl|jne '+success,
        f'movq %r8, {sequence}(%{pointer})|movq %{pointer}, (%{destination})'])
    # All seven permitted-phase comparisons, including the last rejection.
    for index in range(1,7):
        s.sequences(body,[f'cmpq ${index}, %rcx|'+('jne .B2' if index==1 else 'je .B13'),
            f'cmpb %al, {index}(%r9)|je '+('.B17' if lane=='scalar' else '.B20')])
    s.sequences(body,['cmpb %al, 6(%r9)|je '+('.B17' if lane=='scalar' else '.B20')+'|jmp .B13'])
    if lane=='avx2':
        s.sequences(body,['movq 2056(%rsi), %rax|movzbl 8(%rax), %ecx|movzbl 9(%rax), %edx|'
            'xorb $4, %dl|movl %ecx, %r9d|xorb $1, %r9b|orb %dl, %r9b|jne .B27',
            'movb $2, 8(%rax)|movq $3, (%rax)'])
    # Start after the guard decision: prove complete cleanup before returning
    # from the three AVX2 rejection blocks and the scalar wrong-phase block.
    # The scalar sequence rejection shares the same complete inline event.
    event=t.clear_event(lane,'rdi' if lane=='scalar' else 'rsi')
    starts=['.B13'] if lane=='scalar' else ['.B23','.B15','.B29']
    returns={start:s.normal_returns(body,start,event) for start in starts}
    s.require('\n'.join(s.lines(body)).count('\n'.join(event))==(2 if lane=='scalar' else 3),
              'every operation rejection retains the complete inline clearing sequence')
    return dict(nonwrapping_exact_sequence=True,allowed_phase_comparisons=7,
                authority_health_and_kernel_checked=(lane=='avx2'),rejection_return_sites=returns)


def cancellation(bodies,lane):
    name=t.owner(bodies,'cancel');body=bodies[name];phase=t.offsets(lane)[6]
    s.sequences(body,['callq '+t.owner(bodies,'operation')+'|cmpb $2, 56(%rsp)|jne .B2',
                     f'movb $0, {phase}(%rsi)|movb $-1, %al'])
    return dict(admitted_return_sites=s.normal_returns(body,'.B2',t.clear_event(lane)),
                returns_empty=True,admission_failure_delegates_to_operation=True)


def suffix(bodies,lane):
    body=bodies[t.owner(bodies,'finish')]
    _,_,identity,_,width,packer,phase,last=t.offsets(lane)
    pointer,output,tail,fixed=('rsi','rbx','dil','r13b') if lane=='scalar' else ('r14','rdi','sil','r12b')
    reject='.B25' if lane=='scalar' else '.B30'
    s.sequences(body,[f'cmpq $1024, %{output}|ja '+reject,
        f'cmpq $3, {identity}(%{pointer})|setb %{fixed}|setae %cl|movq %rdx, %rax|'
        'orq %r8, %rax|setne %r9b|movb $3, %al|testb %cl, %r9b|je .B8|jmp '+reject,
        'movq %r15, %rcx|movb $1, %r9b|callq '+s.ENCODE])
    if lane=='scalar':
        s.sequences(body,['callq '+s.one(bodies,r'Packer6append$')+'|cmpb $-1, %al|je .B9',
            'movzbl 2201(%rsi), %ebp|testb %bpl, %bpl|je .B10|movb $4, %al|cmpb $8, %bpl|ja .B25',
            'callq '+s.CORE+'13secret_memory24secret_byte_mask_is_zero|movl %eax, %ecx|'
            'movb $4, %al|movl %ebp, %edx|testb %cl, %cl|je .B25',
            f'movb $0, {packer+1}(%rsi)|movb $5, %al|testb %{fixed}, %{fixed}|je .B21',
            f'movq %rbx, {width}(%rsi)|movb %dil, {last}(%rsi)|movb $6, %al|'
            f'.B21:|movb %al, {phase}(%rsi)|movb $-1, %al'])
    else:
        s.sequences(body,['callq '+s.one(bodies,r'Packer6append$')+'|cmpb $-1, %al|jne .B29',
            'cmpb $8, %r15b|ja .B28',
            'callq '+s.CORE+'13secret_memory24secret_byte_mask_is_zero|movl %eax, %ecx|'
            'movb $4, %al|movq %r14, %r13|movl %r15d, %edx|testb %cl, %cl|jne .B14',
            f'movb $0, {packer+1}(%rdx)|movb $5, %al|testb %{fixed}, %{fixed}|je .B24',
            f'movq %rdi, {width}(%rdx)|movb %sil, {last}(%rdx)|movb $6, %al|'
            f'.B24:|movb %al, {phase}(%rdx)|movb $-1, %al'])
    return dict(right_encoding_selector=1,fixed_identities=[1,2],xof_rejects_nonzero_output_bits=True,
                partial_byte_canonicality=True,reader_phase=5,retained_phase=6,
                state_finalizer_and_reader_composition_pending=False)


def completion(bodies,lane):
    custom=bodies[t.owner(bodies,'custom')];finish=bodies[t.owner(bodies,'finish')]
    if lane=='scalar':
        s.sequences(custom,['cmpq $1024, 8(%rdi)|ja .B10',
            'movzbl (%rsi), %ecx|cmpl $2, %ecx|je .B6|movb $2, %al|cmpl $1, %ecx|jne .B10'])
        for rate in ('a8','88'):
            s.sequences(custom,['leaq 16(%rsi), %rcx|movb $1, %dl|movq %rdi, %r8|callq '+
                s.one(bodies,rf'SetupKj{rate}_E4push')])
        for strength in ('128','256'):
            s.sequences(finish,['leaq 1(%rsi), %rcx|leaq 48(%rsp), %rdx|callq '+
                s.one(bodies,'HardenedCshake'+strength+'24enter_squeezing_in_place')])
        s.sequences(finish,['.B19:|movl %eax, %ecx|movb $6, %al|cmpb $-1, %cl|jne .B25',
            'leaq 1152(%rsi), %rdx|movb $1, 32(%rsp)|movq %rsi, %rcx|movq %rbx, %r8|'
            'movl %edi, %r9d|callq '+s.one(bodies,r'tuple_stream_state.*State7squeeze$')+
            '|cmpb $-1, %al|jne .B25',
            'callq '+s.one(bodies,r'drop_glue.*tuple_stream_state5StateE')+'|movb $0, (%rsi)|movq %rbx, 2192(%rsi)'])
    else:
        s.sequences(custom,['cmpq $1024, 8(%rsi)|jbe .B3',
            'leaq 1024(%r14), %rcx|xorl %edx, %edx|movq %rsi, %r8|callq '+s.one(bodies,r'State11setup_chunk$')])
        s.sequences(finish,['leaq 184(%rbp), %rdx|movq 248(%rbp), %rcx|callq '+s.one(bodies,r'State10finish_xof$'),
            '.Ltmp17:|movl %eax, %ecx|movb $6, %al|cmpb $-1, %cl|jne .B28',
            'movb $1, 32(%rsp)|movq 248(%rbp), %r14|movq %r14, %rcx|movq %rdi, %r8|'
            'movl %esi, %r9d|callq '+s.one(bodies,r'State7squeeze$'),
            '.Ltmp19:|movl %eax, %ecx|movb $6, %al|cmpb $-1, %cl|movzbl 271(%rbp), %ebx|jne .B29',
            '.B23:|movq $-1, 1968(%rdx)|movq %rdi, 2048(%rdx)|movb %sil, 2066(%rdx)|movb $6, %al'])
    return dict(customization_limit=1024,customization_selector=1 if lane=='scalar' else 0,
                fixed_output_uses_terminal_reader=True,error_cleanup='operation guard',
                consumed_state_disarmed_before_retained_output=True)


def inspect(bodies,lane):
    return dict(operation_admission=operation(bodies,lane),cancellation=cancellation(bodies,lane),
                final_suffix=suffix(bodies,lane),state_completion=completion(bodies,lane))
