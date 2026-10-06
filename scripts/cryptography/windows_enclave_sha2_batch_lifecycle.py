"""Sequential SHA-2 batch terminal/retirement composition for frozen images."""
import re
import windows_enclave_kmac_shapes as s


def owner(bodies,role): return s.one(bodies,r'Owner\d+'+role+'$')


def sealing(bodies,lane):
    scalar=lane=='scalar';plan=16 if scalar else 2016
    phase=1782 if scalar else 2616;bitmap=phase+1
    body=bodies[owner(bodies,'seal')]
    s.sequences(body,['movb $1, %r9b|callq '+owner(bodies,'operation'),
        f'cmpq $0, {plan}(%rsi)|movzbl {bitmap}(%rsi), %eax|sete %dl|orb %al, %dl|testb $1, %dl|je .B10'])
    for slot in range(1,7):
        s.sequences(body,[f'cmpq $0, {plan+8*slot}(%rsi)|setne %dl|testb ${1<<slot}, %al|'
            'sete %r8b|testb %r8b, %dl|jne .B10'])
    success='.B14' if scalar else '.B17'
    s.sequences(body,[f'cmpq $0, {plan+56}(%rsi)|setne %dl|testb %al, %al|setns %al|andb %dl, %al|'
        'cmpb $1, %al|jne '+success,
        success+f':|movb $3, {phase}(%rsi)|movb $-1, %al'])
    return dict(slots=8,each_nonempty_slot_requires_completion_bit=True,
        required_phase='Collecting',success_phase='Sealed')


def clearing(bodies,lane):
    scalar=lane=='scalar';phase=1782 if scalar else 2616
    output=80 if scalar else 2080;budget=600 if scalar else 2608
    active=0 if scalar else 2000
    clear=owner(bodies,'clear');body=bodies[clear]
    wipe=s.one(bodies,r'HardenedSha2Owner4wipe$')
    if scalar:
        s.sequences(body,['leaq 608(%rcx), %rdx|leaq 42(%rsp), %rcx|movl $1174, %r8d|callq memcpy',
            'movb $-1, 608(%rsi)|movzbl 42(%rsp), %eax|cmpb $-1, %al|je .B2',
            'xorl %ecx, %ecx|cmpb $6, %al|setae %cl|leaq (%rcx,%rcx,2), %rax|'
            'leaq (%rsp,%rax), %rcx|addq $43, %rcx|callq '+wipe])
    else:
        scratch=s.one(bodies,r'Scratch4wipe$')
        s.sequences(body,['leaq 32(%rsp), %rcx|movl $2000, %r8d|movq %rsi, %rdx|callq memcpy',
            'movq $0, 8(%rsi)|movq $2, (%rsi)',
            'vptest %xmm0, %xmm0|je .B3|leaq 848(%rsp), %rcx|callq '+wipe+
            '|cmpq $0, 112(%rsp)|je .B3|leaq 128(%rsp), %rcx|callq '+scratch])
    # A taken State is erased through its owner (and live SHA-NI scratch).
    # Compiler-created moved-from copies remain with whole-window reclamation.
    s.sequences(body,[f'movb $0, {phase+1}(%rsi)|movq $0, '+
        ('' if scalar else str(active))+f'(%rsi)|movq $0, {budget}(%rsi)'])
    cancel=owner(bodies,'cancel');body=bodies[cancel]
    s.sequences(body,[f'movzbl {phase}(%rcx), %r9d|leal -1(%r9), %eax|cmpb $3, %al|jae .B1',
        f'movq $0, {budget}(%rsi)|movw $0, {phase}(%rsi)|movb $-1, %al'])
    starts=('.B3','.B8') if scalar else ('.B4','.B12')
    event=[f'leaq {output}(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO]
    returns={n:s.normal_returns(body,n,event) for n in starts}
    return dict(taken_state_bytes=1174 if scalar else 2000,output_bytes=512,
        cancellation_phases=['Collecting','Streaming','Sealed'],
        cancellation_cleanup_return_sites=returns,moved_from_copies_individually_erased=False)


def export(bodies,lane):
    scalar=lane=='scalar';name=s.one(bodies,r'worker7receive$');body=bodies[name]
    clear=owner(bodies,'clear');guard=s.one(bodies,r'Operation.*Drop4drop$')
    if scalar:
        s.sequences(body,['movb $3, %r9b|callq '+owner(bodies,'operation'),
            'leaq 16(%rdi), %rdx|leaq 128(%rsp), %rcx|movl $64, %r8d|callq memcmp|testl %eax, %eax|jne .B58',
            'leaq 80(%rdi), %rcx|movl $512, %edx|callq PublicSha2BatchOutput|testl %eax, %eax|je .B65',
            '.B58:|movq %rdi, %rcx|movl %ebx, %edx|callq '+guard+'|jmp .B61',
            '.B65:|movq %rdi, %rcx|callq '+clear+'|movb $1, %bl|xorl %eax, %eax|movb %al, 1782(%rdi)'])
        start='.B65'
    else:
        check=s.one(bodies,r'15check_authority$')
        s.sequences(body,['movb $3, %r9b|vzeroupper|callq '+owner(bodies,'operation'),
            'vmovdqu 64(%rsp), %ymm0|vmovdqu 96(%rsp), %ymm1|vpxor 2048(%rdi), %ymm1, %ymm1|'
            'vpxor 2016(%rdi), %ymm0, %ymm0|vpor %ymm1, %ymm0, %ymm0|vptest %ymm0, %ymm0|je .B18',
            'leaq 2080(%rdi), %rcx|movl $512, %edx|vzeroupper|callq PublicSha2BatchOutput|'
            'movl %eax, %ecx|movb $5, %al|testl %ecx, %ecx|jne .B20',
            'movq 2592(%rdi), %rcx|callq '+check+'|cmpb $-1, %al|je .B21',
            '.B20:|movq %rdi, %rcx|movl %ebx, %edx|movl %eax, %edi|callq '+guard,
            '.B21:|movq %rdi, %rcx|callq '+clear+'|movb $0, 2616(%rdi)|movb $-1, %al'])
        start='.B21'
    sites=s.normal_returns(body,start,['callq '+clear])
    return dict(function=name,identity_bytes_compared=64,export_bytes=512,
        fixed_transport='PublicSha2BatchOutput',copy_result_checked=True,
        post_copy_authority_check=not scalar,successful_export_cleanup_return_sites=sites,
        success_phase='Empty',transport_internals_shared=True)


def operation_guard(bodies,lane):
    scalar=lane=='scalar';name=s.one(bodies,r'Operation.*Drop4drop$');body=bodies[name]
    phase=1782 if scalar else 2616;output=80 if scalar else 2080
    done='.B4' if scalar else '.B7';cleanup='.B3' if scalar else '.B4'
    s.sequences(body,['testb $1, %dl|jne '+done+'|movq %rcx, %rsi'])
    event=[f'leaq {output}(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO]
    sites=s.normal_returns(body,cleanup,event)
    s.sequences(body,[f'movw $4, {phase}(%rsi)' if scalar else f'movb $4, {phase}(%rsi)'])
    if not scalar:
        s.sequences(body,['movq 2592(%rsi), %rax|cmpb $2, 8(%rax)|je .B6|movb $2, 8(%rax)|movq $3, (%rax)'])
    return dict(function=name,completed_guard_bypasses_quarantine=True,
        incomplete_guard_quarantines=True,output_cleanup_return_sites=sites,
        authority_quarantined=not scalar,arbitrary_os_unwind_qualified=False)


def retirement(bodies,lane):
    scalar=lane=='scalar';work=bodies['RetainedWork'];drop=s.one(bodies,r'worker7BuffersE')
    start='.B14' if scalar else '.B20'
    sites=s.normal_returns(work,start,['callq '+drop])
    buffer=drop if scalar else s.one(bodies,r'worker.*Buffers5clear$')
    for name in sorted({buffer,drop}):
        s.sequences(bodies[name],['addq $1024, %rcx|movl $'+('128' if scalar else '144')+', %edx|callq '+s.ZERO,
            'movl $1024, %edx|movq %rsi, %rcx','jmp '+s.ZERO])
    if scalar:
        live=s.one({n:0 for n in re.findall(r'(_RN\w+4LIVE\.0)\(%rip\)',work)},r'LIVE\.0$')
        destructor=s.one(bodies,r'Owner.*Drop4drop$')
        s.sequences(work,['cmpq $3, %rcx|jne .B14|movq %rdx, %rdi|movq %rsi, %rcx|callq '+destructor,
            '.B12:|movq $0, '+live+'(%rip)|xorl %ecx, %ecx|movl $4, %eax|.p2align 4|.B13:'])
        body=work;label='.B13';pointer='rdi';index='rcx';entry='.B12'
    else:
        destructor=s.one(bodies,r'Resident.*Drop4drop$');body=bodies[destructor]
        live=s.one({n:0 for n in re.findall(r'(_RN\w+4LIVE)\(%rip\)',work)},r'LIVE$')
        page=s.one({n:0 for n in re.findall(r'(_RN\w+9LIVE_PAGE\.0)\(%rip\)',work)},r'LIVE_PAGE\.0$')
        s.sequences(work,['cmpq $3, %rcx|jne .B20',
            'movq $0, '+live+'(%rip)|movq %rax, %rcx|callq '+destructor+
            '|movq $0, '+page+'(%rip)|movl $4, %esi'])
        s.sequences(body,['movb $4, 2616(%rdi)', '.B8:|xorl %eax, %eax|.p2align 4|.B9:'])
        label='.B9';pointer='rsi';index='rax';entry=destructor
    event=['movb $0, '+('' if i==0 else str(i))+f'(%{pointer},%{index})' for i in range(8)]
    event += [f'addq $8, %{index}',f'cmpq $4096, %{index}','jne '+label]
    s.sequences(body,[label+':|'+'|'.join(event)])
    erased=s.normal_returns(body,entry,event)
    return dict(post_buffer_construction_return_sites=sites,buffer_destructor=drop,
        header_bytes=128 if scalar else 144,payload_bytes=1024,
        typed_destructor=destructor,page_erasure_bytes=4096,page_cleanup_return_sites=erased,
        enclosing_stack_window_reclamation_pending=True)


def inspect(bodies,lane):
    s.require(lane in ('scalar','sha_ni'),'two sequential batch routes only')
    return dict(sealing=sealing(bodies,lane),clearing=clearing(bodies,lane),
        export=export(bodies,lane),operation_guard=operation_guard(bodies,lane),
        retirement=retirement(bodies,lane),
        primitive_and_finalizer_composition_pending=True)
