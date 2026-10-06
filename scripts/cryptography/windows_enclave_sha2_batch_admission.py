"""Initial placement and public plan admission in frozen sequential images."""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_batch_state as state
import windows_enclave_sha2_batch_kat as kat


def admitted_plan(plan,lane):
    """Public arithmetic cross-check; not execution of the saved instructions."""
    s.require(lane in ('scalar','sha_ni'),'sequential plan lane')
    s.require(len(plan)==8 and all(type(x) is int and 0<=x<1<<64 for x in plan),'eight u64 identities')
    return any(plan) and all(x==0 or (state.decoded_width(x) is not None if lane=='scalar'
                                    else x<=2) for x in plan)


def scalar_begin(bodies):
    body=bodies[state.owner(bodies,'begin')]
    s.sequences(body,[
        'movq %r9, %rsi|movq %r8, %rdi|movq %rdx, %r8|movq %rcx, %rdx|'
        'leaq 40(%rsp), %rcx|xorl %r9d, %r9d|callq '+state.owner(bodies,'operation'),
        'movzbl 48(%rsp), %ecx|cmpb $2, %cl|jne .B2|movzbl 40(%rsp), %eax|jmp .B48',
        '.B2:|movq 40(%rsp), %rbx|movq (%rdi), %r12|movq 8(%rdi), %r15|testq %r12, %r12|je .B3',
        'movq 16(%rdi), %r14|movq 24(%rdi), %r11|movq 32(%rdi), %r10|'
        'movq 40(%rdi), %r9|movq 48(%rdi), %r8|movq 56(%rdi), %rdx|'
        'cmpq $7, %r12|jae .B50|decl %r12d|jmp .B52',
        '.B3:|movq 16(%rdi), %r14|movq 24(%rdi), %r11|movq %r15, %rax|orq %r14, %rax|'
        'movq 32(%rdi), %r10|movq %r11, %rdx|orq %r10, %rdx|orq %rax, %rdx|'
        'movq 40(%rdi), %r9|movq 48(%rdi), %r8|movq %r9, %rax|orq %r8, %rax|'
        'orq %rdx, %rax|movq 56(%rdi), %rdx|orq %rdx, %rax|jne .B5|'
        'xorl %eax, %eax|testb $1, %cl|je .B55|jmp .B48'])
    slots=[('r12','r12d','bpl',50,52),('r15','r15d','bpl',7,10),
           ('r14','r14d','bpl',13,16),('r11','r11d','bpl',19,22),
           ('r10','r10d','r11b',25,28),('r9','r9d','r10b',31,34),
           ('r8','r8d','r9b',37,40),('rdx','edx','r8b',43,46)]
    for slot,(reg,low,tmp,start,end) in enumerate(slots):
        if slot:
            entry=5+(slot-1)*6;following=entry+6
            s.sequences(body,[f'.B{entry}:|testq %{reg}, %{reg}|je .B{following}|'
                f'cmpq $7, %{reg}|jae .B{start}|decl %{low}|jmp .B{end}'])
        s.sequences(body,[f'.B{start}:|leaq -4608(%{reg}), %rax|cmpq $-511, %rax|setb %al|'
            f'cmpq $4480, %{reg}|sete %{tmp}|orb %al, %{tmp}|movl $65535, %eax|jne .B53|'
            f'shll $16, %{low}|andl $33488896, %{low}|orl $6, %{low}|.B{end}:|'
            f'movl %{low}, %eax|cmpw $-1, %ax|'+('jne .B47' if slot==7 else 'je .B53')])
    wipe=s.one(bodies,r'HardenedSha2Owner4wipe$')
    s.sequences(body,[
        '.B53:|shrl $16, %eax|testb $1, %cl|jne .B48|.B55:|movl %eax, %esi|'
        'leaq 608(%rbx), %rdx|leaq 40(%rsp), %rcx|movl $1174, %r8d|callq memcpy|'
        'movb $-1, 608(%rbx)|movzbl 40(%rsp), %eax|cmpb $-1, %al|je .B57|'
        'xorl %ecx, %ecx|cmpb $6, %al|setae %cl|leaq (%rcx,%rcx,2), %rax|'
        'leaq (%rsp,%rax), %rcx|addq $41, %rcx|callq '+wipe,
        'xorps %xmm0, %xmm0|movups %xmm0, 64(%rbx)|movups %xmm0, 48(%rbx)|'
        'movups %xmm0, 32(%rbx)|movups %xmm0, 16(%rbx)|movq $0, (%rbx)|'
        'movq $0, 600(%rbx)|movw $4, 1782(%rbx)|movl %esi, %eax',
        '.B47:|movups (%rdi), %xmm0|movups 16(%rdi), %xmm1|movups 32(%rdi), %xmm2|'
        'movups 48(%rdi), %xmm3|movups %xmm3, 64(%rbx)|movups %xmm2, 48(%rbx)|'
        'movups %xmm1, 32(%rbx)|movups %xmm0, 16(%rbx)|movq %rsi, 600(%rbx)|'
        'movb $1, 1782(%rbx)|movb $-1, %al|jmp .B48'])
    returns=s.normal_returns(body,'.B57',['leaq 80(%rbx), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(slots=8,nonempty_required=True,inactive_identity=0,
        active_domains=['1..6','4097..4607 excluding 4480'],copy_bytes=64,
        success_phase='Collecting',rejection_cleanup_return_sites=returns,
        named_and_general_decoders_checked_per_slot=True)


def sha_ni_begin(bodies):
    body=bodies[state.owner(bodies,'begin')]
    s.sequences(body,[
        'movq %r9, %rdi|movq %r8, %rbx|movq %rdx, %r8|movq %rcx, %rdx|'
        'leaq 32(%rsp), %rcx|xorl %r9d, %r9d|callq '+state.owner(bodies,'operation'),
        'movzbl 40(%rsp), %eax|cmpb $2, %al|jne .B2|movzbl 32(%rsp), %eax|jmp .B24',
        '.B2:|movq 32(%rsp), %rsi|movq (%rbx), %r14|movq 8(%rbx), %r15|'
        'movq %r14, %rcx|orq %r15, %rcx|movq 16(%rbx), %r8|jne .B5|'
        'movq 24(%rbx), %r11|movq 32(%rbx), %rdx|movq %r8, %r9|orq %r11, %r9|'
        'movq 40(%rbx), %rcx|movq %rdx, %r15|orq %rcx, %r15|orq %r9, %r15|'
        'movq 48(%rbx), %r10|orq %r10, %r15|movq 56(%rbx), %r9|orq %r9, %r15|'
        'je .B15|movb $1, %bpl|jmp .B6',
        '.B5:|movq 24(%rbx), %r11|movq 32(%rbx), %rdx|movq 40(%rbx), %rcx|'
        'movq 48(%rbx), %r10|movq 56(%rbx), %r9|cmpq $3, %r15|setb %bpl',
        '.B6:|cmpq $2, %r14|ja .B15|testb %bpl, %bpl|je .B15'])
    for reg in ('r8','r11','rdx','rcx','r10','r9'):
        s.sequences(body,[f'cmpq $2, %{reg}|ja .B15'])
    s.sequences(body,[
        'vmovdqu (%rbx), %ymm0|vmovups 32(%rbx), %ymm1|vmovups %ymm1, 2048(%rsi)|'
        'vmovdqu %ymm0, 2016(%rsi)|movq %rdi, 2608(%rsi)|movb $1, 2616(%rsi)|movb $-1, %al|jmp .B24',
        '.B15:|testb $1, %al|jne .B23|leaq 32(%rsp), %rcx|movl $2000, %r8d|'
        'movq %rsi, %rdx|callq memcpy|movq $0, 8(%rsi)|movq $2, (%rsi)',
        'leaq 848(%rsp), %rcx|callq '+state.accelerated.life.wiping.WIPE+'|'
        'cmpq $0, 112(%rsp)|je .B20|leaq 128(%rsp), %rcx|callq '+state.accelerated.life.SCRATCH,
        'vpxor %xmm0, %xmm0, %xmm0|vmovdqu %ymm0, 2048(%rsi)|vmovdqu %ymm0, 2016(%rsi)|'
        'movb $0, 2617(%rsi)|movq $0, 2000(%rsi)|movq $0, 2608(%rsi)|'
        'movq 2592(%rsi), %rax|cmpb $2, 8(%rax)|je .B22|movb $2, 8(%rax)|movq $3, (%rax)|'
        '.B22:|movb $4, 2616(%rsi)|.B23:|xorl %eax, %eax'])
    returns=s.normal_returns(body,'.B20',['leaq 2080(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(slots=8,nonempty_required=True,inactive_identity=0,active_domains=['1..2'],
        copy_bytes=64,success_phase='Collecting',rejection_cleanup_return_sites=returns,
        backend_revoked_on_guard_failure=True)


def scalar_placement(bodies):
    body=bodies['RetainedWork']
    live=re.findall(r'movq ([^ ,]*4LIVE\.0)\(%rip\), %rsi','\n'.join(s.lines(body)))
    s.require(len(live)==1,'one scalar live pointer');live=live[0]
    s.sequences(body,[
        'testq %rdx, %rdx|sete %r10b|testl $4095, %edx|setne %r11b|movl $200, %eax|'
        'orb %r10b, %r11b|jne .B7|movq %r9, %r10|subq %r8, %r10|setae %r11b|'
        'cmpq $65536, %r10|sete %r10b|andb %r11b, %r10b|cmpb $1, %r10b|jne .B7|'
        'movq '+live+'(%rip), %rsi|testq %rcx, %rcx|je .B3',
        '.B3:|movl $201, %eax|testq %rsi, %rsi|jne .B7|movq $0, (%rdx)|'
        'leaq 16(%rdx), %rcx|movl $592, %r8d|movq %rdx, %rsi|xorl %edx, %edx|callq memset|'
        'movb $-1, 608(%rsi)|movw $0, 1782(%rsi)|movq %rsi, '+live+'(%rip)|movl $1, %eax|jmp .B7'])
    return dict(nonnull_page_alignment=4096,nonwrapping_window_bytes=65536,
        duplicate_live_rejected=True,initialized_plan_output_sequence_budget_bytes=592,
        absent_state_tag=255,initial_phase='Empty',initial_completed_bitmap=0,
        inactive_payload_and_padding_claimed_initialized=False,
        page_window_disjointness='assigned to enclosing C admission, not checked by this scalar body')


def sha_ni_placement(bodies):
    body=bodies['RetainedWork'];new=s.one(bodies,r'Resident3new$')
    live=re.findall(r'movq ([^ ,]*4LIVE)\(%rip\), %rax','\n'.join(s.lines(body)))
    s.require(len(live)==1,'one SHA-NI live resident');live=live[0]
    page=live[:-5]+'9LIVE_PAGE.0'
    s.sequences(body,[
        'testq %rdx, %rdx|setne %al|testl $4095, %edx|sete %r10b|testb %r10b, %al|je .B1|'
        'movq %r9, %rax|subq %r8, %rax|setb %r10b|cmpq $-4097, %rdx|ja .B1|'
        'testb %r10b, %r10b|jne .B1|cmpq $65536, %rax|jne .B1|leaq 4096(%rdx), %rax|'
        'cmpq %r8, %rax|seta %al|cmpq %rdx, %r9|seta %r10b|testb %r10b, %al|jne .B1|'
        'movq '+live+'(%rip), %rax|testq %rcx, %rcx|je .B8',
        '.B8:|testq %rax, %rax|je .B12|movq '+live+'+16(%rip), %rcx|'
        'callq '+state.owner(bodies,'quarantine')+'|movl $201, %esi|jmp .B44',
        '.B12:|movl $4096, %r8d|movq %rdx, %rcx|movq %rdx, %rsi|xorl %edx, %edx|callq memset|'
        'leaq 40(%rsp), %rcx|movq %rsi, %rdi|movq %rsi, %rdx|callq '+new+'|'
        'cmpq $0, 40(%rsp)|je .B13|movq 56(%rsp), %rax|movq %rax, 80(%rsp)|'
        'vmovups 40(%rsp), %xmm0|vmovaps %xmm0, 64(%rsp)',
        '.B16:|movq 80(%rsp), %rax|movq %rax, '+live+'+16(%rip)|vmovaps 64(%rsp), %xmm0|'
        'vmovups %xmm0, '+live+'(%rip)|movq %rdi, '+page+'(%rip)|movl $1, %esi|jmp .B44',
        '.B13:|movl $207, %esi|jmp .B44'])
    constructor=bodies[new];kat_name=s.one(bodies,r'static_execution.*operations12known_answer$')
    s.sequences(constructor,[
        'movq %rdx, %rdi|movq %rcx, %rsi|callq '+kat_name+'|movb $2, %cl|subb %al, %cl|'
        'movq $2, (%rdi)|movb %cl, 8(%rdi)|movb $0, 9(%rdi)|testb %al, %al|je .B1|leaq 16(%rdi), %rax',
        'vxorps %xmm0, %xmm0, %xmm0|vmovups %ymm0, 120(%rsp)|vmovups %ymm0, 152(%rsp)|'
        'vmovups 112(%rsp), %ymm1|vmovups %ymm1, 32(%rsp)|vmovups 144(%rsp), %ymm1|'
        'vmovups %ymm1, 64(%rsp)|movq 176(%rsp), %rcx|movq %rcx, 96(%rsp)',
        'movq $0, 24(%rdi)|movq $2, 16(%rdi)|movb $6, 32(%rdi)|movq $0, 2016(%rdi)|'
        'vmovups 32(%rsp), %ymm1|vmovups 64(%rsp), %ymm2|vmovups %ymm1, 2024(%rdi)|'
        'vmovups %ymm2, 2056(%rdi)|movq 96(%rsp), %rcx|movq %rcx, 2088(%rdi)',
        '|'.join(f'vmovups %ymm0, {offset}(%rdi)' for offset in range(2096,2608,32)),
        'movq %rdi, 2608(%rdi)|vxorps %xmm0, %xmm0, %xmm0|vmovups %xmm0, 2616(%rdi)|'
        'movw $0, 2632(%rdi)|movq %rdi, (%rsi)|movq %rdi, 8(%rsi)|movq %rax, 16(%rsi)|jmp .B5',
        '.B1:|xorl %eax, %eax',
        '.B2:|'+'|'.join(f'movb $0, {str(offset) if offset else ""}(%rdi,%rax)' for offset in range(8))+
        '|addq $8, %rax|cmpq $4096, %rax|jne .B2|movb $6, 8(%rsi)|movq $0, (%rsi)'])
    return dict(nonnull_page_alignment=4096,nonwrapping_window_bytes=65536,
        nonwrapping_page_and_disjoint_window=True,duplicate_live_rejected=True,
        initial_page_memset_bytes=4096,owner_offset=16,empty_state_and_plan=True,
        output_zero_bytes=512,authority_pointer_retained=True,initial_phase='Empty',
        failed_kat_page_erasure_bytes=4096,publication_after_success_only=True,
        inactive_payload_and_padding_claimed_initialized=False,
        public_static_kat=kat.inspect(bodies),constructor_stack_cleanup_claimed=False)


def inspect(bodies,lane):
    s.require(lane in ('scalar','sha_ni'),'sequential admission review')
    return dict(plan=(scalar_begin if lane=='scalar' else sha_ni_begin)(bodies),
                initial_placement=(scalar_placement if lane=='scalar' else sha_ni_placement)(bodies))
