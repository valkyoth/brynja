"""Sequential batch slot/state transitions in the frozen Windows images."""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha_ni_state as accelerated


def owner(bodies,role): return s.one(bodies,r'Owner\d+'+role+'$')


def selected_slot(active,completed):
    """Cross-check the reviewed unrolled public bitmap arithmetic, not execution."""
    for slot in range(7):
        if active & (1<<slot) and not completed & (1<<slot): return slot
    return 7 if active & 128 and not completed & 128 else None


def decoded_width(identity):
    """Unsigned identity interval and ceil(t/8) from the reviewed scalar caller."""
    mask=(1<<64)-1
    s.require(type(identity) is int and 0<=identity<=mask,'public wire u64 identity')
    named=(identity-1)&mask
    if named<6: return named,0,(28,32,48,64,28,32)[named]
    if ((identity-4608)&mask)<mask-510 or identity==4480: return None
    parameter=(identity<<16 & 33488896)>>16
    return 6,parameter,(parameter>>3)+int((parameter&7)>=1)


def scalar_tables(bodies,assembly):
    """Bind semantic dispatch labels to already byte-bound local table entries."""
    tables={}
    expected={'start':(17,18,19,20,21,22,23),
              'finish':(19,20,21,22,19,20,23),'update':(8,8,9,9,9,9,10)}
    for role,labels in expected.items():
        body=bodies[owner(bodies,role)]
        names=set(re.findall(r'\.LJTI\d+_0',body));s.require(len(names)==1,'one scalar dispatch table')
        name=names.pop();number=name.split('_')[0][5:]
        pattern=r'^'+re.escape(name)+r':\n((?:\s*\.long\s+[^\n]+\n)+)'
        rows=re.findall(pattern,assembly,re.M);s.require(len(rows)==1,'one complete emitted dispatch definition')
        destinations=re.findall(r'\.long\s+([^\s]+)',rows[0])
        s.require(destinations==[f'.LBB{number}_{label}-{name}' for label in labels],
                  'exact scalar variant dispatch order: '+role)
        tables[role]=list(labels)
    return tables


def start_selection(bodies,lane):
    scalar=lane=='scalar';body=bodies[owner(bodies,'start')]
    plan=16 if scalar else 2016;bitmap=1783 if scalar else 2617
    ptr='rdi' if scalar else 'rsi';dest='dl' if scalar else 'cl'
    found='edx' if scalar else 'ecx';a,b=('r8b','r9b') if scalar else ('dl','r8b')
    failed='.B38' if scalar else '.B44'
    s.sequences(body,['movb $1, %r9b|callq '+owner(bodies,'operation'),
        f'cmpq $0, {plan}(%{ptr})|movzbl {bitmap}(%{ptr}), %eax|sete %{dest}|'
        f'orb %al, %{dest}|testb $1, %{dest}|je .B3'])
    for slot in range(1,7):
        s.sequences(body,[f'cmpq $0, {plan+8*slot}(%{ptr})|setne %{a}|testb ${1<<slot}, %al|'
            f'sete %{b}|movl ${slot}, %{found}|testb %{b}, %{a}|jne .B11'])
    s.sequences(body,[f'cmpq $0, {plan+56}(%{ptr})|setne %{dest}|testb %al, %al|setns %bl|'
        f'andb %{dest}, %bl|movl $7, %{found}|jmp .B11|.B3:|xorl %{found}, %{found}',
        ('cmpq %r14, %rdx|setne %dl|xorb $1, %bl|movb $2, %al|orb %dl, %bl|jne ' if scalar else
         'cmpq %rdi, %rcx|setne %cl|xorb $1, %bl|movb $2, %al|orb %cl, %bl|jne ')+failed])
    return dict(first_active_unfinished_slot_only=True,slots=8,
        equality_to_selected_slot_bounds_plan_load=True,all_finished_rejected=True)


def scalar_finish(bodies):
    body=bodies[owner(bodies,'finish')];finish=s.one(bodies,r'state.*State6finish$')
    s.sequences(body,[
        'movzbl 1352(%rsp), %r14d|movq %rax, 600(%r15)|testq %r12, %r12|je .B6|'
        'leal -1(%r14), %eax|movb $4, %dil|cmpb $7, %al|ja .B26|cmpb $7, %r14b|ja .B11',
        'leaq -1(%r12), %rax|movb $-1, %dl|movl %r14d, %ecx|shrb %cl, %dl|'
        'addq %rbx, %rax|movq %rax, %rcx|callq '+s.one(bodies,r'12mask_is_zero$')+'|cmpl $1, %eax|jne .B26',
        '.B11:|movzbl %r14b, %eax|leaq (%rax,%r12,8), %rax|addq $-8, %rax',
        '.B6:|movb $4, %dil|testb %r14b, %r14b|jne .B26',
        'movq %rax, 56(%rsp)|movb %r14b, 64(%rsp)|movq %rbx, 40(%rsp)|movb %r12b, 48(%rsp)|'
        'cmpq $7, %rsi|ja .B13|movq 16(%r15,%rsi,8), %rax',
        'leaq -1(%rax), %rcx|cmpq $6, %rcx|jb .B17|leaq -4608(%rax), %rcx|'
        'cmpq $-511, %rcx|setb %cl|cmpq $4480, %rax|sete %dl|xorl %edi, %edi|orb %cl, %dl|jne .B26',
        'shll $16, %eax|andl $33488896, %eax|orl $6, %eax|movl %eax, %ecx',
        '.B23:|movzwl %di, %eax|shrl $3, %eax|andl $7, %edi|cmpw $1, %di|sbbw $-1, %ax|'
        'movzwl %ax, %edi|jmp .B24',
        '.B24:|movzbl 608(%r15), %ebx|movzbl 609(%r15), %r14d|movb $-1, 608(%r15)|cmpb $-1, %bl|je .B25',
        'movq %rsi, %r12|shlq $6, %r12|leaq 610(%r15), %rdx|leaq 74(%rsp), %rcx|movl $1172, %r8d|callq memcpy',
        'movb %bl, 72(%rsp)|movb %r14b, 73(%rsp)|leaq (%r15,%r12), %r8|addq $80, %r8|'
        'leaq 72(%rsp), %rcx|leaq 40(%rsp), %rdx|movq %rdi, %r9|callq '+finish,
        'callq '+finish+'|movl %eax, %edi|cmpb $-1, %al|jne .B26'])
    for label,width in ((19,28),(20,32),(21,48),(22,64)):
        s.sequences(body,[f'.B{label}:|movl ${width}, %edi'])
    cleared=s.normal_returns(body,'.B29',['leaq 80(%r15), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(canonical_tail_checked=True,identity_domains=['1..6','4097..4607 excluding 4480'],
        general_width='ceil(t/8)',slot_stride=64,taken_state_bytes=1174,
        state_invalidated_before_call=True,error_output_cleanup_return_sites=cleared,
        dispatch_tables_bound_by_parent=True)


def scalar_start_transfer(bodies):
    body=bodies[owner(bodies,'start')];wipe=s.one(bodies,r'HardenedSha2Owner4wipe$')
    s.sequences(body,[
        'movq (%rsi,%r14,8), %r8|leaq -1(%r8), %rdx|cmpq $6, %rdx|jb .B15',
        'leaq -4608(%r8), %rax|cmpq $-511, %rax|setb %dl|cmpq $4480, %r8|sete %r9b|'
        'xorl %eax, %eax|orb %dl, %r9b|jne .B38',
        'shll $16, %r8d|andl $33488896, %r8d|orl $6, %r8d|movl %r8d, %edx',
        '.B15:|movl %edx, %eax|shrl $16, %eax|cmpw $6, %dx|ja .B38',
        '.B34:|movzbl 608(%rdi), %eax|cmpb $-1, %al|je .B36',
        'leaq 608(%rdi), %rcx|xorl %edx, %edx|cmpb $6, %al|setae %dl|'
        'leaq (%rdx,%rdx,2), %rax|addq %rax, %rcx|incq %rcx|callq '+wipe,
        '.B36:|movb %cl, 608(%rdi)|movb $0, 609(%rdi)|movl 44(%rsp), %eax|movw %ax, 610(%rdi)|'
        'leaq 612(%rdi), %rcx|leaq 306(%rsp), %rdx|movl $1021, %r8d|callq memcpy',
        'movl $0, 1777(%rdi)|movw $512, 1781(%rdi)|movq $1, (%rdi)|'
        'movq 296(%rsp), %rax|movq %rax, 8(%rdi)|movb $-1, %al',
        'movb $-1, 608(%r14)|movzbl 1328(%rsp), %eax|cmpb $-1, %al|je .B41',
        'movq $0, (%rbx)|movq $0, 600(%rbx)|movw $4, 1782(%rbx)'])
    # The sibling IV module and explicit prior-loop replay cover the inlined
    # public calculation. This local check covers replacement and publication.
    cleared=s.normal_returns(body,'.B41',['leaq 80(%rbx), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(old_owner_wiped_before_replacement=True,placed_state_offset=608,
        success_phase='Streaming',rejection_cleanup_return_sites=cleared,
        inlined_public_iv_calculation_review='sibling IV checks plus explicit prior-loop replay')


def sha_ni_start_transfer(bodies):
    body=bodies[owner(bodies,'start')];wipe=accelerated.life.wiping.WIPE;scratch=accelerated.life.SCRATCH
    s.sequences(body,[
        'movq (%r15,%rdi,8), %rcx|xorl %eax, %eax|cmpq $1, %rcx|je .B15|cmpq $2, %rcx|jne .B44|movb $1, %al',
        '.B15:|movq 2592(%rsi), %rcx|cmpb $1, 8(%rcx)|jne .B43',
        'movzbl 9(%rcx), %ebx|movzbl %bl, %r8d|movq (%rcx), %rdx|movl $46, %r9d|btl %r8d, %r9d|jae .B17',
        '.B17:|cmpb $3, %bl|ja .B43',
        'leaq 992(%rsp), %r14|movl $704, %r8d|movq %r14, %rcx|xorl %edx, %edx|callq memset|'
        'leaq 976(%rsp), %rcx|movl %ebx, %edx|callq '+accelerated.KAT+'|testb $1, %al|je .B19',
        '.B22:|movq %r14, %rcx|callq '+scratch+'|jmp .B43',
        '.B20:|cmpb $2, 8(%r12)|je .B22|movb $2, 8(%r12)|movq $3, (%r12)|jmp .B22',
        '.B42:|leaq 256(%rsp), %rcx|vzeroupper|callq '+scratch+'|leaq 976(%rsp), %rcx|callq '+wipe+'|jmp .B43',
        'leaq 816(%rsi), %rcx|callq '+wipe+'|cmpq $0, 80(%rsi)|je .B40|leaq 96(%rsi), %rcx|callq '+scratch,
        '.B40:|movq %r14, (%rsi)|movq $0, 8(%rsi)|movb $0, 16(%rsi)',
        'leaq 66(%rsi), %rcx|leaq 5474(%rsp), %rdx|movl $750, %r8d|callq memcpy|'
        'leaq 816(%rsi), %rcx|leaq 8156(%rsp), %rdx|movl $1170, %r8d|callq memcpy|'
        'movw $0, 1986(%rsi)|movq $1, 2000(%rsi)|movq %rdi, 2008(%rsi)|movb $2, 2616(%rsi)|movb $-1, %al'])
    for constant in accelerated.IVS:
        s.sequences(body,['vmovaps '+constant+'(%rip), %ymm0|vmovups %ymm0, 2000(%rsp)'])
    copies=sha_ni_constructor_copies(body)
    cleared=s.normal_returns(body,'.B48',['leaq 2080(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(narrow_identities_only=True,authority_checked_before_kat=True,
        kat_failure_wipes_scratch=True,old_state_wiped_before_replacement=True,
        owner_bytes=1170,session_copy_bytes=750,success_phase='Streaming',
        rejection_cleanup_return_sites=cleared,intermediate_copies=copies,
        intermediate_copy_composition_pending=False)


def sha_ni_constructor_copies(body):
    s.sequences(body,[
        '.B19:|movq 976(%rsp), %r12|testb $1, %dl|je .B20|movzbl 984(%rsp), %r14d|'
        'leaq 985(%rsp), %rdx|leaq 6224(%rsp), %rcx|movl $711, %r8d|callq memcpy|testq %r12, %r12|je .B43',
        'movb %r14b, 47(%rsp)|leaq 9326(%rsp), %r14|leaq 6224(%rsp), %rdx|movl $711, %r8d|'
        'movq %r14, %rcx|callq memcpy|movb %r12b, 46(%rsp)|shrq $8, %r12|'
        'leaq 4763(%rsp), %rcx|movl $711, %r8d|movq %r14, %rdx|callq memcpy|'
        'leaq 249(%rsp), %rcx|leaq 4763(%rsp), %rdx|movl $711, %r8d|testb %r13b, %r13b|je .B25',
        'movl $1, %r14d|jmp .B37', 'xorl %r14d, %r14d|.B37:',
        '.B37:|vmovdqa (%rsi), %xmm0|vpxor __xmm@00000000000000000000000000000002(%rip), %xmm0, %xmm0|'
        'vptest %xmm0, %xmm0|je .B40'])
    repeated=[
        'callq memcpy|vxorps %xmm0, %xmm0, %xmm0|vmovups %ymm0, 208(%rsp)|vmovups %ymm0, 176(%rsp)|'
        'vmovups %ymm0, 3884(%rsp)|vmovups %ymm0, 3916(%rsp)|vmovups %ymm0, 3948(%rsp)|vmovups %ymm0, 3980(%rsp)|'
        'vxorps %xmm6, %xmm6, %xmm6|vmovups %xmm6, 2128(%rsp)|vmovups %ymm0, 144(%rsp)|'
        'leaq 2988(%rsp), %r14|movl $896, %r8d|movq %r14, %rcx|xorl %edx, %edx|vzeroupper|callq memset|'
        'leaq 976(%rsp), %rcx|movl $1024, %r8d|movq %r14, %rdx|callq memcpy',
        'vmovdqu 144(%rsp), %ymm0|vmovups 176(%rsp), %ymm1|vmovups 208(%rsp), %ymm2|'
        'vmovdqu %ymm0, 2032(%rsp)|vmovups %ymm1, 2064(%rsp)|vmovups %ymm2, 2096(%rsp)|movw $0, 2144(%rsp)',
        'movzbl 46(%rsp), %eax|movb %al, 240(%rsp)|movq %r12, %rax|shrq $48, %rax|movb %al, 247(%rsp)|'
        'movq %r12, %rax|shrq $32, %rax|movw %ax, 245(%rsp)|movl %r12d, 241(%rsp)|'
        'movzbl 47(%rsp), %eax|movb %al, 248(%rsp)|movb $2, 960(%rsp)|movb %bl, 961(%rsp)',
        'cmpb $1, 8(%rax)|jne .B42|movq 248(%rsp), %rcx|cmpq %rcx, (%rax)|jne .B42|'
        'movzbl 9(%rax), %eax|movzbl %al, %ecx|movl $46, %edx|btl %ecx, %edx|jb .B42|testb $5, %al',
        'leaq 6224(%rsp), %r14|leaq 976(%rsp), %rdx|movl $1170, %r8d|movq %r14, %rcx|vzeroupper|callq memcpy|'
        'leaq 4026(%rsp), %rcx|leaq 240(%rsp), %rdx|movl $736, %r8d|callq memcpy',
        'leaq 7406(%rsp), %r15|leaq 4012(%rsp), %rdx|movl $750, %r8d|movq %r15, %rcx|callq memcpy|'
        'leaq 9326(%rsp), %r12|movl $1170, %r8d|movq %r12, %rcx|movq %r14, %rdx|callq memcpy',
        'leaq 5474(%rsp), %rcx|movl $750, %r8d|movq %r15, %rdx|callq memcpy|'
        'leaq 8156(%rsp), %rcx|movl $1170, %r8d|movq %r12, %rdx|callq memcpy']
    s.sequences(body,repeated)
    text='\n'.join(s.lines(body))
    for sequence in repeated:
        s.require(text.count(sequence.replace('|','\n'))==2,'both SHA-NI constructor variants preserve copies')
    return dict(owner_initialization_bytes=1170,session_bytes=736,session_wrapper_bytes=750,
        authority_pointer_and_epoch_retained=True,authority_rechecked_before_publication=True,
        both_variants_checked=True,initialization_memset_is_volatile_erasure=False,
        compiler_copies_require_enclosing_window_cleanup=True)


def updates(bodies,lane):
    scalar=lane=='scalar';body=bodies[owner(bodies,'update')]
    if scalar:
        s.sequences(body,['.B9:|leaq 609(%rbx), %rcx|.B11:|movq %rsi, %rdx|callq '+s.one(bodies,r'8update64$'),
            '.B8:|leaq 609(%rbx), %rcx|movq %rsi, %rdx|callq '+s.one(bodies,r'8update32$'),
            '.B10:|leaq 612(%rbx), %rcx|jmp .B11',
            '.B12:|movl %eax, %ecx|movb $-1, %al|movb $3, %r14b|testb %cl, %cl|je .B18'])
        start='.B16';output=80;ptr='rbx'
    else:
        s.sequences(body,['cmpl $1, 2000(%rsi)|jne .B9|cmpq %r14, 2008(%rsi)|jne .B9',
            'movq 2112(%rsp), %r8|movq 2608(%rsi), %rax|movb $3, %bl|subq %r8, %rax|jb .B9|movq %rax, 2608(%rsi)',
            'vptest %xmm0, %xmm0|movb $2, %bl|je .B9|leaq 16(%rsi), %rcx|movq %rdi, %rdx|'
            'callq '+s.one(bodies,r'Engine6update$')+'|movb $6, %bl|cmpb $-1, %al|je .B7'])
        start='.B13';output=2080;ptr='rsi'
    cleared=s.normal_returns(body,start,[f'leaq {output}(%{ptr}), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(only_reproduced_update_helpers_called=True,error_output_cleanup_return_sites=cleared,
        scalar_general_owner_offset=612 if scalar else None)


def finish_funclet(bodies):
    name=s.one(bodies,r'^\?dtor.*Owner6finish@');body=bodies[name]
    guard=s.one(bodies,r'ptr9drop_glue.*9OperationE')
    caller=bodies[owner(bodies,'finish')]
    s.sequences(caller,['movb %r12b, 1951(%rbp)', 'movq %r13, 1936(%rbp)'])
    s.sequences(body,['leaq 128(%rdx), %rbp|.seh_endprologue|movq 1936(%rbp), %rcx|'
        'movzbl 1951(%rbp), %edx|callq '+guard])
    returns=s.normal_returns(body,'.B32',['callq '+guard])
    s.sequences(bodies[guard],['testb $1, %dl|jne .B7|movq %rcx, %rsi',
        'movq $0, 8(%rsi)|movq $2, (%rsi)',
        'leaq 848(%rsp), %rcx|callq '+accelerated.life.wiping.WIPE+'|cmpq $0, 112(%rsp)|je .B4|'
        'leaq 128(%rsp), %rcx|callq '+accelerated.life.SCRATCH,
        'movb $2, 8(%rax)|movq $3, (%rax)', 'movb $4, 2616(%rsi)'])
    s.normal_returns(bodies[guard],'.B4',['leaq 2080(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO])
    return dict(function=name,parent_frame_displacement=128,owner_slot=1936,guard_slot=1951,
        all_invoked_returns_call_guard=returns,guard_target=guard,
        actual_handler_metadata_bound_by_parent=True,arbitrary_os_unwind_qualified=False)


def inspect(bodies,lane):
    return dict(slot_selection=start_selection(bodies,lane),
        constructor_transfer=(scalar_start_transfer if lane=='scalar' else sha_ni_start_transfer)(bodies),
        update=updates(bodies,lane),
        scalar_finish=scalar_finish(bodies) if lane=='scalar' else None,
        finish_funclet=finish_funclet(bodies) if lane=='sha_ni' else None,
        complete_constructor_composition_pending=True,
        remaining_constructor_scope='enclosing frame cleanup and batch-specific storage composition')
