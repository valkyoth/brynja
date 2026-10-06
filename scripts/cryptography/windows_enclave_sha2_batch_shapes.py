"""Selected SHA-2 batch admission/cleanup contracts, not full chain closure."""
import windows_enclave_kmac_shapes as s
import windows_enclave_kmac_reuse as reuse


def owner(bodies,role): return s.one(bodies,r'Owner\d+'+role+'$')


def abi(bodies,ir,lane):
    size,align={'scalar':(1784,8),'sha_ni':(2624,16),'simd256':(288,8),'simd512':(296,8)}[lane]
    rows={owner(bodies,'operation'):[f'align {align} dereferenceable({size}) %1',
        'range(i8 0, '+('5' if lane in ('scalar','sha_ni') else '2')+') %3']}
    if lane in ('scalar','sha_ni'):
        for role in ('update','finish'):
            rows[owner(bodies,role)]=['range(i64 0, 1025) %4',f'align {align} dereferenceable({size}) %0']
    else:
        rows[s.one(bodies,r'Resident6digest$')]=[
            f'readonly align 8 captures(none) dereferenceable({192 if lane=="simd256" else 96}) %2']
        rows[s.one(bodies,r'Kernel8compiled$')]=['(i1 noundef zeroext %0)']
    for name,tokens in rows.items():
        text=reuse.abi(ir,name)
        for token in tokens: s.require(token in text,'batch private ABI '+token)
    return rows


def sequential(bodies,lane):
    scalar=lane=='scalar';phase=1782 if scalar else 2616;seq=592 if scalar else 2600
    pointer='rdi' if scalar else 'rsi';destination='rsi' if scalar else 'rdi'
    op=bodies[owner(bodies,'operation')]
    s.sequences(op,[f'cmpb %r9b, {phase}(%rdx)|jne '+('.B3' if scalar else '.B10'),
        f'movq {seq}(%{pointer}), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B2',
        f'movq %r8, {seq}(%{pointer})|movq %{pointer}, (%{destination})'])
    output=80 if scalar else 2080
    event=[f'leaq {output}(%{pointer}), %rcx','movl $512, %edx','callq '+s.ZERO]
    starts=('.B3','.B8') if scalar else ('.B7','.B13','.B19')
    returns={label:s.normal_returns(op,label,event) for label in starts}
    clear=owner(bodies,'clear')
    s.normal_returns(bodies[clear],clear,[f'leaq {output}(%rsi), %rcx','movl $512, %edx','callq '+s.ZERO])
    if scalar:
        s.sequences(op,['movq $0, (%rdi)|movq $0, 600(%rdi)|movw $4, 1782(%rdi)'])
        update=bodies[owner(bodies,'update')];finish=bodies[owner(bodies,'finish')]
        s.sequences(update,['cmpl $1, (%rbx)|jne .B13|cmpq %rdi, 8(%rbx)|jne .B13',
            'movq 600(%rbx), %rax|subq %r8, %rax|jae .B6',
            '.B6:|movq %rax, 600(%rbx)|movzbl 608(%rbx), %eax|cmpq $6, %rax|ja .B13'])
        s.sequences(finish,['cmpl $1, (%r15)|jne .B26|cmpq %rsi, 8(%r15)|jne .B26',
            'movq 600(%r15), %rax|movb $3, %dil|subq %r12, %rax|jb .B26',
            'movq %rsi, %r12|shlq $6, %r12',
            'callq '+s.one(bodies,r'state.*State6finish$')+'|movl %eax, %edi|cmpb $-1, %al|jne .B26',
            'orb %al, 1783(%r15)|movq $0, (%r15)|movb $1, 1782(%r15)'])
    else:
        s.sequences(op,['movq 2592(%rsi), %rax|cmpb $0, 9(%rax)|jne .B4|cmpb $1, 8(%rax)|jne .B4',
            'movb $2, 8(%rax)|movq $3, (%rax)',f'movb $4, {phase}(%rsi)'])
    return dict(exact_nonwrapping_sequence=True,phase_checked=True,output_bytes=512,
        rejection_return_sites=returns,authority_identity_and_health_checked=not scalar,
        scalar_active_slot_budget_and_result_commit_checked=scalar,
        full_state_transfer_and_lane_review_pending=True)


def simd(bodies,lane):
    width=256;phase=280 if lane=='simd256' else 288;seq=272 if lane=='simd256' else 280
    out=16 if lane=='simd256' else 24
    body=bodies[owner(bodies,'operation')]
    s.sequences(body,[f'cmpb %r9b, {phase}(%rdx)|jne .B15',
        f'movq {seq}(%rbx), %rax|incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B2',
        f'movq %rdi, {seq}(%rbx)|movq %rbx, (%rsi)|movb $0, 8(%rsi)',
        f'movb $2, {phase}(%rbx)'])
    event=[f'leaq {out}(%rbx), %rcx',f'movl ${width}, %edx','callq '+s.ZERO]
    returns={label:s.normal_returns(body,label,event) for label in ('.B15','.B10')}
    s.sequences(body,['cmpb $1, 16(%rax)|jne .B9','movb $0, 16(%rax)'])
    return dict(exact_nonwrapping_sequence=True,phase_checked=True,output_bytes=width,
        rejection_return_sites=returns,authority_revoked_on_rejection=True,
        callback_and_lane_engine_review_pending=True)


def callback_targets(bodies,lane):
    """Constructor/leaf contracts only; not all indirect callsite provenance."""
    compiled=s.one(bodies,r'Kernel8compiled$')
    s.sequences(bodies[compiled],['movl %ecx, %eax|xorb $1, %al|retq'])
    s.require(len(s.lines(bodies[compiled]))==5,'complete typed capability leaf')
    names=[n for n in bodies if 'Owner6digests2_0' in n]
    s.require(len(names)==2,'closure and callable vtable thunk')
    for name in names:
        s.sequences(bodies[name],['xorl %eax, %eax|retq'])
        s.require(len(s.lines(bodies[name]))==4,'complete stateless false callback')
    factory=s.one(bodies,r'Resident3new$');body=bodies[factory]
    s.sequences(body,[
        'leaq '+compiled+'(%rip), %rax|movq %rax, 8(%rdi)|movw $1, 16(%rdi)',
        'xorl %ecx, %ecx|callq '+compiled+'|testb %al, %al|je .B13',
        'movq %rdi, '+('32' if lane=='simd256' else '40')+'(%rdi)',
        'movq %rdi, (%rsi)|movq %rdi, 8(%rsi)|movq '+
            ('%rbx' if lane=='simd256' else '%rax')+', 16(%rsi)|jmp .B17'])
    # Both constructor failures erase all 4096 backing bytes. This does not
    # erase the KAT frame or prove the later live-page retirement path.
    loop='|'.join(['movb $0, '+('' if i==0 else str(i))+'(%rdi,%rax)' for i in range(8)])
    for label in ('.B9','.B14'):
        s.sequences(body,[label+':|'+loop+'|addq $8, %rax|cmpq $4096, %rax|jne '+label])
    s.sequences(body,['xorl %eax, %eax|.p2align 4|.B9:',
        '.B13:|movb $0, 16(%rdi)|xorl %eax, %eax|'+
        ('.p2align 4|' if lane=='simd256' else '')+'.B14:'])
    return dict(typed_capability_leaf=compiled,stateless_false_callbacks=names,
        constructor=factory,authority_callback_offset=8,authority_page_offset=0,
        owner_page_offset=24,constructor_failure_erases_page_bytes=4096,
        all_indirect_callsite_provenance_qualified=False)


def inspect(bodies,ir,lane):
    result=dict(private_abi=abi(bodies,ir,lane),
        admission=sequential(bodies,lane) if lane in ('scalar','sha_ni') else simd(bodies,lane))
    if lane.startswith('simd'): result['callback_targets']=callback_targets(bodies,lane)
    return result
