"""Distinct TupleHash setup contexts in the saved Windows images."""
import windows_enclave_tuple_shapes as t
import windows_enclave_tuple_transfers as x

s=t.s


def constants(values,digest,lane):
    prefix='anon.'+('6e7951ee1c35fa5c04606f5334a6e2b1' if lane=='scalar' else 'de9b71afbadc051ece76f344c9e0d88b')
    expected=[b'TupleHash',bytes([3]),bytes([4]),bytes([1,2]),bytes([0]),bytes(range(1,8)),bytes([6,7]),bytes([5])]
    for index,raw in enumerate(expected):
        p=values[prefix+'.'+str(index)]
        s.require(p['bytes']==len(raw) and p['sha256']==digest(raw),'actual domain/allowed-phase constant')
    if lane=='avx2':
        table=s.one(values,r'^switch.table.*State5setup$')
        s.require(values[table]['bytes']==32 and
                  values[table]['sha256']==digest(b''.join(n.to_bytes(8,'little') for n in (168,136,168,136))),
                  'actual identity-to-rate table')
    return dict(domain='TupleHash',domain_bits=72,identities_to_rates=[168,136,168,136],
                phase_lists=[list(v) for v in expected[1:]])


def scalar(bodies):
    name=s.one(bodies,r'tuple_stream_state.*State5setup$');body=bodies[name]
    wipe=s.one(bodies,r'HardenedFips202OwnerKj88_E4wipe')
    s.sequences(body,['movq $72, 336(%rsp)|movb $8, 344(%rsp)',
        'decq %rdx|cmpq $3, %rdx|ja .B12',
        'adcq $0, %r14|jb .B31','adcq $0, %r8|jb .B31',
        'movq $72, 400(%rsp)','movl $1040, %r8d|movq %r14, %rcx|xorl %edx, %edx|callq memset',
        'movw $-22527, 62(%rsp)','movw $-30719, 62(%rsp)','movw $18433, 62(%rsp)',
        'incq %rsi|leaq 384(%rsp), %rdx|movl $1135, %r8d|movq %rsi, %rcx|callq memcpy'])
    # Two strengths have identical construction order with their own bound
    # sponge/setup callees; custom bits use u128 checked carry before padding.
    for rate in ('a8','88'):
        for role in ('push','advance','bits'):
            s.sequences(body,['callq '+s.one(bodies,rf'SetupKj{rate}_E\d+{role}')])
    for label,offset in (('.B20',448),('.B37',1584)):
        pointer='movq %rdi, %rcx' if offset==448 else 'leaq 1584(%rsp), %rcx'
        event=['movl $1, %edx',pointer,'callq '+s.ZERO] if offset==448 else [pointer,'movl $1, %edx','callq '+s.ZERO]
        s.normal_returns(body,label,event)
    finish=bodies[t.owner(bodies,'finish_custom')]
    checks=['cmpb $2, 82(%rsi)','movq 40(%rsi), %rax|orq 32(%rsi), %rax',
        'cmpb $0, 81(%rsi)','movdqa 16(%rsi), %xmm0|pcmpeqb 64(%rsi), %xmm0|'
        'pmovmskb %xmm0, %eax|cmpl $65535, %eax']
    for check in checks:
        s.sequences(finish,[check]);s.require('\n'.join(s.lines(finish)).count(check.replace('|','\n'))==2,
                                            'both rates enforce exact setup completion')
    s.sequences(finish,['movl $1040, %r8d|movq %rdi, %rcx|xorl %edx, %edx|callq memset|'
        'movq %rdi, %rcx|callq '+wipe,
        'movb $0, 83(%rsi)|leaq 80(%rsi), %rcx|movl $1, %edx|callq '+s.ZERO,
        'callq '+x.state_drop(bodies,'scalar')+'|movb %dil, (%rsi)'])
    return dict(setup_owner_extent=1136,moved_setup_stack_copies_package=8,
                exact_custom_completion_both_strengths=True,source_owner_erased_before_replacement=True)


def accelerated(bodies):
    name=s.one(bodies,r'tuple_accelerated_state.*State5setup$');body=bodies[name]
    s.sequences(body,['leaq -1(%r8), %rcx|cmpq $4, %rcx|jae .B15',
        'cmpb $4, 9(%rdx)|jne .B30|cmpb $1, 8(%rdx)|jne .B30',
        'movq $72, 80(%rbx)|movb $8, 88(%rbx)',
        'adcq $0, %r14|jb .B26',
        'movb $1, %dl|vzeroupper|callq '+s.one(bodies,r'State11setup_chunk$'),
        '.B48:|leaq 4096(%rbx), %rdx|movl $992, %r8d|movq %rsi, %rcx|callq memcpy'])
    memory=s.one(bodies,r'Memory4wipe$');scratch=s.one(bodies,r'KeccakScratch4wipe$')
    s.normal_returns(body,'.B26',['callq '+memory])
    s.normal_returns(body,'.B28',['leaq 1312(%rbx), %rcx','callq '+scratch])
    finish=bodies[t.owner(bodies,'finish_custom')]
    s.sequences(finish,['cmpb $2, 1962(%rsi)|jne .B5|movq 1888(%rsi), %rax|'
        'orq 1896(%rsi), %rax|jne .B5|cmpb $0, 1961(%rsi)|jne .B5',
        'vmovdqa 1920(%rsi), %xmm0|vpxor 1936(%rsi), %xmm0, %xmm0|vptest %xmm0, %xmm0|jne .B5',
        'callq '+s.ZERO+'|movb $0, 1961(%rsi)|vpxor %xmm0, %xmm0, %xmm0|'
        'vmovdqa %ymm0, 32(%rbx)|vmovdqa %ymm0, (%rbx)|movb $-1, 1962(%rsi)|movb $1, 1986(%rsi)'])
    return dict(setup_owner_extent=992,authority_and_generation_checked=True,
                exact_custom_completion=True,moved_setup_stack_copies_package=8)


def inspect(bodies,lane):
    return scalar(bodies) if lane=='scalar' else accelerated(bodies)
