"""TupleHash retained-state, terminal-reader and invoked-funclet composition."""
import windows_enclave_tuple_shapes as t
import windows_enclave_tuple_reuse as reuse

s=t.s


def state_drop(bodies,lane):
    return s.one(bodies,r'drop_glue.*'+('tuple_stream18tuple_stream_state5StateEBF_$'
        if lane=='scalar' else 'sha3_accelerated_state5StateECs.*tuple_accelerated$'))


def retained(bodies,lane):
    name=t.owner(bodies,'finish_custom');body=bodies[name]
    _,output,_,_,width,_,phase,last=t.offsets(lane)
    append=s.one(bodies,r'Packer6append$')
    s.sequences(body,[f'cmpb $2, {phase}(%rsi)|jne .B42',
        f'movq {width}(%rsi), %r8|movb $3, %'+('al' if lane=='scalar' else 'bl')+
        '|cmpq $1024, %r8|ja '+('.B32' if lane=='scalar' else '.B9'),
        'xorl %r9d, %r9d|'+('vzeroupper|' if lane=='avx2' else '')+'callq '+s.ENCODE])
    prefix='movq %rdi, %rcx|movq %rsi, %rdx' if lane=='scalar' else 'movq %r14, %rcx|movq %rdi, %rdx'
    event=[*prefix.split('|'),'callq '+append,'cmpb $-1, %al',
        'jne '+('.B32' if lane=='scalar' else '.B34'),'movl $1024, %edx',
        'movq %'+('rbx' if lane=='scalar' else 'rsi')+', %rcx','callq '+s.ZERO,
        f'movq $0, {width}(%rsi)',f'movb $0, {last}(%rsi)']
    s.sequences(body,['|'.join(event),f'.B42:|movb $3, {phase}(%rsi)'])
    # The output itself is used only after the encoded length succeeds; the
    # entire output is erased only after its own append succeeds.
    s.require(s.lines(body).count('callq '+append)==2,'exact length then retained-item absorption')
    pointer='rbx' if lane=='scalar' else 'rsi'
    s.sequences(body,[('leaq 1152(%rsi), %rbx|' if lane=='scalar' else '')+
        f'movzbl {last}(%rsi), %r9d|leaq '+('64' if lane=='scalar' else '40')+
        f'(%rsp), %rcx|movq %{pointer}, %rdx|callq '+s.one(bodies,r'Fips202BitString3new$')])
    begin=bodies[t.owner(bodies,'begin')];rehash=bodies[t.owner(bodies,'rehash')]
    if lane=='scalar':
        for b in (begin,rehash):
            s.sequences(b,['leaq 50(%rsp), %rdx|leaq 1194(%rsp), %r14|movl $1134, %r8d|'
                'movq %r14, %rcx|callq memcpy',
                'callq '+state_drop(bodies,lane)+'|movb %r15b, (%rsi)|movb %bl, 1(%rsi)',
                'leaq 2(%rsi), %rcx|movl $1134, %r8d|movq %r14, %rdx|callq memcpy'])
        s.sequences(begin,['movq %rdi, 2176(%rsi)|movb $1, 2202(%rsi)|movb $-1, %bl'])
        s.sequences(rehash,['leaq 2200(%rsi), %rcx|movl $1, %edx|callq '+s.ZERO+
                            '|movw $512, 2201(%rsi)|movq %rdi, 2176(%rsi)|movb $-1, %bl'])
    else:
        for b in (begin,rehash):
            s.sequences(b,['leaq 129(%rbx), %rdx|leaq 1129(%rbx), %rcx|movl $943, %r8d|callq memcpy',
                'leaq 1025(%r15), %rcx|leaq 1129(%rbx), %rdx|movl $943, %r8d|vzeroupper|callq memcpy'])
        s.sequences(begin,['movq %rsi, 2032(%r15)|movb $1, 2067(%r15)|movb $-1, %al'])
        s.sequences(rehash,['callq '+s.ZERO+'|movb $0, 2065(%r15)|movq %rsi, 2032(%r15)|'
                            'movb $2, 2067(%r15)|movb $-1, %al'])
    return dict(retained_item_consumed_before_clear=True,retained_phase=2,tuple_phase=3,
                old_output_preserved_during_setup=True,aggregate_moves_cleanup_package=8)


def readers(bodies,lane):
    name=t.owner(bodies,'squeeze');body=bodies[name]
    if lane=='scalar':
        s.sequences(body,['testq %rbx, %rbx|setne %cl|shlb $3, %cl|cmpb %cl, %dil|jne .B7',
            'callq '+state_drop(bodies,lane)+'|movb $0, (%rsi)|movb $6, %al',
            '.B12:|movb $7, %al|.B13:|movq %rbx, 2192(%rsi)|movb %dil, 2203(%rsi)|'
            'movb %al, 2202(%rsi)|movb $-1, %al'])
        name=s.one(bodies,r'tuple_stream_state.*State7squeeze$');body=bodies[name]
        for rate in ('88','a8'):
            s.sequences(body,['callq '+s.one(bodies,'OwnerKj'+rate+'_E14squeeze_secret')])
        s.sequences(body,['movb $2, 1(%rcx)|leaq 2(%rcx), %rsi',
            'addq 18(%r15), %rax|adcq 26(%r15), %rcx|movb $2, %al|jb .B38',
            'callq '+s.CORE+'13secret_memory22apply_secret_byte_mask',
            'movl $168, %edx|movq %rbx, %rcx|callq '+s.ZERO+'|movb $4, %al|jmp .B38',
            'callq '+s.CORE+'22secret_memory_transfer10copy_bytes|movl $168, %edx|movq %rbx, %rcx|'
            'callq '+s.ZERO+'|jmp .B42'])
        event=['leaq 88(%rsp), %rcx','movl $1024, %edx','movl %eax, %ebx','callq '+s.ZERO]
        # Both branches following creation of Scratch converge on its destructor.
        counts={p:s.normal_returns(body,p,event) for p in ('.B15','.B32','.B38','.B59')}
        wipe=s.one(bodies,r'HardenedFips202OwnerKj88_E4wipe')
        s.normal_returns(body,'.B38',['callq '+wipe])
        s.sequences(body,['callq '+s.CORE+'13secret_memory18copy_secret_region|cmpb $-1, %al|'
                          'sete %al|negb %al|orb $5, %al'])
        return dict(scratch_bytes=1024,staging_return_sites=counts,terminal_partial_staging_bytes=168,
                    terminal_owner_wipe=True,partial_copy_transactional=True)
    s.sequences(body,['shlb $3, %cl|cmpb %cl, %sil|jne .B7',
        'movb $7, %al|testb %r14b, %r14b|je .B21',
        'movq $-1, 1968(%r15)|movb $6, %al|.B21:|movq %rdi, 2048(%r15)|'
        'movb %sil, 2066(%r15)|movb %al, 2067(%r15)|movb $-1, %al'])
    # The complete accelerated State::squeeze body/ABI is independently reused
    # from the reproduced KMAC review, including its scratch return coverage.
    finish=s.one(bodies,r'sha3_accelerated_state.*State10finish_xof$')
    s.sequences(bodies[finish],['cmpb $1, 962(%rcx)|jne .B14',
        'movq (%rcx), %r8|movb $5, %dil|cmpq 584(%rsi), %r8|jne .B14',
        'callq '+s.one(bodies,r'Engine6finish$')+'|movl %eax, %edi|cmpb $-1, %al|jne .B14|'
        'movb $-1, %dil|movb $2, %al|jmp .B17'])
    s.normal_returns(bodies[finish],'.B14',['leaq 624(%rsi), %rcx','callq '+s.one(bodies,r'Memory4wipe$')])
    return dict(accelerated_scratch_review_reproduced=True,terminal_owner_drop=True,finish_error_wipes=True)


def funclets(bodies,lane):
    if lane=='scalar': return dict(functions={},arbitrary_exception_guarantee=False)
    guard=s.one(bodies,r'Operation.*Drop4drop$');drop=state_drop(bodies,lane)
    rows=[('Owner5begin','movq 56(%rbx), %rcx|movzbl 55(%rbx), %edx',guard),
          ('State5setup','leaq 4096(%rbx), %rcx',drop),
          ('Owner6custom','movq -24(%rbp), %rcx|movzbl -9(%rbp), %edx',guard),
          ('Owner6finish','movq 256(%rbp), %rcx|movzbl 271(%rbp), %edx',guard),
          ('Owner6rehash','movq 56(%rbx), %rcx|movzbl 55(%rbx), %edx',guard),
          ('Owner7squeeze','movq -16(%rbp), %rcx|movzbl -1(%rbp), %edx',guard)]
    result={}
    for role,load,target in rows:
        name=s.one(bodies,r'^\?dtor.*'+role+'@');event=load.split('|')+['callq '+target]
        result[name]=dict(target=target,normal_returns=s.normal_returns(bodies[name],'"'+name+'"',event))
    s.require(set(result)=={n for n in bodies if n.startswith('?')},'all six invoked cleanup bodies')
    s.sequences(bodies[guard],['testb $1, %dl|jne .B6','movb $2, 8(%rax)|movq $3, (%rax)'])
    s.normal_returns(bodies[guard],'.B3',t.clear_event('avx2'))
    return dict(functions=result,arbitrary_exception_guarantee=False)


def preconditions(bodies,ir,lane):
    size,align=(2208,16) if lane=='scalar' else (2080,32)
    rows={t.owner(bodies,n):[f'align {align} dereferenceable({size}) %0']
          for n in ('begin','rehash','squeeze')}
    rows[t.owner(bodies,'operation')]=[f'align {align} dereferenceable({size}) %1','range(i64 1, 8) %4']
    rows[s.one(bodies,r'State7squeeze$')]=['range(i64 0, 1025) %2']
    for name,tokens in rows.items():
        abi=reuse.c.reuse.abi(ir,name)
        for token in tokens: s.require(token in abi,'private TupleHash ABI '+token)
    return rows


def inspect(bodies,ir,lane):
    return dict(retained=retained(bodies,lane),readers=readers(bodies,lane),
                invoked_funclets=funclets(bodies,lane),private_abi=preconditions(bodies,ir,lane))
