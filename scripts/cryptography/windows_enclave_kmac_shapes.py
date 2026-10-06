"""KMAC-specific saved-machine-code checks, separate from identity binding."""
import re
import windows_enclave_sha3_avx2_shapes as sha3

require=sha3.require
ZERO=sha3.ZERO
CORE='_RNvNtCsjNKEhcqdpKw_11brynja_core'
DIFFERENCE=CORE+'24secret_memory_difference15accumulate_byte'
ACCUMULATE=CORE+'13secret_memory33accumulate_secret_byte_difference'
EQUAL=CORE+'13secret_memory25secret_difference_is_zero'
ENCODE='_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018511encode_u128'


def one(bodies,pattern):
    found=[n for n in bodies if re.search(pattern,n)]
    require(len(found)==1,'one exact semantic role: '+pattern)
    return found[0]


def lines(body):
    return [re.sub(r'\.LBB\d+_', '.B', l) for l in sha3.normalized(body)]


def sequences(body,items):
    text='\n'.join(lines(body))
    for item in items: require(item.replace('|','\n') in text,'KMAC semantic sequence '+item)


def normal_returns(body,start,event,alternatives=()):
    """Finite direct CFG; supplied event must occur on every return from start."""
    events=[event,*alternatives]
    require(all(events),'nonempty required cleanup events')
    code=lines(body);labels={l[:-1]:i for i,l in enumerate(code) if l.endswith(':')}
    require(len(labels)==sum(l.endswith(':') for l in code),'unique CFG labels')
    require(start in labels,'reviewed CFG entry')
    pending=[(labels[start],False)];seen=set();returns=set()
    while pending:
        at,done=pending.pop()
        if (at,done) in seen: continue
        seen.add((at,done));require(at<len(code),'no escaped normal path')
        if any(code[at:at+len(e)]==e for e in events): done=True
        line=code[at]
        if line=='retq':
            require(done,'normal return bypasses required cleanup')
            returns.add(at);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1);require(target in labels,'only assigned direct branches in CFG')
            pending.append((labels[target],done))
            if op in ('jmp','jmpq'): continue
        require(not line.startswith('callq *'),'no unassigned indirect call')
        pending.append((at+1,done))
    require(returns,'nonvacuous return population')
    return len(returns)


def comparison(bodies,lane):
    name=one(bodies,r'Owner6verify$');body=bodies[name]
    sequences(bodies[DIFFERENCE],[
        'movzbl (%rdx), %eax|xorb (%r8), %al|orb %al, (%rcx)|xorl %eax, %eax|retq'])
    require(len(lines(bodies[DIFFERENCE]))==7,'complete branch-free byte-difference leaf')
    sequences(bodies[ACCUMULATE],['jmp '+DIFFERENCE])
    sequences(bodies[EQUAL],['movb $-1, %dl|callq '+CORE+'23secret_memory_predicate12mask_is_zero',
                            'cmpl $1, %eax|sete %al'])
    if lane=='scalar':
        sequences(body,[
            'cmpb $7, 3297(%rcx)|jne .B2',
            'movq 3280(%rsi), %rax|incq %rax|setne %cl|cmpq %rdx, %rax|sete %al',
            'cmpq 3288(%rsi), %r15|jne .B2|movzbl 24(%r9), %eax|cmpb 3296(%rsi), %al|jne .B2',
            'movb $0, 47(%rsp)|cmpq $1025, %r15|jae .B12',
            '.B15:|movq %rdi, %rcx|movq %r14, %rdx|movq %rbx, %r8|callq '+ACCUMULATE+
            '|incq %rbx|incq %r14|decq %r15|jne .B15',
            'movl $1, %edx|movq %rbx, %rcx|callq '+ZERO+'|xorl %eax, %eax|jmp .B17'])
    else:
        sequences(body,[
            'cmpq 2152(%rsi), %rbx|jne .B13|movzbl 24(%rdi), %eax|cmpb 2168(%rsi), %al|jne .B13',
            'movb $0, 40(%rsp)|cmpq $1024, %rbx|ja .B19',
            '.B9:|leaq 1(%r8), %r15|leaq (%rsi,%r8), %rdx|addq %r14, %r8|movq %rdi, %rcx|callq '+ACCUMULATE+
            '|movq %r15, %r8|cmpq %r8, %rbx|jne .B9',
            'movl $1, %edx|movq %rdi, %rcx|callq '+ZERO+'|movl %ebx, %edx|xorl %eax, %eax|jmp .B18'])
    # This is fixed work for the public width, not a whole-program timing claim.
    return dict(function=name,all_declared_bytes_compared=True,early_mismatch_exit=False,
                difference_wiped=True,whole_program_constant_time_claim=False)


def suffixes(bodies,lane):
    names=[n for n in bodies if '13append_suffix' in n]
    require(len(names)==(2 if lane=='scalar' else 1),'both scalar strengths or shared AVX2 suffix')
    result={}
    for name in names:
        body=bodies[name]
        sequences(body,['movb $1, %r9b|callq '+ENCODE])
        start=name+':'
        event=(['movl $1, %edx','movq %r15, %rcx','vzeroupper','callq '+ZERO,
                'movl $1, %edx','movq %r12, %rcx','callq '+ZERO,
                'leaq 32(%rsp), %rsi','movl $8, %edx','movq %rsi, %rcx','callq '+ZERO]
               if lane=='avx2' else
               ['movl $1, %edx','movq %r12, %rcx','callq '+ZERO,
                'movl $1, %edx','movq %rbx, %rcx','callq '+ZERO,
                'leaq 40(%rsp), %rsi','movl $8, %edx','movq %rsi, %rcx','callq '+ZERO])
        result[name]=dict(normal_return_sites=normal_returns(body,start[:-1],event),
                          pending_used_count_cleared=True,right_encoding=True)
    return result


def worker(bodies,lane):
    drop=one(bodies,r'worker7BuffersE');body=bodies['RetainedWork']
    start='.B27' if lane=='avx2' else '.B11'
    result=normal_returns(body,start,['callq '+drop])
    header=112 if lane=='avx2' else 96
    sequences(bodies[drop],[f'movl ${header}, %edx|callq '+ZERO,
                           'movl $1024, %edx','jmp '+ZERO])
    receiver=one(bodies,r'worker7receive$');b=bodies[receiver]
    if lane=='avx2':
        authority=one(bodies,r'15check_authority$')
        sequences(b,[
            'cmpq $11, %r14|ja .B27',
            'cmpq 216(%rsp), %r12|jne .B27',
            'cmpq %r8, %rax|jne .B47',
            'cmpq 2152(%rcx), %rax|jne .B47',
            'cmpb 2168(%rcx), %al|jne .B47',
            'callq PublicKmacOutput|testl %eax, %eax|jne .B46|movq 2160(%rdi), %rcx|callq '+authority,
            'movl $1024, %edx|movq %rdi, %rcx|callq '+ZERO,
            'movb $5, %al|cmpb $6, %bl|je .B50'])
    else:
        sequences(b,[
            'callq PublicKmacOutput|testl %eax, %eax|je .B78',
            'movl $1024, %edx|movq %rdi, %rcx|callq '+ZERO,
            'movb $5, %al|cmpb $6, %bl|je .B80'])
    return dict(normal_post_construction_return_sites=result,buffer_destructor_dominates=True,
                header_bytes=header,payload_bytes=1024)


def key_completion(bodies,lane):
    if lane=='scalar': return scalar_key_completion(bodies)
    name=one(bodies,r'kmac_accelerated_stateNtB4_5State12finish_setup$')
    sequences(bodies[name],[
        'movq 1032(%rsi), %rax|orq 1024(%rsi), %rax|jne .B8',
        'cmpb $0, 1081(%rsi)|je .B14',
        'movb $0, 1081(%rsi)|movq %r15, 1048(%rsi)|movq %r14, 1040(%rsi)',
        'xorq 1056(%rsi), %r14|xorq 1064(%rsi), %r15|orq %r14, %r15|movb $2, %bl|jne .B8',
        'movl $1, %edx|callq '+ZERO+'|movb $0, 1081(%rsi)',
        'movb $2, 1089(%rsi)'])
    fixed=one(bodies,r'kmac_accelerated_stateNtB4_5State5fixed$')
    suffix=one(bodies,r'13append_suffix')
    sequences(bodies[fixed],[
        'movl $128, %eax|movl $256, %ecx|cmoveq %rax, %rcx|movb $6, %bl|cmpq %r8, %rcx|ja .B13',
        'xorl %r9d, %r9d|callq '+suffix])
    finish=one(bodies,r'Owner6finish$')
    sequences(bodies[finish],['xorl %r8d, %r8d|xorl %r9d, %r9d|callq '+suffix])
    return dict(exact_remaining_and_emitted=True,partial_key_pending_cleared=True,
                minimum_strengths=[128,256],fixed_output_suffix='declared bits',xof_output_suffix=0)


def scalar_key_completion(bodies):
    names=[n for n in bodies if 'setup6engine' in n and 'E6finish' in n]
    require(len(names)==2,'two scalar key completion strengths')
    returns={}
    for n in names:
        first='128Setup' in n
        low,high=('r14','r15') if first else ('rbx','r14')
        sequences(bodies[n],[
            'cmpb $1, 2227(%rdx)|jne .B24|movq 8(%rsi), %rax|orq (%rsi), %rax|jne .B24',
            f'xorq 48(%rsi), %{low}|xorq 56(%rsi), %{high}|orq %{low}, %{high}|jne .B24',
            f'movl ${168 if first else 136}, %r8d|subq %rax, %r8|addq %r8, %{low}|adcq $0, %{high}',
            'movb $2, 2227(%rsi)'])
        event=['leaq 1184(%rsi), %rcx','movl $1, %edx','callq '+ZERO,'movb $0, 1185(%rsi)']
        returns[n]=normal_returns(bodies[n],n,event)
    for strength in (128,256):
        fixed=one(bodies,rf'Kmac{strength}20finalize_secret_bits$')
        xof=one(bodies,rf'KmacXof{strength}17finalize_bits_xof$')
        suffix=one(bodies,rf'13append_suffix.*Cshake{strength}Nt')
        sequences(bodies[fixed],[f'cmpq ${strength}, %rax|jb .B4',
            'movq %rax, %r9|callq '+suffix])
        sequences(bodies[xof],['xorl %r9d, %r9d|callq '+suffix,
            'movl $16, %edx|movq %rdi, %rcx|callq '+ZERO,'jmp '+ZERO])
        returns[fixed]=normal_returns(bodies[fixed],fixed,
            ['movl $16, %edx','movq %rdi, %rcx','callq '+ZERO,
             'movl $1, %edx','movq %rsi, %rcx','callq '+ZERO])
    return dict(functions=names,normal_return_sites=returns,exact_remaining_and_emitted=True,
                partial_key_pending_cleared=True,minimum_strengths=[128,256],
                fixed_output_suffix='declared bits',xof_output_suffix=0)


def inspect(bodies,lane):
    return dict(comparison=comparison(bodies,lane),suffix=suffixes(bodies,lane),
                worker=worker(bodies,lane),key=key_completion(bodies,lane),
                retained_key=retained_key(bodies,lane),
                unwind_helpers=unwind_helpers(bodies,lane))


def retained_key(bodies,lane):
    rekey=one(bodies,r'Owner11rekey_setup$')
    finish=one(bodies,r'Owner20finish_customization$')
    if lane=='scalar':
        setup=one(bodies,r'kmac_stream_setupNtNt.*State12finish_setup$')
        sequences(bodies[rekey],[
            'movq 3288(%rsi), %r10|movb $3, %dil|cmpq $1024, %r10|ja .B2',
            'leaq (%rax,%r10,8), %rdx|addq $-8, %rdx',
            'movb $-1, %dil|movb $2, %al|jmp .B16',
            'movl $1024, %edx|movq %rsi, %rcx|callq '+ZERO+'|movq $0, 3288(%rsi)'])
        sequences(bodies[finish],[
            '.B54:|movb $6, %bl|cmpb $-1, %al|jne .B43',
            'callq '+setup+'|movl %eax, %ebx|cmpb $-1, %al|jne .B43|'
            'movl $1024, %edx|movq %rsi, %rcx|callq '+ZERO+'|movq $0, 3288(%rsi)|'
            'movb $0, 3296(%rsi)|movb $4, %al|jmp .B44'])
    else:
        setup=one(bodies,r'kmac_accelerated_stateNtB4_5State12finish_setup$')
        sequences(bodies[rekey],[
            'movq 2152(%r15), %r8|movb $3, %al|cmpq $1024, %r8|ja .B13',
            'leaq (%rax,%r8,8), %r9|addq $-8, %r9',
            'movb %sil, 2170(%r13)|movb $2, 2169(%r13)|movb $-1, %al|jmp .B18'])
        sequences(bodies[finish],[
            'movl %eax, %edi|cmpb $-1, %al|je .B51',
            'movl %eax, %edi|cmpb $-1, %al|jne .B50|movl $1024, %edx|'
            'movq 688(%rbp), %rsi|movq %rsi, %rcx|callq '+ZERO+'|movq $0, 2152(%rsi)|'
            'movb $0, 2168(%rsi)|movb $4, %al'])
        require(('callq '+setup) in lines(bodies[finish]),'retained key exact completion call')
    # Complete bodies are pinned separately. These are reviewed transition
    # landmarks, not a symbolic proof of every path or external exception.
    return dict(exact_retained_bit_shape=True,customization_retains_old_key=True,
                completed_key_setup_precedes_successful_output_clear=True,
                error_and_cancellation_tests_required=True,arbitrary_exception_claim=False)


def unwind_helpers(bodies,lane):
    names={n for n in bodies if n.startswith('?')}
    if lane=='scalar':
        require(not names,'saved scalar route has no emitted cleanup funclets')
        return dict(funclets=0,arbitrary_exception_claim=False)
    operation=one(bodies,r'drop_glueNtCsf.*kmac_accelerated9OperationE')
    guard=one(bodies,r'drop_glueNtNtCsf.*kmac_accelerated_state5GuardE')
    state=one(bodies,r'drop_glueNtCsc.*sha3_accelerated_state5StateE')
    roles=[(4,'Owner11begin_setup','movq 88(%rbx), %rcx|movzbl 87(%rbx), %edx',operation),
           (19,'Owner11rekey_setup','movq 88(%rbx), %rcx|movzbl 87(%rbx), %edx',operation),
           (8,'Owner12finish_setup','movq -24(%rbp), %rcx|movzbl -9(%rbp), %edx',operation),
           (17,'Owner13customization','movq -32(%rbp), %rcx|movzbl -9(%rbp), %edx',operation),
           (18,'Owner13customization','movq -24(%rbp), %rcx',guard),
           (44,'Owner20finish_customization','movq 688(%rbp), %rcx|movzbl 703(%rbp), %edx',operation),
           (11,'Owner3key','movq -16(%rbp), %rcx|movzbl -1(%rbp), %edx',operation),
           (30,'Owner6finish','movq -16(%rbp), %rcx|movzbl -1(%rbp), %edx',operation),
           (31,'Owner6finish','movq -24(%rbp), %rcx',guard),
           (27,'Owner7squeeze','movq -24(%rbp), %rcx|movzbl -1(%rbp), %edx',operation),
           (28,'Owner7squeeze','movq -16(%rbp), %rcx',guard),
           (49,'State5setup','leaq 4096(%rbx), %rcx',state),
           (17,'State5fixed','movq -8(%rbp), %rcx',guard)]
    result={}
    for number,parent,args,callee in roles:
        name=one(bodies,rf'^\?dtor\${number}@.*{parent}@')
        sequences(bodies[name],[args+'|callq '+callee])
        count=normal_returns(bodies[name],'"'+name+'"',['callq '+callee])
        result[name]=dict(cleanup_callee=callee,normal_return_sites=count)
    require(set(result)==names,'every emitted funclet has an exact cleanup role')
    sequences(bodies[guard],[
        'callq '+state+'|movq 1008(%rsi), %rax|orq 1016(%rsi), %rax|je .B3',
        'leaq 1080(%rsi), %rcx|movl $1, %edx|callq '+ZERO+'|movb $0, 1081(%rsi)',
        'movq $0, 1016(%rsi)|movq $2, 1008(%rsi)'])
    return dict(funclets=13,roles=result,invoked_funclets_call_their_destructors=True,
                arbitrary_exception_claim=False,dispatcher_and_window_reclamation_package=8)


def preconditions(ir,bodies,lane):
    """Private ABI assumptions, not permission for arbitrary foreign calls."""
    owner=f'align {16 if lane=="scalar" else 32} dereferenceable({3312 if lane=="scalar" else 2176})'
    checks={one(bodies,r'Owner6update$'):[owner,'range(i64 0, 1025)'],
            one(bodies,r'Owner6finish$'):[owner,'range(i64 0, 2305843009213693953)','range(i8 0, 9)'],
            one(bodies,r'Owner11begin_setup$'):[owner]}
    if lane=='avx2':
        checks[sha3.SESSION]=['align 32 dereferenceable(608)','dereferenceable(200)']
        checks[one(bodies,r'Key4bits$')]=['align 16 dereferenceable(64)',
                                        'align 32 dereferenceable(992)','dereferenceable(1)']
    for name,tokens in checks.items():
        found=[line for line in ir.splitlines() if line.startswith('define internal fastcc ') and '@'+name+'(' in line]
        require(len(found)==1 and all(t in found[0] for t in tokens),'KMAC typed private ABI '+name)
    return dict(input_maximum_bytes=1024,owner_alignment=16 if lane=='scalar' else 32,
                checked_functions=checks,receiver_and_typed_callers_required=True,
                arbitrary_foreign_calls_qualified=False)
