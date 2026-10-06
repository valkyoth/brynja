"""Semantic checks for the saved AVX2 SHA-3 route, not a generic verifier."""
import re

import windows_enclave_sha3_permutation as scalar
import windows_enclave_engine_review as engine

require,digest=scalar.require,scalar.digest
KERNEL,SESSION,ZERO=engine.KERNEL,engine.SESSION,scalar.ZERO
OWNER='_RNvMs_CsbweaVgBOhqc_16sha3_acceleratedNtB4_5Owner'
STATE='_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State'
WORKER='_RNvCs9k1jhC7Dm7H_23sha3_accelerated_worker'
DROP='_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCs9k1jhC7Dm7H_23sha3_accelerated_worker7BuffersEBD_'
CONSTANT='anon.886b1edfcdffe7c13102d1d0ad2ffa3f.1'
RESIDENT='_RNvMs_Csav2wNVSWsYU_25sha3_accelerated_residentNtB4_8Resident'
RESIDENT_DROP='_RNvXs0_Csav2wNVSWsYU_25sha3_accelerated_residentNtB5_8ResidentNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
KAT='_RNvNtNtCshYLbG8W7MpL_17brynja_crypto_cpu16static_execution10operations12known_answer'


def normalized(body):
    return scalar.normalized(body)


def bodies(text,names):
    result={}
    for name in names:
        label='"'+name+'"' if name.startswith('?') else name
        token='\n'+label+':\n'
        require(text.count(token)==1,'unique emitted assembly function')
        start=text.index(token)+1
        ends=[p for p in (text.find('\t.seh_endproc',start),text.find('.Lfunc_end',start)) if p>=0]
        require(ends,'bounded assembly function')
        result[name]=text[start:min(ends)]
    return result


def kernel_shape():
    m=scalar.mem
    lines=['xorl %ecx, %ecx','.Ltmp4:','movq (%r9,%rcx), %rax',
        'movq %rax, (%r10,%rcx)','addq $8, %rcx','cmpq $200, %rcx','jne .Ltmp4',
        'xorl %r8d, %r8d','.Ltmp5:','xorl %ecx, %ecx','.Ltmp6:',
        'movq (%r10,%rcx), %rax']
    lines += [f'xorq {40*y}(%r10,%rcx), %rax' for y in range(1,5)]
    lines += ['movq %rax, 200(%r10,%rcx)','addq $8, %rcx','cmpq $40, %rcx','jne .Ltmp6']
    for x in range(5):
        lines += [f'movq {200+8*((x-1)%5)}(%r10), %rax',
            f'movq {200+8*((x+1)%5)}(%r10), %rdx','rolq %rdx','xorq %rdx, %rax',
            f'movq %rax, {240+8*x}(%r10)']
    for source,rotation,destination in scalar.rho_pi():
        lines += [f'movq {m(source*8,"%r10")}, %rax',f'xorq {240+8*(source%5)}(%r10), %rax',
            'rolq '+('' if rotation==1 else f'${rotation}, ')+'%rax',
            f'movq %rax, {280+8*destination}(%r10)']
    lines += ['xorl %ecx, %ecx','.Ltmp7:',
        'vmovdqu 280(%r10,%rcx), %ymm0','vmovdqu 288(%r10,%rcx), %ymm1',
        'vpermq $57, %ymm1, %ymm2','vpbroadcastq 280(%r10,%rcx), %ymm3',
        'vpblendd $192, %ymm3, %ymm2, %ymm2','vpandn %ymm2, %ymm1, %ymm1',
        'vpxor %ymm1, %ymm0, %ymm0','vmovdqu %ymm0, (%r10,%rcx)',
        'movq 280(%r10,%rcx), %rax','notq %rax','andq 288(%r10,%rcx), %rax',
        'xorq 312(%r10,%rcx), %rax','movq %rax, 32(%r10,%rcx)',
        'addq $40, %rcx','cmpq $200, %rcx','jne .Ltmp7',
        'movq (%r11,%r8), %rax','xorq %rax, (%r10)','addq $8, %r8',
        'cmpq $192, %r8','jne .Ltmp5','xorl %ecx, %ecx','.Ltmp8:',
        'movq (%r10,%rcx), %rax','movq %rax, (%r9,%rcx)','addq $8, %rcx',
        'cmpq $200, %rcx','jne .Ltmp8','xorl %eax, %eax','xorl %ecx, %ecx','.Ltmp9:',
        'movq %rax, (%r10,%rcx)','addq $8, %rcx','cmpq $576, %rcx','jne .Ltmp9']
    lines += [f'vpxor %ymm{i}, %ymm{i}, %ymm{i}' for i in range(4)]
    lines += [f'xorl %{r}, %{r}' for r in ('eax','ecx','edx','r8d')]
    return lines+['cmpl %eax, %eax','vzeroupper']


def kernel(body):
    require(body.count('#APP')==body.count('#NO_APP')==1,'one complete opaque kernel')
    before,opaque=body.split('#APP');opaque,after=opaque.split('#NO_APP')
    require(normalized(opaque)==kernel_shape(),'complete theta/rho/pi/chi/iota, commit and erase schedule')
    for token in ('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END'):
        require(opaque.count(token)==1,'unique kernel marker')
    require(normalized(opaque.split('BRYNJA_REGISTER_ERASE')[1].split('# BRYNJA_SECRET_END')[0])==kernel_shape()[-10:],
            'all four working vectors, four working GPRs, flags and upper halves cleared')
    prologue=['subq $168, %rsp','.seh_stackalloc 168']
    for r in range(15,5,-1):
        prologue += [f'vmovaps %xmm{r}, {scalar.mem((r-6)*16,"%rsp")}',f'.seh_savexmm %xmm{r}, {(r-6)*16}']
    prologue += ['.seh_endprologue','movq %rdx, %r9','movq %rcx, %r10',f'leaq {CONSTANT}(%rip), %r11']
    require(normalized(before)[3:]==prologue,'only incoming nonvolatile vector saves before secret work')
    epilogue=[f'vmovaps {scalar.mem((r-6)*16,"%rsp")}, %xmm{r}' for r in range(6,16)]
    epilogue += ['.seh_startepilogue','addq $168, %rsp','.seh_endepilogue','retq']
    require(normalized(after)==epilogue,'no secret reload after erasure; only ABI incoming-vector restores')
    return dict(rounds=24,state_bytes=200,scratch_bytes=576,opaque_stack_accesses=0,
        working_vectors=[0,1,2,3],working_gprs=['rax','rcx','rdx','r8'],
        incoming_nonvolatile_saves=[dict(register=r,offset=(r-6)*16) for r in range(6,16)],
        saved_vectors_require_outer_window_clearing=True)


def contains(body,sequences,label):
    text='\n'.join(normalized(body))
    for sequence in sequences:
        require(sequence.replace('|','\n') in text,'reviewed '+label+' sequence: '+sequence)


def semantics(all_bodies):
    result=kernel(all_bodies[KERNEL])
    contains(all_bodies[SESSION],[
        'movq 576(%rcx), %r8|movzbl 8(%r8), %eax|testl %eax, %eax|je .LBB16_1',
        'cmpl $1, %eax|jne .LBB16_8',
        'cmpq 584(%rcx), %r9|jne .LBB16_7',
        'callq '+KERNEL+'|movq %rsi, %rcx|callq '+engine.cleanup.SCRATCH,
        'movb $-1, %al|jmp .LBB16_7'], 'session epoch/health/dispatch/wipe')
    contains(all_bodies[OWNER+'9operation'],[
        'testq %r8, %r8|je .LBB21_12','movq 2016(%rsi), %rax|incq %rax|cmpq %r8, %rax|je .LBB21_22',
        'cmpb $4, 9(%rax)|jne .LBB21_24|cmpb $1, 8(%rax)|jne .LBB21_24',
        'movq %r8, 2016(%rsi)|movq %rsi, (%rdi)|movb $0, 8(%rdi)'], 'operation admission')
    contains(all_bodies[WORKER+'7receive'],[
        'leaq -21(%r15), %r12|cmpq $10, %r12|ja .LBB2_34',
        'cmpq %rax, %r8|jne .LBB2_33|cmpq 2024(%rcx), %rbx|jne .LBB2_33|cmpb 2040(%rcx), %bpl|jne .LBB2_33',
        'callq PublicSha3Output|movq %rdi, %rcx|testl %eax, %eax|jne .LBB2_32',
        'callq _RNvCsbweaVgBOhqc_16sha3_accelerated15check_authority',
        'movl $1024, %edx|movq %rcx, %rsi|callq '+ZERO], 'receiver/public-output authorization')
    for name,body in all_bodies.items():
        if name.startswith(OWNER) and name not in (OWNER+'9operation',OWNER+'5clear'):
            require('callq\t'+OWNER+'9operation' in body,'every owner entry checks exact phase/sequence/authority')
            require('callq\t'+ZERO in body,'owner operation output cleanup exists')
    contains(all_bodies[OWNER+'6rehash'],[
        'leaq 96(%rbx), %rcx|movl $1024, %edx|callq '+ZERO,
        'movl $992, %r8d|movq %r15, %rcx|movq %r14, %rdx|callq memcpy'], 'rehash staging and replacement')
    contains(all_bodies[STATE+'12finish_fixed'],[
        'cmpq %r9, 952(%rsi)|jne .LBB45_19',
        'callq '+engine.COPY+'|movb $10, %dil|cmpb $-1, %al|je .LBB45_15',
        'leaq 32(%rsp), %rcx|movl $1024, %edx|callq '+ZERO], 'fixed-output transaction')
    contains(all_bodies[OWNER+'7squeeze'],[
        'testb %r12b, %r12b|jne .LBB31_4',
        'leaq 48(%rsp), %rcx|movl $1024, %edx|callq '+ZERO,
        'movq %rdi, 2024(%rsi)|movb %bl, 2040(%rsi)|movb %al, 2042(%rsi)'], 'terminal/continuing squeeze staging')
    for name,register,label in ((RESIDENT+'3new','rdi','.LBB34_2'),(RESIDENT_DROP,'rsi','.LBB35_1')):
        sequence=[f'movb $0, {scalar.mem(i,"%"+register,"%rax")}' for i in range(8)]
        sequence += ['addq $8, %rax','cmpq $4096, %rax','jne '+label]
        contains(all_bodies[name],['|'.join(sequence)],'complete resident-page erasure')
    contains(all_bodies[RESIDENT+'3new'],['callq '+KAT,
        'movq $2, (%rdi)|movb %cl, 8(%rdi)|movb $4, 9(%rdi)|testb %al, %al|je .LBB34_1',
        'movq %rdi, 2064(%rdi)'], 'resident authority before borrowing owner; failed KAT clears page')
    contains(all_bodies[STATE+'7initial'],['cmpb $4, 9(%rdx)|jne .LBB52_6',
        'cmpq 904(%rsp), %rcx|jne .LBB52_14',
        'callq '+KERNEL+'|movq %rsi, %rcx|callq '+engine.cleanup.SCRATCH,
        'movb $2, 8(%rax)|movq $3, (%rax)|jmp .LBB52_14'], 'session KAT and revocation')
    # Each frame has only direct calls. The three jump tables are bound separately.
    indirect={n:re.findall(r'^\s*(?:callq|jmpq)\s+\*([^\n]+)',b,re.M) for n,b in all_bodies.items()}
    indirect={n:v for n,v in indirect.items() if v}
    require(indirect=={WORKER+'7receive':['%r12','%r9'],OWNER+'6finish':['%rax']},'complete indirect-transfer population')
    return result


def zero_permutation():
    """Independent small coordinate model for the public zero-state KAT data."""
    mask=(1<<64)-1
    def rotate(v,n): return ((v<<n)|(v>>(64-n))) & mask if n else v
    state=[0]*25
    raw=scalar.round_constants()
    for at in range(0,192,8):
        parity=[state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20] for x in range(5)]
        delta=[parity[(x-1)%5]^rotate(parity[(x+1)%5],1) for x in range(5)]
        b=[0]*25
        for source,rotation,destination in scalar.rho_pi(): b[destination]=rotate(state[source]^delta[source%5],rotation)
        state=[b[x+5*y]^((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y]) for y in range(5) for x in range(5)]
        state[0]^=int.from_bytes(raw[at:at+8],'little')
    return b''.join(v.to_bytes(8,'little') for v in state)


def preconditions(ir):
    checks={OWNER+'6update':['range(i64 0, 1025)','align 32 dereferenceable(2048)'],
        OWNER+'6finish':['range(i64 0, 1025)'],OWNER+'11setup_chunk':['range(i64 0, 1025)'],
        STATE+'7initial':['range(i8 0, 8)'],STATE+'12finish_fixed':['range(i64 28, 65)'],
        SESSION:['align 32 dereferenceable(608)','dereferenceable(200)']}
    for name,tokens in checks.items():
        lines=[l for l in ir.splitlines() if l.startswith('define internal fastcc ') and '@'+name+'(' in l]
        require(len(lines)==1 and all(t in lines[0] for t in tokens),'typed private ABI preconditions')
    return dict(algorithm_range=[0,7],input_maximum_bytes=1024,owner_alignment=32,
        standalone_arbitrary_abi_calls_qualified=False,receiver_and_typed_callers_required=True)


def buffer_exits(body):
    lines=normalized(body);labels={s[:-1]:i for i,s in enumerate(lines) if s.endswith(':')}
    require('.LBB0_27' in labels,'buffer construction entry')
    pending=[(labels['.LBB0_27'],False)];seen=set();returns=set()
    while pending:
        at,cleared=pending.pop()
        if (at,cleared) in seen: continue
        seen.add((at,cleared));require(at<len(lines),'bounded worker CFG')
        line=lines[at]
        if line=='callq '+DROP: cleared=True
        if line=='retq':
            require(cleared,'no normal post-construction return bypasses Buffers drop')
            returns.add(at);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1);require(target in labels,'direct worker branch')
            pending.append((labels[target],cleared))
            if op in ('jmp','jmpq'): continue
        pending.append((at+1,cleared))
    require(len(returns)==1,'one reviewed normal return')
    contains(body,['leaq 64(%rsp), %rcx|callq '+DROP+'|jmp .LBB0_52'],'buffer destruction')
    return dict(normal_post_construction_return_sites=1,destructor_dominates_returns=True)
