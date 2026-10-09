"""Scalar cSHAKE setup arithmetic and initialization before prefix absorption.

Later setup, transfer, failure cleanup and runtime internals remain separate.
"""
import windows_enclave_sha3_batch_empty as empty
import windows_enclave_sha3_setup as setup

life,s,L=empty.life,empty.s,empty.L
ENCODE='_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018511encode_u128'
UPDATE='_RNvMNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6spongeINtNtB4_5owner20HardenedFips202OwnerKj'
MASK=(1<<64)-1


def instructions(rate):
    s.require(rate in (136,168),'two scalar cSHAKE rates')
    lines=L(f'''.B{18 if rate==136 else 28}:|movq %rsi, 280(%rsp)
        leaq 1390(%rsp), %rcx|movq %rdi, %rdx|movq %rbx, %r8|callq {ENCODE}
        movzwl 1646(%rsp), %esi|leaq 1680(%rsp), %rcx
        movq %r14, %rdx|movq %r15, %r8|callq {ENCODE}|movzwl 1936(%rsp), %eax
        leal 2(%rsi), %ecx|cmpl $257, %esi|movl $2, %edx|cmovbl %ecx, %edx
        xorl %ecx, %ecx|cmpl $257, %eax|cmovbl %eax, %ecx
        addl %edx, %ecx|shll $3, %ecx|movzwl %cx, %eax|addq %rdi, %rax''')
    if rate==136:
        lines+=L('''movq %rbx, %r8|adcq $0, %r8|movb $1, %bpl|jb .B77
            addq %r14, %rax|adcq %r15, %r8|jb .B77
            movq %rdi, %rcx|orq %r14, %rcx|movq %rcx, 48(%rsp)
            movq %r15, %rbp|orq %rbx, %rbp|orq %rbp, %rcx|sete %r10b
            movq %r8, %rcx|shldq $61, %rax, %rcx|shrq $3, %r8
            xorl %r9d, %r9d|testb $7, %al|setne %r9b|addq %rcx, %r9|adcq $0, %r8
            movq %r8, %rax|shldq $61, %r9, %rax|movq %r8, %rcx|shrq $3, %rcx
            addq %rax, %rcx|adcq $0, %rcx|movabsq $-1085102592571150095, %rdx
            movq %rcx, %rax|mulq %rdx|shrq $4, %rdx|movl %edx, %eax
            shll $4, %eax|addl %edx, %eax|subl %eax, %ecx
            movl %r9d, %eax|andl $7, %eax|leaq (%rax,%rcx,8), %rax
            movl $136, %esi|subq %rax, %rsi|movl $0, %ebx|sbbq %rbx, %rbx
            testq %rax, %rax|cmoveq %rax, %rbx|cmoveq %rax, %rsi
            addq %r9, %rsi|adcq %r8, %rbx|addb %r10b, %r10b|movb %r10b, 40(%rsp)''')
    else:
        lines+=L('''movq %rbx, %rcx|adcq $0, %rbx|movb $1, %bpl|jb .B85
            addq %r14, %rax|adcq %r15, %rbx|jb .B85|movb %r12b, 35(%rsp)
            movq %rdi, %rdx|orq %r14, %rdx|movq %rdx, 48(%rsp)
            movq %r15, %r8|orq %rcx, %r8|movq %r8, 40(%rsp)
            movq %rdx, %rcx|orq %r8, %rcx|sete 36(%rsp)
            movq %rbx, %rcx|shldq $61, %rax, %rcx|shrq $3, %rbx
            xorl %ebp, %ebp|testb $7, %al|setne %bpl|addq %rcx, %rbp|adcq $0, %rbx
            movq %rbp, 1360(%rsp)|movq %rbx, 1368(%rsp)
            movq $168, 1344(%rsp)|movq $0, 1352(%rsp)
            leaq 1360(%rsp), %rcx|leaq 1344(%rsp), %rdx|callq __umodti3
            pshufd $238, %xmm0, %xmm1|movq %xmm1, %rax|movq %xmm0, %rcx
            pxor %xmm6, %xmm6|pcmpeqd %xmm6, %xmm0|movmskps %xmm0, %edx
            xorl $15, %edx|movl $168, %esi|subq %rcx, %rsi
            movl $0, %r12d|sbbq %rax, %r12|testl %edx, %edx|movl $0, %eax
            cmoveq %rax, %r12|cmoveq %rax, %rsi|addq %rbp, %rsi|adcq %rbx, %r12
            movzbl 36(%rsp), %ebx|addb %bl, %bl''')
    lines+=L('movb $1, 1747(%rsp)|leaq 1748(%rsp), %rcx|movw $0, 1744(%rsp)')
    if rate==136:lines+=['pxor %xmm6, %xmm6']
    lines+=L('movdqa %xmm6, 1680(%rsp)|movl $1040, %r8d|xorl %edx, %edx|callq memset')
    lines+=L('orq 48(%rsp), %rbp' if rate==136 else 'movq 40(%rsp), %rax|orq 48(%rsp), %rax')
    lines+=L(f'''movl $0, %eax|cmoveq %rax, %{ 'rbx' if rate==136 else 'r12'}|cmoveq %rax, %rsi
        movq 7296(%rsp), %rax''')
    if rate==136:lines+=['movq %rax, %rbp']
    lines+=L(f'''movq %rax, 1704(%rsp)|movq %rdi, 1696(%rsp)
        movq %r15, 1720(%rsp)|movq %r14, 1712(%rsp)|movq %rsi, 1728(%rsp)
        movq %{ 'rbx' if rate==136 else 'r12'}, 1736(%rsp)''')
    lines+=L('movzbl 40(%rsp), %eax|movb %al, 1746(%rsp)' if rate==136 else 'movb %bl, 1746(%rsp)')
    lines+=L(f'setne 2788(%rsp)|je .B{42 if rate==136 else 44}')
    lines+=['movdqu %xmm6, 1630(%rsp)']+[f'movdqu %xmm6, {at}(%rsp)' for at in range(1616,1391,-16)]
    lines+=L(f'''movw ${-30719 if rate==136 else -22527}, 1390(%rsp)|movw $2, 1646(%rsp)
        leaq 1390(%rsp), %r14|movl $2, %r8d|leaq 1748(%rsp), %r15
        movq %r15, %rcx|movq %r14, %rdx|callq {UPDATE}{rate:x}_E6updateB6_
        testb %al, %al|je .B{48 if rate==136 else 53}|movb $1, %bpl''')
    return lines+(['jmp .B72'] if rate==136 else [])


def check_shapes(bodies,assembly):
    names,_,_=empty.start.check_shapes(bodies,assembly,'scalar');name=names['start']
    lines=life.code(bodies[name]);pred=empty.predecessors(lines);covered=set()
    dispatch=lines.index('jmpq *%rcx')
    for rate in (136,168):
        part=instructions(rate);at=lines.index(part[0])
        end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[at:end]==part,'complete cSHAKE arithmetic/initialization and first-prefix block')
        s.require(pred[at]=={dispatch},'cSHAKE initializer only entered from admitted identity dispatch')
        covered.update(range(at,end))
    s.require(lines[lines.index('.B28:')+len(instructions(168))]=='.B79:', 'rate168 update-error fallthrough')
    return name,sorted(covered)


def add128(a,b):
    low=(a&MASK)+(b&MASK);high=(a>>64)+(b>>64)+(low>>64)
    return None if high>MASK else (high<<64)|(low&MASK)


def counts(rate,name,custom):
    """Machine-width carry/ceiling/remainder model; __umodti3 is a contract."""
    s.require(type(rate) is int and rate in (136,168) and all(type(x) is int and
        0<=x<1<<128 for x in (name,custom)),'bounded public cSHAKE setup lengths')
    lengths=[max(1,(x.bit_length()+7)//8)+1 for x in (name,custom)]
    fixed=(2+sum(n if n<257 else 0 for n in lengths))*8
    bits=add128(name,fixed)
    if bits is not None:bits=add128(bits,custom)
    if bits is None:return None
    low,high=bits&MASK,bits>>64
    shifted=((high<<61)|(low>>3))&MASK
    low_bytes=shifted+int(bool(low&7));high_bytes=(high>>3)+(low_bytes>>64)
    byte_count=(high_bytes<<64)|(low_bytes&MASK)
    rem=setup.remainder136(byte_count) if rate==136 else byte_count%168
    s.require(0<=rem<rate,'remainder contract')
    rounded=add128(byte_count,0 if rem==0 else rate-rem)
    # bits<=u128::MAX means ceil(bits/8)<=2^125; rounding adds at most167.
    s.require(rounded is not None and rounded<=(1<<125)+167,'rounding cannot overflow u128')
    customized=bool(name or custom)
    return dict(bits=bits,bytes=byte_count,expected=rounded if customized else 0,
        remaining=name,custom_bits=custom,phase=0 if customized else 2,
        customized=customized,prefix=[1,rate] if customized else [])


def initialization(rate,name,custom):
    """Live fields just BEFORE the first update, not the later retained copy."""
    fields=counts(rate,name,custom)
    if fields is None:return None
    memory=[None]*7168
    def put(at,width,value):
        s.require(32<=at and at+width<=7168 and 0<=value<1<<(8*width),'bounded initialized field')
        memory[at:at+width]=value.to_bytes(width,'little')
    for at,value in ((1680,0),(1696,name),(1712,custom),(1728,fields['expected'])):put(at,16,value)
    for at,value in ((1744,0),(1745,0),(1746,fields['phase']),(1747,1),(2788,int(fields['customized']))):put(at,1,value)
    put(1748,1040,0)
    s.require(None not in memory[1680:2789],'all1109 active setup bytes initialized')
    if fields['customized']:
        put(1390,256,0);put(1390,2,1+(rate<<8));put(1646,2,2)
        s.require(memory[1390:1392]==fields['prefix'] and 1648<=1680 and 1648<=1748,
                  'public two-byte rate prefix disjoint from metadata and sponge owner')
    return dict(active_setup_span=[1680,2789],owner_span=[1748,2788],
        initial_owner_zeroed=True,first_prefix_bytes=fields['prefix'],
        padding_span=[2789,2800],padding_initialized=False,helper_scratch_reused_after_length_read=True,
        later_setup_transfers_qualified=False,private_frame_erasure_qualified=False)


def inspect(bodies,assembly,prior,construction):
    name,positions=check_shapes(bodies,assembly)
    helpers={ENCODE,*(UPDATE+f'{rate:x}_E6updateB6_' for rate in (136,168))}
    s.require(prior['prior_semantics_replayed'] and helpers<=set(prior['exact_body_reference_extent_and_abi']),
              'exact encoding and sponge update semantics replayed')
    s.require(construction['function']==name and construction['slot_equality_before_indexed_plan_read'] and
        construction['geometry']['home_offsets_from_entry']==[40,48,56], 'admitted inputs and Win64 u128 home slots')
    return dict(function=name,reviewed_instruction_positions=positions,
        rates={str(rate):initialization(rate,1,1) for rate in (136,168)},
        checked_total_bit_additions=2,ceiling_and_rate_rounding_cannot_overflow=True,
        cshake_initial_arithmetic_and_fields_qualified=True,
        public_umodti3_runtime_pending=True,all_constructor_paths_qualified=False,
        subsequent_prefix_absorption_and_failure_cleanup_qualified=False,
        private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
