"""Saved SIMD owner admission/cancellation and their exact callback funclets."""
import re
import windows_enclave_sha3_simd_resident as resident

life,s,L=resident.life,resident.s,resident.L


def names(bodies):
    return {role:s.one(bodies,p) for role,p in (
        ('operation',r'^[^?].*keccak_simd.*Owner9operation$'),
        ('check',r'^_RNvCs.*keccak_simd5check$'),
        ('cancel',r'^[^?].*keccak_simd_resident.*Resident6cancel$'))}


def clear(reg,quarantine=True):
    code=L(f'''leaq 72(%{reg}), %rcx|movl $1024, %edx|callq {life.ZERO}|
        movb $-1, 8(%{reg})|movb ${2 if quarantine else 0}, 1104(%{reg})''')
    if quarantine:code+=L(f'movq 64(%{reg}), %rax|movb $0, 16(%rax)')
    return code


def check_shape():
    return L('''pushq %rbp|subq $48, %rsp|leaq 48(%rsp), %rbp|movq $-2, -8(%rbp)|
        cmpb $1, 16(%rcx)|jne .B7|movq %rcx, %rax|movzbl 17(%rcx), %ecx|
        movq %rax, -16(%rbp)|callq *8(%rax)|nop|testb %al, %al|
        movq -16(%rbp), %rcx|je .B7|movb $5, %al|cmpb $0, 17(%rcx)|jne .B8|
        cmpb $1, 16(%rcx)|jne .B7|movq %rcx, %rax|xorl %ecx, %ecx|
        callq *8(%rax)|nop|movl %eax, %ecx|movb $-1, %al|testb %cl, %cl|
        movq -16(%rbp), %rcx|jne .B8|.B7:|movb $0, 16(%rcx)|movb $5, %al|
        .B8:|addq $48, %rsp|popq %rbp|retq''')


def operation_shape():
    code=L('''pushq %rbp|pushq %rsi|pushq %rdi|pushq %rbx|subq $56, %rsp|
        leaq 48(%rsp), %rbp|movq $-2, (%rbp)|movq %rdx, %rbx|movq %rcx, %rsi|
        cmpb %r9b, 1104(%rdx)|jne .B15|movq %r8, %rdi|movq 1096(%rbx), %rax|
        incq %rax|setne %cl|cmpq %r8, %rax|sete %al|testb %al, %cl|jne .B2''')
    code+=clear('rbx')+L('movb $1, (%rsi)|movb $2, 8(%rsi)|jmp .B14|.B15:')
    code+=clear('rbx')+L('movb $0, (%rsi)|movb $2, 8(%rsi)|jmp .B14')
    code+=L('''.B2:|movq 64(%rbx), %rax|cmpb $1, 16(%rax)|jne .B9|
        movq %rbx, -16(%rbp)|movzbl 17(%rax), %ecx|movq %rax, -8(%rbp)|
        callq *8(%rax)|nop|testb %al, %al|movq -16(%rbp), %rbx|
        movq -8(%rbp), %rax|je .B9|cmpb $0, 17(%rax)|jne .B10|
        cmpb $1, 16(%rax)|jne .B9|xorl %ecx, %ecx|callq *8(%rax)|nop|
        testb %al, %al|movq -16(%rbp), %rbx|movq -8(%rbp), %rax|je .B9|
        movq %rdi, 1096(%rbx)|movq %rbx, (%rsi)|movb $0, 8(%rsi)|jmp .B14|
        .B9:|movb $0, 16(%rax)|.B10:|movb $5, (%rsi)|movb $2, 8(%rsi)''')
    return code+clear('rbx')+L('.B14:|addq $56, %rsp|popq %rbx|popq %rdi|popq %rsi|popq %rbp|retq')


def cancel_shape(n):
    return life.frame(48)+L(f'''movzbl 1104(%rcx), %r9d|cmpb $2, %r9b|jne .B2|
        xorl %eax, %eax|jmp .B5|.B2:|movq %rdx, %r8|movq %rcx, %rdx|
        leaq 32(%rsp), %rcx|callq {n['operation']}|cmpb $2, 40(%rsp)|jne .B4|
        movzbl 32(%rsp), %eax|jmp .B5|.B4:|movq 32(%rsp), %rsi''')+clear('rsi',False)+L(
        'movb $-1, %al|.B5:')+life.frame(48,end=True)


def cleanup(bodies,asm,n):
    expected={};handlers={};chains={}
    for role,numbers,frame,begin,states,ips in (
        ('check',(9,10),40,33,[(-1,9),(-1,10)],[(46,0),(48,1),(49,-1)]),
        ('operation',(12,16,17),48,34,[(-1,12),(0,17),(0,16)],[(50,2),(52,1),(53,-1)])):
        parent=n[role];registers=['rbp'] if role=='check' else ['rbp','rsi','rdi','rbx']
        stack=32 if role=='check' else 40;by_number={}
        for number in numbers:
            name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@\?0\?'+re.escape(parent)+r'@')
            code=[f'.B{number}:','movq %rdx, 16(%rsp)']+['pushq %'+r for r in registers]+[
                f'subq ${stack}, %rsp','leaq 48(%rdx), %rbp']
            if role=='operation' and number==12:code+=['movq -16(%rbp), %rsi']+clear('rsi')
            else:code+=L(f'movq {-16 if role=="check" else -8}(%rbp), %rax|movb $0, 16(%rax)')
            code+=[f'addq ${stack}, %rsp']+['popq %'+r for r in reversed(registers)]+['retq']
            s.require(life.code(bodies[name])==code,'complete owner/check cleanup funclet')
            handlers[name]=dict(parent=parent,number=number);by_number[number]=name
        prefix={p:p+parent for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
        expected[prefix['$cppxdata$']]=['429065506',str(len(states)),prefix['$stateUnwindMap$']+'@IMGREL',
            '0','0','4',prefix['$ip2state$']+'@IMGREL',str(frame),'0','1']
        expected[prefix['$stateUnwindMap$']]=[v for p,h in states for v in (str(p),'"'+by_number[h]+'"@IMGREL')]
        expected[prefix['$ip2state$']]=[f'.Lfunc_begin{begin}@IMGREL','-1']+[
            v for label,state in ips for v in (f'.Ltmp{label}@IMGREL',str(state))]
        chains[parent]={}
        for label,state in ips:
            chain=[]
            while state!=-1:
                ancestor,handler=states[state];chain.append(by_number[handler]);state=ancestor
            chains[parent][f'.Ltmp{label}']=chain
    for label,want in expected.items():
        matches=list(re.finditer(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M))
        s.require(len(matches)==1,'unique owner cleanup table')
        s.require([v.strip().split(None,1)[1] for v in matches[0][1].splitlines()]==want,'exact owner cleanup table')
    for role,first,pre in (('check',46,'movq %rax, -16(%rbp)|'),('operation',50,'movq %rax, -8(%rbp)|')):
        s.sequences(bodies[n[role]],[f'.Ltmp{first}:|{pre}callq *8(%rax)|nop|.Ltmp{first+1}:'])
    s.sequences(bodies[n['check']],['.Ltmp48:|movq %rcx, %rax|xorl %ecx, %ecx|callq *8(%rax)|nop|.Ltmp49:'])
    s.sequences(bodies[n['operation']],['.Ltmp52:|xorl %ecx, %ecx|callq *8(%rax)|nop|.Ltmp53:'])
    return dict(invoked_funclets=handlers,expected_tables=expected,ordered_cleanup_chains=chains,os_dispatcher_qualified=False)


def inspect(bodies,assembly,ir,construction,checked_session):
    n=names(bodies)
    s.require(construction['callback_is_pure_compiled_tag_check'] and construction['public_callback_not_host_supplied'],
              'owner callback origin must be replayed')
    p=construction['placement'];s.require(p['owner_authority_pointer_offset']==64 and
        p['owner_page_span']==[24,1136] and p['authority_page_span']==[0,24],'exact resident/authority placement')
    s.require(checked_session['functions']['zero']==life.ZERO,'reviewed volatile output clear')
    for role,expected in (('check',check_shape()),('operation',operation_shape()),('cancel',cancel_shape(n))):
        s.require(life.code(bodies[n[role]])==expected,'complete SIMD owner '+role)
    target='"target-cpu"="x86-64" "target-features"="'+resident.session.zero.SIMD_FEATURES+'"'
    signature={
        'check':('noundef range(i8 -1, 6) i8','ptr noundef nonnull align 8 captures(none) %0'),
        'cancel':('noundef range(i8 -1, 8) i8','ptr nonnull %.16.val, i64 noundef %0'),
        'operation':('void','ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none) dereferenceable(16) %0, ptr noalias nofree noundef nonnull align 8 dereferenceable(1112) %1, i64 noundef %2, i8 noundef range(i8 0, 2) %3')}
    for role,(result,args) in signature.items():
        expected=f'define internal fastcc {result} @{n[role]}({args}) unnamed_addr '+(
            '{ uwtable '+target+' } personality ptr @__CxxFrameHandler3 {')
        s.require(life.reuse.abi(ir,n[role])==expected,'exact SIMD owner ABI '+role)
    return dict(functions=n,cleanup=cleanup(bodies,assembly,n),
        phase_and_nonwrapping_sequence_before_authority=True,
        owner_authority_offset=64,authority_callback_offset=8,
        expected_kernel_tag=0,sequence_commit_after_two_revalidations=True,
        rejected_operation_clears_output_and_quarantines=True,
        cancellation_clears_output_then_sets_empty=True,
        already_quarantined_cancellation_does_not_repeat_wipe=True,
        standalone_check_wrong_kernel_returns_error_without_quarantine=True,
        caller_must_preserve_resident_authority_and_exclusive_owner=True,
        digest_and_worker_provenance_qualified=False,private_frame_erasure_qualified=False)
