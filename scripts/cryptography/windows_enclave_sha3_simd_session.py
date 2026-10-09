"""Saved Keccak SIMD session, scratch clearing and FH3 cleanup composition.

Private caller authority/allocation validity and the OS unwind implementation
remain prerequisites. This is not a generic assembly or exception verifier.
"""
import re
import windows_enclave_sha3_batch_lifecycle as life
import windows_enclave_sha2_simd_reuse as zero

s=life.s


def names(bodies):
    return {role:s.one(bodies,pattern) for role,pattern in (
        ('session',r'^[^?].*keccak_hardened_batch.*Session13permute_bytes$'),
        ('wipe',r'^[^?].*keccak_hardened_batch7scratch.*Workspace4wipe$'),
        ('pack',r'keccak_hardened_batch8transfer9transposeKb1_'),
        ('unpack',r'keccak_hardened_batch8transfer9transposeKb0_'),
        ('wrapper',r'keccak_hardened_batch3x8614permute_secret$'))}


def wipe_shape():
    return life.frame(32)+['movq %rcx, %rsi','movl $800, %edx','callq '+life.ZERO,
        'leaq 800(%rsi), %rcx','movl $160, %edx','callq '+life.ZERO,
        'leaq 960(%rsi), %rcx','movl $160, %edx','callq '+life.ZERO,
        'addq $1120, %rsi','movl $800, %edx','movq %rsi, %rcx',
        'addq $32, %rsp','popq %rsi','jmp '+life.ZERO]


def session_shape(n):
    return ['pushq %rbp','pushq %r14','pushq %rsi','pushq %rdi','pushq %rbx',
        'subq $64, %rsp','leaq 64(%rsp), %rbp','movq $-2, -8(%rbp)',
        'movq %r8, %r14','movq %rcx, %rbx','cmpb $1, 16(%rcx)','jne .B12',
        'movq %rdx, %rsi','movq %r14, -24(%rbp)','movzbl 17(%rbx), %ecx',
        'movq %rbx, -16(%rbp)','callq *8(%rbx)','nop','testb %al, %al',
        'movq -16(%rbp), %rbx','movq -24(%rbp), %r14','je .B12',
        'movzbl 17(%rbx), %edi','movq %r14, %rcx','callq '+n['wipe'],
        'xorl $1, %edi','leaq 2(,%rdi,2), %r8','movq %r14, %rcx','movq %rsi, %rdx',
        'callq '+n['pack'],'cmpb $0, 17(%rbx)','je .B5','xorl %esi, %esi','jmp .B13',
        '.B5:','movq %r14, %rcx','callq '+n['wrapper'],'cmpb $1, 16(%rbx)',
        'jne .B12','movzbl 17(%rbx), %ecx','callq *8(%rbx)','nop','testb %al, %al',
        'movq -16(%rbp), %rbx','movq -24(%rbp), %r14','je .B12',
        'movq (%rbx), %rdi','cmpq $-1, %rdi','je .B9','incq %rdi',
        'movzbl 17(%rbx), %eax','xorl $1, %eax','leaq 2(,%rax,2), %r8',
        'movq %rsi, %rcx','movq %r14, %rdx','callq '+n['unpack'],
        'movq %rdi, (%rbx)','movq %r14, %rcx','callq '+n['wipe'],
        'movb $-1, %sil','jmp .B11','.B12:','movb $0, 16(%rbx)','movb $2, %sil',
        '.B13:','movq %r14, %rcx','callq '+n['wipe'],'movb $0, 16(%rbx)',
        '.B11:','movl %esi, %eax','addq $64, %rsp','popq %rbx','popq %rdi',
        'popq %rsi','popq %r14','popq %rbp','retq','.B9:','movb $3, %sil','jmp .B13']


def handlers(bodies,n):
    result={}
    for number in (14,15,16):
        name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@\?0\?'+re.escape(n['session'])+r'@')
        expected=[f'.B{number}:','movq %rdx, 16(%rsp)',
            *['pushq %'+r for r in ('rbp','r14','rsi','rdi','rbx')],
            'subq $32, %rsp','leaq 64(%rdx), %rbp']
        if number==15:expected+=['movq -24(%rbp), %rcx','callq '+n['wipe']]
        expected+=['movq -16(%rbp), %rax','movb $0, 16(%rax)','addq $32, %rsp',
            *['popq %'+r for r in ('rbx','rdi','rsi','r14','rbp')],'retq']
        s.require(life.code(bodies[name])==expected,'complete Keccak session cleanup funclet')
        result[number]=name
    return result


def tables(assembly,body,n,h):
    # Table entries refer to actual call-site labels, not just named handlers.
    s.sequences(body,['.Ltmp18:|movq %rbx, -16(%rbp)|callq *8(%rbx)|nop|.Ltmp19:',
                      '.Ltmp20:|callq *8(%rbx)|nop|.Ltmp21:'])
    prefix={p:p+n['session'] for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    expected={
        prefix['$cppxdata$']:['429065506','3',prefix['$stateUnwindMap$']+'@IMGREL','0','0','4',
                            prefix['$ip2state$']+'@IMGREL','56','0','1'],
        prefix['$stateUnwindMap$']:['-1','"'+h[15]+'"@IMGREL','0','"'+h[16]+'"@IMGREL',
                                   '0','"'+h[14]+'"@IMGREL'],
        prefix['$ip2state$']:['.Lfunc_begin22@IMGREL','-1','.Ltmp18@IMGREL','2',
                            '.Ltmp20@IMGREL','1','.Ltmp21@IMGREL','-1']}
    for label,want in expected.items():
        found=list(re.finditer(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M))
        s.require(len(found)==1,'unique Keccak session cleanup table')
        actual=[l.strip().split(None,1)[1] for l in found[0][1].splitlines()]
        s.require(actual==want,'exact Keccak session cleanup state/order table')
    return dict(expected_tables=expected,callback_unwind_chains=[[h[14],h[15]],[h[16],h[15]]],
        first_quarantine_then_wipe_and_quarantine=True,frame_state_offset=56,
        parent_frame_adjustment=64,os_dispatcher_qualified=False)


def normal_paths(lines,n):
    """Conservative CFG walk: both outcomes of each branch, no crypto emulation.

    Check actual event ordering on every normal path, independently of exact
    instruction equality. Callee semantics/arguments are separate contracts.
    """
    labels={line[:-1]:i for i,line in enumerate(lines) if line.endswith(':')}
    events={'callq '+n[k]:k for k in ('wipe','pack','wrapper','unpack')}
    events.update({'callq *8(%rbx)':'revalidate','incq %rdi':'counter_increment',
        'movq %rdi, (%rbx)':'counter_commit','movb $0, 16(%rbx)':'quarantine',
        'movb $-1, %sil':'success','movb $2, %sil':'revoked',
        'movb $3, %sil':'overflow','xorl %esi, %esi':'wrong_architecture'})
    pending=[(0,(),())];out=[]
    while pending:
        at,trace,seen=pending.pop()
        s.require(0<=at<len(lines) and at not in seen,'bounded acyclic session CFG')
        line=lines[at];seen=seen+(at,)
        if line in events:trace=trace+(events[line],)
        if line=='retq':
            s.require(trace and trace.count('wipe')>=1,'session return requires scratch wipe')
            if 'success' in trace:
                s.require(trace==('revalidate','wipe','pack','wrapper','revalidate',
                    'counter_increment','unpack','counter_commit','wipe','success'),
                    'successful session exact effect order')
            else:
                s.require('unpack' not in trace and 'counter_commit' not in trace,
                          'rejected session cannot write caller output or commit counter')
                s.require(trace[-2:]==('wipe','quarantine'),'every rejected session wipes then quarantines')
            out.append(trace);continue
        if line.startswith(('je ','jne ','jmp ')):
            target=line.split()[1];s.require(target in labels,'session local branch target')
            pending.append((labels[target],trace,seen))
            if line.startswith('jmp '):continue
        pending.append((at+1,trace,seen))
    s.require(len(out)==7,'all seven normal session paths')
    return [list(v) for v in out]


def abis(ir,n):
    target='"target-cpu"="x86-64" "target-features"="'+zero.SIMD_FEATURES+'"'
    arguments={
        'wipe':'ptr noalias nofree noundef nonnull dereferenceable(1920) %0',
        'zero':'ptr noalias nofree noundef nonnull %0, i64 noundef range(i64 1, -9223372036854775808) %1',
        'session':'ptr nonnull captures(none) %.0.val, ptr noalias nofree noundef nonnull dereferenceable(800) %0, ptr noalias nofree noundef nonnull dereferenceable(1920) %1'}
    for role,name in n.items():
        if role not in arguments:continue
        result='noundef range(i8 -1, 4) i8' if role=='session' else 'void'
        attrs='uwtable' if role=='session' else 'nofree noinline norecurse nounwind uwtable'
        tail=' personality ptr @__CxxFrameHandler3' if role=='session' else ''
        expected=f'define internal fastcc {result} @{name}({arguments[role]}) unnamed_addr '+(
            '{ '+attrs+' '+target+' }')+tail+' {'
        s.require(life.reuse.abi(ir,name)==expected,'exact Keccak session/wipe ABI '+role)


def inspect(bodies,assembly,ir,leaves):
    n=names(bodies);n['zero']=life.ZERO
    for role in ('pack','unpack','wrapper'):
        s.require(leaves['functions'][role]==n[role],'session uses reviewed SIMD leaf '+role)
    for key,want in [('lanes',4),('state_region',[0,800]),('erased_scratch_region',[800,1920]),
                     ('transpose_llvm_width_range',[2,5]),('linked_constants_independently_derived',True)]:
        s.require(leaves[key]==want,'required SIMD leaf contract '+key)
    zeroizer=zero.zeroizer(bodies)
    s.require(life.code(bodies[n['wipe']])==wipe_shape(),'complete 1920-byte scratch wipe')
    code=life.code(bodies[n['session']])
    s.require(code==session_shape(n),'complete Keccak session body')
    abis(ir,n);h=handlers(bodies,n)
    cleanup=tables(assembly,bodies[n['session']],n,h)
    return dict(functions=n,normal_path_events=normal_paths(code,n),cleanup=cleanup,
        invoked_funclets=h,zeroizer=zeroizer,
        authority_fields=dict(counter=0,revalidator=8,healthy=16,kernel=17),
        authority_frame_slot=-16,scratch_frame_slot=-24,caller_states_preserved_in='rsi',
        full_scratch_wipe_ranges=[[0,800],[800,960],[960,1120],[1120,1920]],
        caller_output_after_revalidation_and_checked_counter=True,
        success_error_and_callback_unwind_scratch_clearing_composed=True,
        callback_cannot_mutate_kernel_or_invalidate_storage_required=True,
        callback_abi_and_nonvolatile_preservation_required=True,
        caller_authority_and_allocation_lifetimes_qualified=False,
        arbitrary_os_unwind_qualified=False,private_frame_erasure_qualified=False)
