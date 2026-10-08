"""Exact sequential SHA-3 owner transitions, not whole-worker qualification.

Expected instruction lists are assembled from reviewed layouts/control flow,
never learned from the candidate body. Callee destruction, caller allocation
lifetimes, funclets and private-frame erasure require separate composition.
"""
import windows_enclave_kmac_reuse as reuse

s=reuse.shapes
ZERO='_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_volatile23zeroize_region_volatile'
LAYOUT={
    'scalar':dict(state=16,plan=1152,output=1344,sequence=2368,budget=2376,
                  phase=2384,completed=2385,active=0,size=2400,align=16),
    'avx2':dict(state=1216,plan=1024,output=0,sequence=2208,budget=2216,
                phase=2249,completed=2248,active=2232,size=2272,align=32),
}
DROP={
    'scalar':'_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCseaU6QMlAGlg_10sha3_batch5state5StateEBF_',
    'avx2':'_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCscBEH4D3OuJh_22sha3_accelerated_state5StateECs68G716Ptymm_22sha3_batch_accelerated',
}


def code(body):
    return [l for l in s.lines(body)[1:] if not l.startswith('.') or l.startswith('.B')]


def mem(offset,reg):
    return (str(offset) if offset else '')+'(%'+reg+')'


def frame(size,two=False,end=False):
    registers=['rsi','rdi'] if two else ['rsi']
    if end:return [f'addq ${size}, %rsp']+[f'popq %{r}' for r in reversed(registers)]+['retq']
    return [f'pushq %{r}' for r in registers]+[f'subq ${size}, %rsp']


def clear_tail(lane,reg='rsi',seal=False):
    """Destroy then clear output/logical fields; NOT slot padding/state copies."""
    a=LAYOUT[lane];v='v' if lane=='avx2' else ''
    if lane=='scalar':
        lines=[f'movb $0, 16(%{reg})',f'leaq 1344(%{reg}), %rcx','movl $1024, %edx']
    else:lines=[f'movq $2, 2160(%{reg})','movl $1024, %edx',f'movq %{reg}, %rcx']
    lines+=['callq '+ZERO]
    if seal and lane=='scalar':lines+=['movb $2, %al']
    lines += [f'movq $0, {mem(a["active"],reg)}',f'movb $0, {mem(a["completed"],reg)}',
              f'movq $0, {mem(a["budget"],reg)}',
              'vxorps %xmm0, %xmm0, %xmm0' if v else 'xorps %xmm0, %xmm0']
    for slot in range(8):
        base,offset=('rdi',0) if seal and slot==0 else (reg,a['plan']+24*slot)
        lines += [f'{v}mov'+('aps' if slot%2==0 else 'ups')+f' %xmm0, {mem(offset,base)}',
                  f'movb $0, {mem(offset+16,base)}']
    return lines


def clear(lane,reg='rsi',seal=False):
    return [f'leaq {mem(LAYOUT[lane]["state"],reg)}, %rcx','callq '+DROP[lane]]+clear_tail(lane,reg,seal)


def quarantine(lane,reg='rsi',label=3):
    lines=[]
    if lane=='avx2':
        lines=[f'movq 2224(%{reg}), %rax','cmpb $2, 8(%rax)',f'je .B{label}',
               'movb $2, 8(%rax)','movq $3, (%rax)',f'.B{label}:']
    return lines+[f'movb $5, {mem(LAYOUT[lane]["phase"],reg)}']


def operation(lane):
    a=LAYOUT[lane];scalar=lane=='scalar';owner,result=('rdi','rsi') if scalar else ('rsi','rdi')
    lines=frame(40,True)+[f'movq %rdx, %{owner}',f'movq %rcx, %{result}',
        f'cmpb %r9b, {a["phase"]}(%rdx)',f'jne .B{6 if scalar else 7}',
        f'movq {mem(a["sequence"],owner)}, %rax','incq %rax','setne %cl',
        'cmpq %r8, %rax','sete %al','testb %al, %cl','jne .B2']
    for error,label in ((1,12),(2,9)):
        if error==2:lines += [f'.B{6 if scalar else 7}:']
        lines+=clear(lane,owner)+quarantine(lane,owner,label)+[f'movb ${error}, (%{result})']
        if scalar:
            if error==1:lines+=['jmp .B4']
        else:lines+=['movb $2, 8(%rdi)','jmp .B14']
    if scalar:
        lines+=['.B4:','movb $2, %al','jmp .B5','.B2:',
                'movq %r8, 2368(%rdi)','movq %rdi, (%rsi)','xorl %eax, %eax',
                '.B5:','movb %al, 8(%rsi)']
    else:
        lines+=['.B2:','movq 2224(%rsi), %rax','cmpb $4, 9(%rax)','jne .B4',
                'cmpb $1, 8(%rax)','jne .B4','movq %r8, 2208(%rsi)',
                'movq %rsi, (%rdi)','movb $0, 8(%rdi)','jmp .B14','.B4:',
                'movb $6, (%rdi)','movb $2, 8(%rdi)']
        lines+=clear(lane)+quarantine(lane,label=6)+['.B14:']
    return lines+frame(40,True,True)


def guard(lane):
    end=2 if lane=='scalar' else 4
    lines=frame(32)+['testb $1, %dl',f'jne .B{end}']
    if lane=='scalar':lines+=['leaq 16(%rcx), %rax','movq %rcx, %rsi','movq %rax, %rcx']
    else:lines+=['movq %rcx, %rsi','addq $1216, %rcx']
    return lines+['callq '+DROP[lane]]+clear_tail(lane)+quarantine(lane)+[f'.B{end}:']+frame(32,end=True)


def cancel(lane,op):
    a=LAYOUT[lane];success,end=(4,5) if lane=='scalar' else (6,7)
    lines=frame(48)+['movq %rcx, %rsi',f'movzbl {a["phase"]}(%rcx), %r9d',
        'leal -1(%r9), %eax','cmpb $4, %al','jae .B1','movq %rdx, %r8',
        'leaq 32(%rsp), %rcx','movq %rsi, %rdx','callq '+op,'cmpb $2, 40(%rsp)',
        f'jne .B{success}','movzbl 32(%rsp), %eax',f'jmp .B{end}','.B1:']
    lines+=clear(lane)+quarantine(lane)+['movb $2, %al',f'jmp .B{end}',f'.B{success}:',
                                       'movq 32(%rsp), %rsi']
    return lines+clear(lane)+[f'movb $0, {a["phase"]}(%rsi)','movb $-1, %al',
                             f'.B{end}:']+frame(48,end=True)


def seal(lane,op):
    a=LAYOUT[lane];success,end=(12,13) if lane=='scalar' else (14,15)
    lines=frame(56,True)+['movq %rdx, %r8','movq %rcx, %rdx','leaq 40(%rsp), %rcx',
        'movb $1, %r9b','callq '+op,'movzbl 48(%rsp), %ecx','cmpb $2, %cl','jne .B2',
        'movzbl 40(%rsp), %eax',f'jmp .B{end}','.B2:','movq 40(%rsp), %rsi',
        f'cmpq $0, {a["plan"]}(%rsi)',f'movzbl {a["completed"]}(%rsi), %eax',
        'sete %dl','orb %al, %dl','testb $1, %dl','je .B10']
    for slot in range(1,7):
        lines += [f'cmpq $0, {a["plan"]+24*slot}(%rsi)','setne %dl',f'testb ${1<<slot}, %al',
                  'sete %r8b','testb %r8b, %dl','jne .B10']
    lines += [f'cmpq $0, {a["plan"]+168}(%rsi)','setne %dl','testb %al, %al',
        'setns %al','andb %dl, %al','cmpb $1, %al',f'jne .B{success}',
        '.B10:','movb $2, %al','testb $1, %cl',f'jne .B{end}',f'leaq {a["plan"]}(%rsi), %rdi']
    lines+=clear(lane,seal=True)+quarantine(lane,label=13)
    if lane=='avx2':lines+=['movb $2, %al']
    return lines+[f'.B{end}:']+frame(56,True,True)+[f'.B{success}:',
        f'movb $4, {a["phase"]}(%rsi)','movb $-1, %al',f'jmp .B{end}']


def contracts(bodies,lane):
    s.require(lane in LAYOUT,'sequential batch lifecycle lane')
    names={kind:s.one(bodies,'Owner'+suffix+'$') for kind,suffix in
           [('operation','9operation'),('clear','5clear'),('cancel','6cancel'),('seal','4seal')]}
    names['guard']=s.one(bodies,r'9Operation.*4drop$')
    expected=dict(operation=operation(lane),guard=guard(lane),
        clear=frame(32)+['movq %rcx, %rsi',f'addq ${LAYOUT[lane]["state"]}, %rcx',
              'callq '+DROP[lane]]+clear_tail(lane)+frame(32,end=True),
        cancel=cancel(lane,names['operation']),seal=seal(lane,names['operation']))
    return names,expected


def inspect(bodies,ir,lane):
    names,expected=contracts(bodies,lane);a=LAYOUT[lane]
    owner=f'ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({a["size"]})'
    for kind,name in names.items():
        s.require(code(bodies[name])==expected[kind],'complete sequential SHA-3 '+lane+' '+kind+' lifecycle')
        abi=reuse.abi(ir,name)
        if kind=='guard':
            s.require('(ptr nonnull %.0.val, i8 range(i8 0, 2) %.8.val)' in abi,'live owner and Boolean completion guard ABI')
        else:
            s.require(owner+(' %1' if kind=='operation' else ' %0') in abi,'full exclusive live batch owner ABI')
        if kind=='operation':
            output='ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none) dereferenceable(16)'
            if lane=='scalar':output+=' initializes((0, 1), (8, 9))'
            s.require('('+output+' %0, '+owner+' %1, i64 noundef %2, i8 noundef range(i8 0, 6) %3)' in abi,
                      'disjoint operation result, sequence and valid phase ABI')
        if kind in ('seal','cancel'):
            s.require('noundef range(i8 -1, 7) i8 @' in abi and owner+' %0, i64 noundef %1)' in abi,
                      'complete status and sequence ABI')
    return dict(functions=names,instructions_and_labels_checked=sum(map(len,expected.values())),
        owner_layout=a,checked_next_sequence=True,phase_match_before_admission=True,
        authority_check_before_sequence_commit=lane=='avx2',
        unfinished_guard_clears_and_quarantines=True,cancel_phases=[1,2,3,4],
        seal_requires_all_active_slots_complete=True,output_clear_bytes=1024,
        logical_plan_fields_reset=True,plan_padding_erased=False,
        state_destructor=DROP[lane],state_destructor_composition_qualified=False,
        caller_storage_lifetimes_qualified=False,unwind_paths_qualified=False,
        complete_private_frame_erasure_qualified=False)
