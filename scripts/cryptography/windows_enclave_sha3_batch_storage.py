"""Sequential batch state destruction and admitted plan placement contracts.

Typed field cleanup and disjoint owner subobjects are checked here. These
contracts do not establish caller stack residency or erase moved copies and
padding; those remain final private-frame/window composition obligations.
"""
import re
import windows_enclave_sha3_batch_lifecycle as life
import windows_enclave_sha3_batch_plan as plan

s=life.s
SCALAR_WIPE='_RNvMNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened5ownerINtB2_20HardenedFips202OwnerKj48_E4wipeB6_'
MEMORY_WIPE='_RNvMNtCscBEH4D3OuJh_22sha3_accelerated_state6engineNtB2_6Memory4wipe'
SCRATCH_WIPE='_RNvMNtNtCshYLbG8W7MpL_17brynja_crypto_cpu18hardened_execution14keccak_scratchNtB2_13KeccakScratch4wipe'
PRIOR_DROP={
    'scalar':'_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCsgp9hxIs16B4_11sha3_stream17sha3_stream_state5StateEBF_',
    'avx2':'_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCscBEH4D3OuJh_22sha3_accelerated_state5StateECsav2wNVSWsYU_25sha3_accelerated_resident',
}
STATE_BYTES={'scalar':1136,'avx2':992}
TARGETS=[7,8,8,8,8,10,10,2]


def rebind(lane,functions,prior,ir,prior_ir):
    now,old=life.DROP[lane],PRIOR_DROP[lane]
    s.require(now in functions and old in prior,'enumerated current and prior state destructors')
    s.require(functions[now]==prior[old],'state destructor complete code/references/extent identity')
    expected=life.reuse.abi(prior_ir,old).replace('@'+old+'(','@'+now+'(')
    s.require(life.reuse.abi(ir,now)==expected,'state destructor exact renamed LLVM ABI')
    return dict(function=now,prior_function=old,exact_code_references_extent_and_renamed_abi=True)


def scalar_drop():
    lines=['pushq %rsi','pushq %rdi','pushq %rbx','subq $32, %rsp',
        'movzbl (%rcx), %eax','cmpq $7, %rax','ja .B2','leaq TABLE(%rip), %rdx',
        'movslq (%rdx,%rax,4), %rax','addq %rdx, %rax','jmpq *%rax',
        '.B8:','incq %rcx','jmp .B9','.B10:','addq $2, %rcx','jmp .B9',
        '.B2:','leaq 16(%rcx), %rdi','cmpb $1, 83(%rcx)','jne .B5',
        'leaq 84(%rcx), %rsi','movq %rcx, %rbx','movq %rsi, %rcx','callq '+SCALAR_WIPE,
        'movq %rbx, %rcx','cmpb $0, 83(%rbx)','je .B5','movq %rsi, %rcx',
        'callq '+SCALAR_WIPE,'movq %rbx, %rcx','.B5:','movb $0, 83(%rcx)',
        'leaq 80(%rcx), %rax','movl $1, %edx','movq %rcx, %rsi','movq %rax, %rcx',
        'callq '+life.ZERO,'movw $768, 81(%rsi)','movb $0, 1124(%rsi)','xorps %xmm0, %xmm0']
    lines += [f'movaps %xmm0, {life.mem(n,"rdi")}' for n in (48,32,16,0)]
    lines += ['cmpb $0, 83(%rsi)','je .B7','movq %rsi, %rcx','addq $84, %rcx','.B9:']
    epilogue=['addq $32, %rsp','popq %rbx','popq %rdi','popq %rsi']
    return lines+epilogue+['jmp '+SCALAR_WIPE,'.B7:']+epilogue+['retq']


def prefix_clear():
    return ['leaq 936(%rsi), %rcx','movl $1, %edx','callq '+life.ZERO,
        'movb $0, 937(%rsi)','vxorps %xmm0, %xmm0, %xmm0',
        'vmovaps %ymm0, 864(%rsi)','vmovaps %ymm0, 896(%rsi)']


def avx2_drop():
    return life.frame(40,True)+['cmpl $2, 944(%rcx)','je .B5','movq %rcx, %rsi',
        'movb $1, 859(%rcx)','movq $0, 616(%rcx)','leaq 624(%rcx), %rdi',
        'movq %rdi, %rcx','callq '+MEMORY_WIPE,'cmpb $-1, 938(%rsi)','je .B3']+prefix_clear()+[
        '.B3:','movb $-1, 938(%rsi)','movb $3, 962(%rsi)','movq %rdi, %rcx',
        'vzeroupper','callq '+MEMORY_WIPE,'movq %rsi, %rcx','callq '+SCRATCH_WIPE,
        'cmpb $-1, 938(%rsi)','je .B5']+prefix_clear()+['.B5:']+life.frame(40,True,True)[:-1]+['vzeroupper','retq']


def begin(lane,operation,validate):
    scalar=lane=='scalar';a=life.LAYOUT[lane]
    owner,plan,budget=('rbx','rdi','rsi') if scalar else ('rsi','rbx','rdi')
    success,end=(5,6) if scalar else (7,8)
    lines=['pushq %rsi','pushq %rdi','pushq %rbp','pushq %rbx','subq $56, %rsp',
        f'movq %r9, %{budget}',f'movq %r8, %{plan}','movq %rdx, %r8','movq %rcx, %rdx',
        'leaq 40(%rsp), %rcx','xorl %r9d, %r9d','callq '+operation,
        'movzbl 48(%rsp), %ebp','cmpb $2, %bpl','jne .B2','movzbl 40(%rsp), %eax',
        f'jmp .B{end}','.B2:',f'movq 40(%rsp), %{owner}',f'movq %{plan}, %rcx',
        'callq '+validate,'cmpb $-1, %al',f'je .B{success}','testb $1, %bpl',f'jne .B{end}']
    if scalar:
        lines+=['leaq 16(%rbx), %rcx','movl %eax, %esi','callq '+life.DROP[lane]]
        tail=life.clear_tail(lane,owner);at=tail.index('callq '+life.ZERO)+1
        lines+=tail[:at]+['movl %esi, %eax']+tail[at:]+life.quarantine(lane,owner)
    else:
        lines+=['movl %eax, %ebx']+life.clear(lane)+life.quarantine(lane,label=6)+['movl %ebx, %eax']
    lines += [f'jmp .B{end}',f'.B{success}:']
    if scalar:
        lines+=['leaq 1152(%rbx), %rcx','movl $192, %r8d','movq %rdi, %rdx','callq memcpy']
    else:
        for at in (160,128):
            lines += [f'vmovups {at}(%rbx), %ymm0',f'vmovups %ymm0, {1024+at}(%rsi)']
        lines += [f'vmovups {life.mem(32*i,"rbx")}, %ymm{i}' for i in range(4)]
        lines += [f'vmovups %ymm{i}, {1024+32*i}(%rsi)' for i in range(3,-1,-1)]
    lines += [f'movq %{budget}, {life.mem(a["budget"],owner)}',
        f'movb $1, {life.mem(a["phase"],owner)}','movb $-1, %al',f'.B{end}:',
        'addq $56, %rsp','popq %rbx','popq %rbp','popq %rdi','popq %rsi']
    return lines+(['vzeroupper'] if not scalar else [])+['retq']


def destructor(bodies,asm,ir,lane,exact):
    name=life.DROP[lane];actual=life.code(bodies[name]);a=life.LAYOUT[lane]
    children={life.ZERO,SCALAR_WIPE} if lane=='scalar' else {life.ZERO,MEMORY_WIPE,SCRATCH_WIPE}
    s.require(children<=set(exact),'every destructor wipe callee has reproduced exact helper review')
    table=None
    if lane=='scalar':
        found=re.findall(r'leaq (\.LJTI\d+_0)\(%rip\), %rdx','\n'.join(actual))
        s.require(len(found)==1,'one scalar destructor dispatch operand');table=found[0]
        actual=[l.replace(table,'TABLE') for l in actual]
        definitions=re.findall(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',asm,re.M)
        s.require(len(definitions)==1,'one complete scalar destructor dispatch table')
        number=table.split('_')[0].removeprefix('.LJTI')
        values=[re.sub(r'\s+','',l) for l in definitions[0].splitlines()]
        s.require(values==[f'.long.LBB{number}_{v}-{table}' for v in TARGETS],
                  'empty/fixed/XOF/setup state destructor dispatch')
    expected=scalar_drop() if lane=='scalar' else avx2_drop()
    s.require(actual==expected,'complete typed state destructor control flow and clearing operands')
    abi=life.reuse.abi(ir,name)
    s.require(f'(ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({STATE_BYTES[lane]}) %0)' in abi,
              'full exclusive aligned state destructor allocation')
    return dict(function=name,state_bytes=STATE_BYTES[lane],dispatch_table=table,
        instructions_and_labels_checked=len(expected),reviewed_wipe_callees=sorted(children),
        typed_payload_cleanup_composed=True,entire_state_allocation_erased=False)


def inspect(bodies,asm,ir,lane,prior):
    s.require(lane in life.LAYOUT,'sequential storage lane')
    s.require(prior['prior_semantics_replayed'],'previous state/helper semantics must replay')
    s.require(prior['state_destructor_rebinding']['function']==life.DROP[lane] and
              prior['state_destructor_rebinding']['exact_code_references_extent_and_renamed_abi'],
              'explicit state destructor rebinding required')
    drop=destructor(bodies,asm,ir,lane,prior['exact_body_reference_extent_and_abi'])
    # Compose only callers whose COMPLETE bodies are checked, not every caller by name.
    transitions=life.inspect(bodies,ir,lane)
    admission=plan.inspect(bodies,asm,ir)
    a=life.LAYOUT[lane];name=s.one(bodies,r'Owner5begin$');validate=s.one(bodies,r'Owner13validate_plan$')
    expected=begin(lane,transitions['functions']['operation'],validate)
    s.require(admission['function']==validate,'begin calls the reproduced complete plan validator')
    s.require(life.code(bodies[name])==expected,'complete batch begin admission/copy/failure cleanup')
    abi=life.reuse.abi(ir,name)
    args=(f'(ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({a["size"]}) %0, '
          'i64 noundef %1, ptr dead_on_return noalias nofree noundef nonnull readonly align 8 '
          'captures(none) dereferenceable(192) %2, i64 noundef %3)')
    s.require(args in abi and 'noundef range(i8 -1, 7) i8 @' in abi,'disjoint full plan/owner and begin status ABI')
    spans={'state':[a['state'],a['state']+STATE_BYTES[lane]],'plan':[a['plan'],a['plan']+192],
           'output':[a['output'],a['output']+1024],'sequence':[a['sequence'],a['sequence']+8],
           'budget':[a['budget'],a['budget']+8]}
    values=sorted(spans.values())
    s.require(all(0<=start<end<=a['size'] for start,end in values) and
              all(left[1]<=right[0] for left,right in zip(values,values[1:])),
              'disjoint bounded state/plan/output/sequence/budget subobjects')
    return dict(state_destructor=drop,composed_lifecycle_methods=transitions['functions'],
        begin=dict(function=name,instructions_and_labels_checked=len(expected),plan_bytes=192,
            complete_validation_before_copy=True,copy_precedes_collecting_phase=True,
            source_destination_disjoint_by_abi=True,shared_memcpy_implementation_package=8),
        owner_subobjects=spans,state_pointer_inside_owner=True,
        state_subobject_validity_conditional_on_live_owner=True,
        retained_owner_lifetime_qualified=False,all_batch_callers_composed=False,
        private_frame_padding_and_moved_copy_erasure_qualified=False,unwind_paths_qualified=False)
