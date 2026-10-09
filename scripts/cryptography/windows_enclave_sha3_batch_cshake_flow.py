"""Scalar constructor prefix-call lifetimes and normal failure cleanup joins."""
import windows_enclave_sha3_batch_cshake_init as init
import windows_enclave_sha3_batch_storage as storage

life,s,L=init.life,init.s,init.L
WIPE=storage.SCALAR_WIPE


def parts(rate):
    wide=rate==136
    entry,loop,bulk,advance,bitfail,absent,clean,reset,error,success=(
        (48,51,59,62,69,71,72,75,77,43) if wide else (53,56,64,67,70,78,80,83,85,45))
    begin=L(f'''.B{entry}:|movq $0, 1688(%rsp)|movq $2, 1680(%rsp)
        movzbl 1745(%rsp), %esi|movq %r14, %rcx|movq %rdi, %rdx''')
    begin+=L('movq %rbp, %r8' if wide else 'movq 7296(%rsp), %r8')
    begin+=L(f'''callq {init.ENCODE}|movzwl 1646(%rsp), %eax|xorl %edi, %edi
        cmpl $257, %eax|movl $1, %ebx|cmovbq %r14, %rbx|cmovbl %eax, %edi
        testb %sil, %sil|je .B{bulk}|testw %di, %di''')
    if not wide:begin+=['movzbl 35(%rsp), %r12d']
    begin+=L(f'je .B{advance}|leaq 1680(%rsp), %r14')
    bit=L(f'''.B{loop}:|movq %r14, %rcx|movq %rbx, %rdx|movb $8, %r8b
        callq {init.setup.name('bits',rate)}|cmpb $-1, %al|jne .B{bitfail}
        incq %rbx|decq %rdi|jne .B{loop}|jmp .B{advance}''')
    bulk_part=L(f'''.B{bulk}:|cmpb $0, 1747(%rsp)|je .B{absent}
        movq %r15, %rcx|movq %rbx, %rdx|movq %rdi, %r8
        callq {init.UPDATE}{rate:x}_E6updateB6_|movb $1, %bpl|testb %al, %al''')
    if not wide:bulk_part+=['movzbl 35(%rsp), %r12d']
    bulk_part+=L(f'''jne .B{clean}|addl $2, %edi|movzwl %di, %eax
        movq %rax, 1680(%rsp)|movq $0, 1688(%rsp)''')
    advance_part=L(f'''.B{advance}:|leaq 1680(%rsp), %rcx
        callq {init.setup.name('advance',rate)}|movl %eax, %ebp|cmpb $-1, %al|jne .B{clean}
        movzbl 2788(%rsp), %esi|movzbl 1680(%rsp), %ebp
        leaq 1681(%rsp), %rdx|leaq 6061(%rsp), %rcx|movl $1107, %r8d|callq memcpy
        movq 2789(%rsp), %rax|movq %rax, 128(%rsp)
        movl 2796(%rsp), %eax|movl %eax, 135(%rsp)|cmpb $2, %sil
        jne .B{success}|jmp .B{error}''')
    cleanup=L(f'''.B{clean}:|leaq 1744(%rsp), %rsi|cmpb $1, 1747(%rsp)|jne .B{reset}
        movq %r15, %rcx|callq {WIPE}|cmpb $0, 1747(%rsp)|je .B{reset}
        movq %r15, %rcx|callq {WIPE}''')
    clear=L(f'''.B{reset}:|movb $0, 1747(%rsp)|movl $1, %edx|movq %rsi, %rcx
        callq {life.ZERO}|movw $768, 1745(%rsp)|movb $0, 2788(%rsp)|xorps %xmm0, %xmm0''')
    clear += [f'movaps %xmm0, {at}(%rsp)' for at in (1680,1696,1712,1728)]
    clear+=L(f'cmpb $0, 1747(%rsp)|je .B{error}|movq %r15, %rcx|callq {WIPE}')
    fail=L(f'.B{error}:|movb %bpl, {4528 if wide else 3408}(%rsp)|movb $2, {5636 if wide else 4516}(%rsp)')
    if not wide:fail+=['jmp .B86']
    bit_error=L(f'.B{bitfail}:|movl %eax, %ebp')+(['jmp .B72'] if wide else [])
    missing=L(f'.B{absent}:|xorl %ebp, %ebp')+([] if wide else ['jmp .B79'])
    return [begin,bit,bulk_part,advance_part,cleanup,clear,fail,bit_error,missing]


def check_shapes(bodies,assembly):
    name,initial=init.check_shapes(bodies,assembly);lines=life.code(bodies[name]);covered=set()
    expected=parts(136)+parts(168)+[L('.B79:|movzbl 35(%rsp), %r12d|jmp .B80'),
        L('.B86:|movb $6, %al|leaq 1152(%r13), %rbp')]
    for part in expected:
        at=lines.index(part[0]);end=next((i for i in range(at+1,len(lines)) if lines[i].endswith(':')),len(lines))
        s.require(lines[at:end]==part,'complete cSHAKE prefix/failure block')
        covered.update(range(at,end))
    pred=init.empty.predecessors(lines)
    for at in covered:
        s.require(pred[at]<=covered|set(initial),'prefix/error paths entered only from checked initialization or checked paths')
    for before,after in ((48,51),(53,56),(59,62),(64,67),(70,80),(71,72),(77,86),(86,87)):
        at=lines.index(f'.B{before}:')
        end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[end]==f'.B{after}:','actual prefix/error fallthrough edge')
    return name,sorted(covered)


def geometry(ir,prior):
    helpers={init.ENCODE,WIPE,life.ZERO}
    for rate in (136,168):
        helpers.update((init.UPDATE+f'{rate:x}_E6updateB6_',init.setup.name('bits',rate),init.setup.name('advance',rate)))
    s.require(prior['prior_semantics_replayed'] and helpers<=set(prior['exact_body_reference_extent_and_abi']),
              'prefix helpers and wipe bodies require fresh exact replay')
    for helper,width in [(init.ENCODE,258),(WIPE,1040)]+[
        (init.UPDATE+f'{r:x}_E6updateB6_',1040) for r in (136,168)]+[
        (init.setup.name(kind,r),1120) for kind in ('bits','advance') for r in (136,168)]:
        abi=life.reuse.abi(ir,helper)
        s.require('dereferenceable('+str(width)+')' in abi and 'noalias' in abi and 'nounwind' in abi,
                  'exclusive full-size nonunwinding prefix helper ABI')
    abi=life.reuse.abi(ir,init.ENCODE)
    s.require('initializes((0, 258))' in abi and 'writeonly' in abi,'complete encoding output initialization')
    # The borrowed sponge excludes setup.pending/used/phase/Option and customized.
    s.require(1390+258<=1680 and 1748+1040==2788 and 6061+1107==7168,
              'encoding/setup/snapshot disjoint within locals, below saved XMM6')
    return dict(encoding=[1390,1648],setup=[1680,2800],sponge=[1748,2788],
        pending=1744,used=1745,phase=1746,optional_owner=1747,customized=2788,
        active_snapshot=[6061,7168],padding_source=[2789,2800],padding_snapshot=[128,139],
        used_preserved_by_sponge_updates=True,bit_loop_unreachable_from_initialized_used_zero=True,
        padding_initialized=False,shared_memcpy_runtime_pending=True)


def prefix_path(rate,name,custom,fail=None):
    """Normal-path state and failure injection; complete advance uses exact helper contract.

    This describes public encoded lengths, not hashing arbitrary input secrets.
    """
    s.require(fail in (None,'rate_update','name_update','advance'),'known helper failure site')
    state=init.counts(rate,name,custom)
    if state is None:return dict(result=6,initialized=False,published=False,local_wipes=0,calls=[])
    if not state['customized']:
        return dict(result=-1,initialized=True,published=False,local_wipes=0,calls=[],emitted=0,phase=2,used=0)
    width=max(1,(name.bit_length()+7)//8)
    encoded=[width,*name.to_bytes(width,'big')]
    calls=[('rate_update',1390,2)];emitted=0
    if fail!='rate_update':
        emitted=2;calls.append(('name_update',1390,len(encoded)))
        if fail!='name_update':emitted+=len(encoded);calls.append(('advance',1680,1120))
    if fail is not None:
        return dict(result=6,initialized=True,published=False,local_wipes=2,
            pending_clear=True,metadata_zero=True,optional_owner=0,phase=3,customized=False,
            emitted=0,used=0,calls=calls,private_frame_erased=False)
    if name==0:
        # Advance consumes left_encode(custom), switches to Custom, and stops
        # for positive custom length. Both zero lengths bypass this path.
        emitted+=max(1,(custom.bit_length()+7)//8)+1
    return dict(result=-1,initialized=True,published=False,local_wipes=0,calls=calls,
        emitted=emitted,phase=0 if name else 1,used=0,encoded_name=encoded,
        remaining=name if name else custom,first_prefix_bytes=[1,rate])


def inspect(bodies,assembly,ir,prior,construction,initialized):
    name,positions=check_shapes(bodies,assembly)
    s.require(initialized['function']==name and initialized['cshake_initial_arithmetic_and_fields_qualified'],
              'initialized constructor state before prefix calls')
    s.require(construction['function']==name and construction['rejection_clears_output_bytes']==1024 and
        construction['successful_placement_destroys_previous_typed_state_first'], 'outer rejection and typed replacement replayed')
    return dict(function=name,reviewed_instruction_positions=positions,geometry=geometry(ir,prior),
        success_only_after_both_prefix_updates_and_advance=True,
        initialized_failure_clears_pending_and_typed_owner=True,uninitialized_overflow_never_drops_local_owner=True,
        restored_guard_and_plan_on_normal_failure=True,outer_failure_status=6,
        retained_constructor_transfers_qualified=False,private_frame_erasure_qualified=False,
        all_constructor_paths_qualified=False,shared_runtime_completion_package=8)
