"""Saved direct AVX2 SHA-3/SHAKE constructor caller and physical transfers.

cSHAKE setup, whole-frame erasure and runtime copy/ABI implementation are not
qualified here. Opaque result bytes retain provenance, not initialization claims.
"""
import windows_enclave_sha3_batch_start as start
import windows_enclave_sha3_batch_initial as initial

life,s,L=start.life,start.s,start.shapes.L
CALLER=L(f'''.B56:|movq 2224(%rsi), %rdx|leaq 1696(%rsp), %rcx|movl %eax, %r8d
    callq {initial.NAME}|movq 2640(%rsp), %r14|cmpq $2, %r14|je .B51
    movzbl 1696(%rsp), %r12d|leaq 1697(%rsp), %rdx|leaq 704(%rsp), %rbx
    movl $943, %r8d|movq %rbx, %rcx|callq memcpy
    vmovups 2648(%rsp), %ymm0|vmovaps %ymm0, 2976(%rsp)
    movq 2680(%rsp), %rax|movq %rax, 3008(%rsp)
    leaq 3945(%rsp), %rcx|movl $943, %r8d|movq %rbx, %rdx|vzeroupper|callq memcpy
    vmovaps 2976(%rsp), %ymm0|vmovaps %ymm0, 576(%rsp)|movq 3008(%rsp), %rax''')
FAILURE=L('.B51:|movb $6, %al|testb $1, %r15b|je .B53|jmp .B59')


def predecessors(lines):
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    pred={i:set() for i in range(len(lines))};dispatches=0
    for at,line in enumerate(lines):
        if line=='retq':targets=[]
        elif line.startswith('j'):
            op,target=line.split()
            if target.startswith('*'):
                s.require(line=='jmpq *%rcx','only the admitted AVX2 identity dispatch')
                dispatches+=1;targets=[labels[f'.B{n}'] for n in start.TABLES['avx2'][1]]
            else:
                s.require(target in labels,'bounded local AVX2 branch')
                targets=[labels[target]]+([] if op in ('jmp','jmpq') else [at+1])
        else:targets=[at+1]
        for target in targets:
            s.require(target in pred,'no out-of-body AVX2 fallthrough');pred[target].add(at)
    s.require(dispatches==1,'exact AVX2 dispatch population')
    return pred


def check_shapes(bodies,assembly):
    names,_,admission=start.check_shapes(bodies,assembly,'avx2');name=names['start']
    lines=life.code(bodies[name]);covered=set()
    for part in (CALLER,FAILURE):
        at=lines.index(part[0]);end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[at:end]==part,'complete AVX2 constructor caller/failure block')
        covered.update(range(at,end))
    begin=lines.index('.B56:');placement=lines.index('.B58:');pred=predecessors(lines)
    s.require(lines[begin+len(CALLER)]=='.B58:','direct success falls through to placement')
    s.require(pred[begin]=={lines.index('je .B56')},'only zero N/S path enters direct constructor')
    for at in range(begin+1,placement):
        s.require(pred[at]=={at-1},'no internal constructor re-entry')
    # The other B58 predecessor is the pending cSHAKE path, not covered here.
    s.require(pred[placement]=={placement-1,lines.index('jmp .B58')},'enumerated placement joins')
    return name,sorted(covered),sorted(covered|set(admission))


def helper_contract(bodies,ir):
    """Join authority/output offsets to the separately replayed exact helper."""
    body=life.code(bodies[initial.NAME])
    parts=[L('movq (%rdx), %rax|movq %rdx, 896(%rsp)|movq %rax, 904(%rsp)'),
        L('movq 896(%rsp), %r12|vmovdqu (%r15), %xmm0|vmovdqa %xmm0, 64(%rsp)'),
        L('leaq 929(%rsp), %rsi|leaq 1561(%rsp), %rdx|movl $575, %r8d|movq %rsi, %rcx|callq memcpy'),
        L('movb %r14b, 928(%rsp)|movq %r12, 1504(%rsp)'),
        L('leaq 1(%rdi), %rcx|movl $607, %r8d|movq %rsi, %rdx|callq memcpy'),
        L('movq $2, 944(%rcx)')]
    for part in parts:
        hits=[i for i in range(len(body)) if body[i:i+len(part)]==part]
        s.require(len(hits)==1,'unique helper authority/result contract slice')
    abi=life.reuse.abi(ir,initial.NAME)
    signature=('(ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 32 '
        'captures(none) dereferenceable(992) %0, ptr noundef nonnull align 8 %1, '
        'i8 noundef range(i8 0, 8) %2)')
    s.require(signature in abi and 'nounwind' in abi,'exact bounded constructor result/authority/identity ABI')
    s.require(1+1504-929==576,'session authority field inside returned state')
    return dict(authority_result_span=[576,584],result_bytes=992,
        authority_origin='retained owner +2224',abi_replayed=True,
        physical_bytes_not_all_initialized=True,normal_error_discriminant=2)


def schedule():
    steps=[('produce',),('copy','frame',2640,'saved',8,8),('accept',),
        ('copy','frame',1696,'saved',0,1)]
    for source,dest,size in ((1697,704,943),(2648,2976,32),(2680,3008,8),
                             (704,3945,943),(2976,576,32),(3008,608,8)):
        steps.append(('copy','frame',source,'frame',dest,size))
    steps += [('destroy',),('copy','saved',0,'owner',1216,1),
        ('copy','frame',3945,'owner',1217,943),('copy','saved',8,'owner',2160,8),
        ('copy','frame',576,'owner',2168,32),('copy','frame',608,'owner',2200,8),('publish',)]
    return steps


def replay(identity,steps=None):
    s.require(type(identity) is int and 0<=identity<6,'six direct SHA-3/SHAKE identities only')
    memory={n:[('unknown',n,i) for i in range(size)] for n,size in
        (('frame',4888),('saved',16),('owner',2272))}
    authority=[('authority',i) for i in range(8)];memory['owner'][2224:2232]=authority
    before=memory['owner'].copy()
    result=[('opaque-result',identity,i) for i in range(992)]
    result[576:584]=authority
    result[944:952]=list((1 if identity<4 else 0).to_bytes(8,'little'))
    produced=accepted=destroyed=published=False;written=set()
    def region(name,at,size):
        s.require(name in memory and type(at) is int and type(size) is int and size>0 and
            (32 if name=='frame' else 1216 if name=='owner' else 0)<=at and
            at+size<=(2208 if name=='owner' else len(memory[name])),
            'bounded result/staging/retained copy, excluding home and neighbouring owner fields')
        return memory[name]
    def complete():
        s.require(produced and accepted and destroyed and written==set(range(1216,2208)),
            'complete physical installation after successful helper and destruction')
        s.require(memory['owner'][1216:2208]==result,'all returned byte origins preserved')
        s.require(memory['owner'][1792:1800]==authority,'same live session authority reaches retained engine')
        s.require(memory['owner'][:1216]==before[:1216] and memory['owner'][2208:]==before[2208:],
            'output, plan and outer authority untouched by state transfer')
    for step in schedule() if steps is None else steps:
        s.require(not published,'no state transfer after publication')
        if step[0]=='produce':
            s.require(not produced,'one complete helper result');produced=True
            memory['frame'][1696:2688]=result;continue
        if step[0]=='accept':
            s.require(produced and not accepted and memory['saved'][8:16]==result[944:952],
                'exact returned discriminant tested before any payload transfer')
            accepted=True;continue
        if step[0]=='destroy':
            s.require(accepted and not destroyed and not written,'old state destruction before installation')
            destroyed=True;memory['owner'][1216:2208]=[('destroyed',i) for i in range(992)];continue
        if step[0]=='publish':complete();published=True;continue
        s.require(step[0]=='copy','known direct-constructor transfer')
        _,src,at,dst,end,size=step
        s.require(produced and (accepted or step==('copy','frame',2640,'saved',8,8)),
            'only discriminant read before success check')
        values=region(src,at,size)[at:at+size];target=region(dst,end,size)
        s.require(src!=dst or at+size<=end or end+size<=at,'nonoverlapping physical copies')
        if dst=='owner':
            s.require(destroyed,'destroy retained state before overwriting')
            s.require(not written.intersection(range(end,end+size)),'no duplicate retained stores')
            written.update(range(end,end+size))
        target[end:end+size]=values
    complete();s.require(published,'publish only complete replacement')
    s.require(memory['frame'][1696:2688]==result,'source result remains live throughout copying')
    return dict(identity=identity,result_span=[1696,2688],retained_span=[1216,2208],
        authority_result_span=[576,584],authority_retained_span=[1792,1800],
        all_physical_origins_preserved=True,source_destination_nonoverlap=True,
        output_plan_and_outer_authority_preserved=True,publication_after_replacement=True,
        padding_and_inactive_initialization_qualified=False,temporary_copy_erasure_qualified=False)


def inspect(bodies,assembly,ir,prior,construction,placement):
    name,covered,total=check_shapes(bodies,assembly)
    reused=prior['initial_constructor_rebinding']
    s.require(prior['prior_semantics_replayed'] and reused['function']==initial.NAME and
        reused['exact_code_extent_and_abi'] and reused['constructor_semantics_reused'],
        'replayed exact helper semantics, constants and ABI required')
    s.require(construction['function']==name and construction['successful_placement_destroys_previous_typed_state_first']
        and construction['successful_slot_and_phase_commit_after_state_copy'] and
        construction['non_cshake_requires_zero_name_and_customization_lengths'],
        'same admitted caller, zero N/S, old-state destruction and final publication')
    s.require(placement['state_destructor']['function']==life.DROP['avx2'] and
        placement['state_destructor']['typed_payload_cleanup_composed'],'replayed old-state destructor')
    return dict(function=name,helper=helper_contract(bodies,ir),reviewed_instruction_positions=covered,
        combined_start_instruction_positions=total,identities={str(i):replay(i) for i in range(6)},
        direct_constructor_caller_transfers_qualified=True,normal_error_status=6,
        normal_error_skips_payload_placement=True,armed_failure_uses_reviewed_clear_and_quarantine=True,
        preserved_nonvolatile_values=['rsi:owner','rdi:slot','r15:guard','r12:byte0','r14:discriminant','rbx:staging'],
        runtime_copy_abi_and_disjoint_resident_allocation_required=True,
        cshake_constructor_lifetimes_qualified=False,all_constructor_paths_qualified=False,
        private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
