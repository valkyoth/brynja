"""Sequential batch update callers; setup/finalization and whole frames stay open.

These expectations describe reviewed emitted instructions, not instructions
learned from a candidate. Lower absorption is reused only after semantic replay
and exact body/reference/extent/ABI comparison by the enclosing checker.
"""
import windows_enclave_sha3_batch_receive as receive

life=receive.life
s=life.s
L=receive.L
TABLE=[17,6,8,9,10,11,13,17,17]


def names(bodies,lane):
    n={k:s.one(bodies,'Owner'+str(len(k))+k+'$') for k in ('operation','update')}
    if lane=='scalar':
        n.update({rate:s.one(bodies,'HardenedFips202OwnerKj'+rate+'_E6update')
                  for rate in ('48','68','88','90','a8')})
    else:
        n.update(absorb=s.one(bodies,r'Engine6absorb$'),wipe=s.one(bodies,r'Memory4wipe$'))
    return n


def scalar(n):
    def absorb(offset,rate):
        return L(f'leaq {offset}(%rbx), %rcx|movq %rsi, %rdx|callq '+n[rate])
    result=L(f'''pushq %r14|pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx|subq $48, %rsp
        movq %r9, %rsi|movq %r8, %rdi|movq %rdx, %r8|movq %rcx, %rdx
        leaq 32(%rsp), %rcx|movb $3, %r9b|callq {n['operation']}
        movzbl 40(%rsp), %ebp|cmpb $2, %bpl|jne .B2|movzbl 32(%rsp), %eax|jmp .B20
        .B2:|movq 32(%rsp), %rbx|movb $2, %r14b|cmpl $1, (%rbx)|jne .B17
        cmpq %rdi, 8(%rbx)|jne .B17|movq 128(%rsp), %r8|movq 2376(%rbx), %rax
        movb $3, %r14b|subq %r8, %rax|jb .B17|movq %rax, 2376(%rbx)
        movzbl 16(%rbx), %eax|leaq TABLE0(%rip), %rcx|movslq (%rcx,%rax,4), %rax
        addq %rcx, %rax|movb $2, %r14b|jmpq *%rax|.B6:''')
    result+=absorb(17,'90')+L('jmp .B7|.B11:|movb $6, %r14b|cmpb $0, 17(%rbx)|jne .B17')
    result+=absorb(18,'a8')+L('jmp .B15|.B9:')+absorb(17,'68')
    result+=L('jmp .B7|.B10:')+absorb(17,'48')
    result+=L('jmp .B7|.B13:|movb $6, %r14b|cmpb $0, 17(%rbx)|jne .B17')+absorb(18,'88')
    result+=L('.B15:|movl %eax, %ecx|movb $-1, %al|jmp .B16|.B8:')+absorb(17,'88')
    result+=L('''.B7:|movl %eax, %ecx|movb $-1, %al|movb $6, %r14b
        .B16:|testb %cl, %cl|je .B20|.B17:|testb $1, %bpl|jne .B19''')
    return result+life.clear('scalar','rbx')+life.quarantine('scalar','rbx')+L('''
        .B19:|movl %r14d, %eax|.B20:|addq $48, %rsp|popq %rbx|popq %rbp
        popq %rdi|popq %rsi|popq %r14|retq''')


def avx2(n):
    wipe=L(f'movb $1, 2075(%rsi)|movq $0, 1832(%rsi)|leaq 1840(%rsi), %rcx|callq '+n['wipe'])
    result=L(f'''pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx|subq $56, %rsp
        movq %r9, %rdi|movq %r8, %rbx|movq %rdx, %r8|movq %rcx, %rdx
        leaq 40(%rsp), %rcx|movb $3, %r9b|callq {n['operation']}
        movzbl 48(%rsp), %ebp|cmpb $2, %bpl|jne .B2|movzbl 40(%rsp), %eax|jmp .B22
        .B2:|movq 40(%rsp), %rsi|movb $2, %al|cmpl $1, 2232(%rsi)|jne .B18
        cmpq %rbx, 2240(%rsi)|jne .B18|movq 128(%rsp), %r8|movq 2216(%rsi), %rcx
        movb $3, %al|subq %r8, %rcx|jb .B18|movq %rcx, 2216(%rsi)|movb $6, %al
        cmpl $2, 2160(%rsi)|je .B18|cmpb $1, 2178(%rsi)|jne .B15
        cmpb $0, 2075(%rsi)|jne .B15|cmpb $0, 2074(%rsi)|jne .B15
        movq 1792(%rsi), %rax|cmpb $1, 8(%rax)|jne .B15
        movq (%rax), %rcx|cmpq 1800(%rsi), %rcx|jne .B15|cmpb $4, 9(%rax)|jne .B15
        leaq 1216(%rsi), %rcx|movq %rdi, %rdx|callq {n['absorb']}
        cmpb $-1, %al|je .B13''')+wipe+['.B15:']+wipe
    result+=L(f'''cmpb $-1, 2154(%rsi)|je .B17|leaq 2152(%rsi), %rcx|movl $1, %edx
        callq {life.ZERO}|movb $0, 2153(%rsi)|vxorps %xmm0, %xmm0, %xmm0
        vmovaps %ymm0, 2080(%rsi)|vmovaps %ymm0, 2112(%rsi)
        .B17:|movb $-1, 2154(%rsi)|movb $3, 2178(%rsi)|movb $6, %al
        .B18:|testb $1, %bpl|jne .B22|movl %eax, %ebx|leaq 1216(%rsi), %rcx
        vzeroupper|callq {life.DROP['avx2']}''')
    return result+life.clear_tail('avx2')+life.quarantine('avx2',label=21)+L('''
        movl %ebx, %eax|.B22:|addq $56, %rsp|popq %rbx|popq %rbp|popq %rdi|popq %rsi
        vzeroupper|retq|.B13:|movb $-1, %al|jmp .B22''')


def check_shapes(bodies,assembly,lane):
    s.require(lane in life.LAYOUT,'sequential update lane')
    n=names(bodies,lane);expected=scalar(n) if lane=='scalar' else avx2(n)
    s.require(receive.normalize(bodies[n['update']],assembly,[TABLE] if lane=='scalar' else [])==expected,
              'complete sequential update pointer, budget, status and cleanup contract')
    return n,expected


def arguments(ir,bodies,lane):
    n=names(bodies,lane);receive.arguments(ir,receive.names(bodies,lane),lane)
    pointer='ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) %1'
    length='i64 noundef range(i64 0, -9223372036854775808) %2)'
    if lane=='scalar':
        for rate in ('48','68','88','90','a8'):
            abi=life.reuse.abi(ir,n[rate])
            s.require('noundef zeroext i1 @' in abi and 'nounwind' in abi and
                '(ptr noalias nofree noundef nonnull dereferenceable(1040) %0, '+pointer+', '+length in abi,
                'scalar update lower owner, source and length ABI')
    else:
        abi=life.reuse.abi(ir,n['absorb'])
        s.require('noundef range(i8 -1, 9) i8 @' in abi and 'nounwind' in abi and
            '(ptr noalias nofree noundef nonnull align 32 dereferenceable(864) %0, '+pointer+', '+length in abi,
            'AVX2 update actual engine, source and length ABI')
        abi=life.reuse.abi(ir,n['wipe'])
        s.require('(ptr noalias nofree noundef nonnull dereferenceable(234) %0)' in abi and 'nounwind' in abi,
                  'AVX2 failed engine memory wipe ABI')


def inspect(bodies,assembly,ir,lane,prior,storage,transitions,receiver):
    s.require(prior['prior_semantics_replayed'],'update requires freshly replayed absorption semantics')
    s.require(storage['state_destructor']['typed_payload_cleanup_composed'] and
              storage['state_pointer_inside_owner'],'update requires actual placed state destruction')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
              transitions['unfinished_guard_clears_and_quarantines'],'update requires composed admission and failure cleanup')
    s.require(receiver['payload_pointer_retained_from_worker_buffer'] and receiver['payload_limit']==1024,
              'update requires bounded copied worker input')
    n,expected=check_shapes(bodies,assembly,lane);arguments(ir,bodies,lane)
    s.require(n['update']==receiver['functions']['update'] and n['operation']==transitions['functions']['operation'],
              'update is the actual receiver target and calls the reviewed operation')
    helpers=[n[r] for r in ('48','68','88','90','a8')] if lane=='scalar' else [n['absorb'],n['wipe']]
    s.require(all(h in prior['exact_body_reference_extent_and_abi'] for h in helpers+[life.ZERO]),
              'every update absorption and wipe helper exactly matches replayed semantics')
    # Both Win64 frames place the fifth argument at rsp+128. The live result is
    # outside the 32-byte callee home area; saved registers start after the frame.
    frame,saved,result=(48,40,[32,48]) if lane=='scalar' else (56,32,[40,56])
    s.require(frame+saved+40==128 and 32<=result[0]<result[1]<=frame,'update argument and result frame geometry')
    spans=([[17,1057],[18,1058]] if lane=='scalar' else [[1216,2080],[1840,2074]])
    state=[16,1152] if lane=='scalar' else [1216,2208]
    s.require(all(state[0]<=lo<hi<=state[1] for lo,hi in spans),'update callee regions fit the active state')
    return dict(function=n['update'],instructions_and_labels_checked=len(expected),
        absorption_helpers=helpers,lower_helpers_replayed_and_exact=True,
        copied_input_pointer_and_length_preserved_to_absorption=True,maximum_input_bytes=1024,
        matching_active_slot_required=True,checked_budget_subtraction_before_absorption=True,
        input_disjoint_from_exclusive_owner_by_abi=True,state_payload_spans=spans,
        payload_spans_are_alternatives_or_nested_not_disjoint=True,
        live_operation_result=result,frame_bytes=frame,saved_register_bytes=saved,
        incoming_length_offset=128,success_status=255,failed_update_typed_state_and_output_cleared=True,
        failed_update_quarantines_owner=True,avx2_state_epoch_and_kernel_checked=lane=='avx2',
        initialized_state_and_valid_enum_required=True,start_establishes_state_invariant_qualified=False,
        caller_input_erasure_claimed=False,private_frame_erasure_qualified=False,
        all_unwind_paths_qualified=False,whole_image_qualified=False)
