"""Saved SIMD output commit preflight and returned descriptor transfer checks."""
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_storage as storage
import windows_enclave_sha2_simd_moves as moves


def width_allowed(lane,width):
    s.require(lane in ('simd256','simd512') and type(width) is int and 0<=width<(1<<64),'typed commit width')
    return width in (28,32) if lane=='simd256' else ((width-1)&((1<<64)-1))<=63


def narrow(bodies):
    names=storage.symbols(bodies);body=bodies[names['resident']]
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    s.sequences(body,['leaq 7712(%rbx), %rax|movq %rax, 184(%rbx)|movq $0, 72(%rbx)',
        'cmpb $-1, %dil|je .B176|cmpq $0, 864(%rbx)|je .B192|movq 872(%rbx), %r9|'
        'cmpq $32, %r9|je .B193|cmpq $28, %r9|leaq 10792(%rbx), %r13|je .B193|jmp .B34',
        '.B192:|movq $0, 184(%rbx)'])
    pointers=(184,104,72,128,112,136,232,224);lengths=('%r9','%r12','%r15',144,168,120,304,296)
    preflight=[]
    for i in range(1,8):
        label=189+4*i;after=label+4 if i<7 else 221
        preflight += [f'.B{label}:',f'cmpq $0, {864+16*i}(%rbx)',f'je .B{label+3}',
            f'leaq {7712+32*i}(%rbx), %rax',f'movq %rax, {pointers[i]}(%rbx)']
        if i<3: preflight += [f'movq {872+16*i}(%rbx), {lengths[i]}',f'cmpq $32, {lengths[i]}',
            f'je .B{after}',f'cmpq $28, {lengths[i]}']
        else: preflight += [f'movq {872+16*i}(%rbx), %rax',f'movq %rax, {lengths[i]}(%rbx)',
            'cmpq $32, %rax',f'je .B{after}',f'cmpq $28, {lengths[i]}(%rbx)']
        preflight += ['leaq 10792(%rbx), %r13',f'je .B{after if i<7 else 222}',
            'jmp .B34',f'.B{label+3}:',f'movq $0, {pointers[i]}(%rbx)']
    preflight += ['.B221:','leaq 10792(%rbx), %r13','.B222:']
    s.sequences(body,['|'.join(preflight)])
    copies=[]
    for i in range(8):
        label=222+3*i;after=label+3
        copies += [f'.B{label}:',f'cmpq $0, {pointers[i]}(%rbx)',f'je .B{after}',
            f'movq {864+16*i}(%rbx), %rcx','testq %rcx, %rcx',f'je .B{after}',
            f'movq {872+16*i}(%rbx), %rdx',f'movq {pointers[i]}(%rbx), %r8']
        if i: copies += [f'movq {lengths[i] if i<3 else str(lengths[i])+"(%rbx)"}, %r9']
        copies += ['callq '+copy,'cmpb $-1, %al','jne .B34']
    copies += ['.B246:']
    s.sequences(body,['|'.join(copies),'.B246:|vmovaps 320(%rbx), %xmm0|vmovaps %xmm0, 368(%rbx)|'
        'movl 216(%rbx), %eax|movl 219(%rbx), %ecx|movl %eax, 200(%rbx)|movl %ecx, 203(%rbx)|'
        'leaq 6688(%rbx), %rcx|callq '+names['workspace']])
    return dict(lanes=8,source_offset=7712,source_stride=32,destination_descriptors=864,
        prepared_pointer_slots=list(pointers),preflight_before_first_copy=True,
        first_source_slot_materialized_before_finish_loop=True,first_source_lifetime_composition_pending=True,
        direct_copy_failure_revokes=True,workspace_erased_after_commit=True)


def wide(bodies):
    names=storage.symbols(bodies);body=bodies[s.one(bodies,r'Executor13digest_secret$')]
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    s.sequences(body,['vmovups (%r9), %ymm0|vmovups 32(%r9), %ymm1|vmovups %ymm1, 848(%rbp)|'
        'vmovups %ymm0, 816(%rbp)|movq $0, 880(%rbp)',
        'leaq 1024(%rdi), %rax|movq %rax, 976(%rbp)',
        'cmpb $-1, %r15b|je .B242|cmpq $0, 816(%rbp)|je .B243|movq 824(%rbp), %r9|'
        'leaq -1(%r9), %rax|movb $11, %r14b|cmpq $63, %rax|movq 1168(%rbp), %rdi|ja .B14|jmp .B244',
        '.B243:|movq $0, 976(%rbp)'])
    s.sequences(body,['.B244:|cmpq $0, 832(%rbp)|je .B247|movq 840(%rbp), %r12|'
        'leaq -1(%r12), %rax|movb $11, %r14b|cmpq $63, %rax|movq 1168(%rbp), %rdi|'
        'ja .B14|leaq 1088(%rdi), %rbx|jmp .B248|.B247:|xorl %ebx, %ebx'])
    for i,base,ptr,length in ((2,248,1024,1016),(3,252,984,960)):
        s.sequences(body,[f'.B{base}:|cmpq $0, {816+16*i}(%rbp)|je .B{base+3}|'
            f'movq {824+16*i}(%rbp), %rax|movq %rax, {length}(%rbp)|decq %rax|'
            'movb $11, %r14b|cmpq $63, %rax|movq 1168(%rbp), %rdi|ja .B14|'
            f'leaq {1024+64*i}(%rdi), %rax|movq %rax, {ptr}(%rbp)|jmp .B{base+4}|'
            f'.B{base+3}:|movq $0, {ptr}(%rbp)'])
    pre=['.B256:','cmpq $0, 976(%rbp)','movq 1168(%rbp), %rdi','je .B259',
         'movq 816(%rbp), %rcx','testq %rcx, %rcx','je .B259','movq 824(%rbp), %rdx',
         'movq 976(%rbp), %r8','callq '+copy,'movb $11, %r14b','cmpb $-1, %al','jne .B14']
    for i,ptr,length in ((1,'%rbx','%r12'),(2,'1024(%rbp)','1016(%rbp)'),(3,'984(%rbp)','960(%rbp)')):
        label=256+3*i
        pre += [f'.B{label}:',('testq %rbx, %rbx' if i==1 else f'cmpq $0, {ptr}'),f'je .B{label+3}',
                f'movq {816+16*i}(%rbp), %rcx','testq %rcx, %rcx',f'je .B{label+3}',
                f'movq {824+16*i}(%rbp), %rdx',f'movq {ptr}, %r8',f'movq {length}, %r9',
                'callq '+copy,'movb $11, %r14b','cmpb $-1, %al','jne .B14']
    pre += ['.B268:','movq 687(%rbp), %rax','movq %rax, 751(%rbp)',
        'vmovaps 672(%rbp), %xmm0','vmovaps %xmm0, 736(%rbp)','movl 896(%rbp), %eax',
        'movl 899(%rbp), %ecx','movl %eax, 912(%rbp)','movl %ecx, 915(%rbp)',
        'movq %rdi, %rcx','callq '+names['workspace']]
    s.sequences(body,['|'.join(pre)])
    return dict(lanes=4,source_workspace_offset=1024,source_stride=64,destination_descriptors=816,
        preflight_before_first_copy=True,unsigned_decrement_width_test=True,
        direct_copy_failure_revokes=True,workspace_erased_after_commit=True,
        first_source_lifetime_composition_pending=True)


def transfers(bodies,lane):
    body=bodies[storage.symbols(bodies)['resident']]
    if lane=='simd256':
        return [moves.trace(body,'movzbl 864(%rbx), %eax','movb %al, 2912(%rbx)',
            ('rbx',864),('rbx',2912),136)]
    executor=bodies[s.one(bodies,r'Executor13digest_secret$')]
    return [moves.trace(executor,'vmovups 816(%rbp), %ymm0','movq %rax, 64(%rsi)',
                ('rbp',816),('rsi',0),72),
            moves.trace(body,'movzbl 4640(%rbx), %eax','movb %al, 352(%rbx)',
                ('rbx',4640),('rbx',352),72)]


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'saved commit route')
    return dict(commit=(narrow if lane=='simd256' else wide)(bodies),
        returned_descriptor_moves=transfers(bodies,lane),
        descriptor_integrity_across_inner_computation_pending=True,
        algorithm_and_result_identity_review_pending=True,whole_frame_qualified=False)
