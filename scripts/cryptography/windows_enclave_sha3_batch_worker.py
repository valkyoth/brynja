"""Complete sequential worker entry paths, conditional on the linked C ABI."""
import windows_enclave_sha3_batch_resident as resident

life,s=resident.life,resident.s
L=resident.lines


def scalar(n,live):
    out=L('''pushq %r15|pushq %r14|pushq %r12|pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx
        subq $1344, %rsp|testq %rdx, %rdx|sete %r10b|testl $4095, %edx|setne %r11b
        movl $200, %eax|orb %r10b, %r11b|jne .B29|movq %r9, %r10|subq %r8, %r10
        setae %r11b|cmpq $65536, %r10|sete %r10b|andb %r11b, %r10b|cmpb $1, %r10b|jne .B29''')
    out += [f'movq {live}(%rip), %rsi']+L('''testq %rcx, %rcx|je .B8|testq %rsi, %rsi|je .B10
        movl $203, %eax|cmpq %rdx, %rsi|jne .B29|cmpq $3, %rcx|jne .B11
        movq %rsi, %rcx|movq %rdx, %rdi''')+['callq '+n['clear'],'addq $16, %rsi',
        'movq %rsi, %rcx','callq '+life.DROP['scalar'],'movq %rdi, %rcx',
        f'movq $0, {live}(%rip)','xorl %edx, %edx','movl $4, %eax']
    out+=resident.page_loop('rcx','rdx','.B7')+L('''jmp .B29|.B8:|movl $201, %eax|testq %rsi, %rsi
        jne .B29|movq $0, (%rdx)|movb $0, 16(%rdx)|leaq 1344(%rdx), %rcx|xorps %xmm0, %xmm0''')
    for i in range(8):
        out += [('movaps' if i%2==0 else 'movups')+f' %xmm0, {1152+24*i}(%rdx)',
                f'movb $0, {1168+24*i}(%rdx)']
    out += L('''movl $1042, %r8d|movq %rdx, %rsi|xorl %edx, %edx|callq memset''')+[
        f'movq %rsi, {live}(%rip)']+L('''movl $1, %eax|jmp .B29|.B10:|movl $202, %eax|jmp .B29
        .B11:|movq %r8, %r15|movq %rcx, %rdi|leaq 32(%rsp), %r14|movq %r14, %rbx
        subq $-1024, %rbx|setb %bpl|movl $1312, %r8d|movq %r14, %rcx|xorl %edx, %edx
        movq %r9, %r12|callq memset|cmpq %r12, %rbx|ja .B27|testb %bpl, %bpl|je .B27
        cmpq %r14, %r15|ja .B27|movl $204, %r14d|cmpq $-289, %rbx|ja .B28
        cmpq %rbx, %r15|ja .B28|leaq 1344(%rsp), %rcx|cmpq %r12, %rcx|ja .B28
        leaq 32(%rsp), %r8|movq %rsi, %rcx|movq %rdi, %rdx''')+['callq '+n['receive']]+L('''
        movl %eax, %ebp|testb %al, %al|jne .B19|movq %rsi, %rcx''')+['callq '+n['quarantine']]+L('''
        .B19:|movl $288, %edx|movq %rbx, %rcx''')+['callq '+life.ZERO]+L('''
        leaq 32(%rsp), %rcx|movl $1024, %edx''')+['callq '+life.ZERO]+L('''
        movl $1027, %eax|movl $205, %r14d|.B20:|cmpq $1315, %rax|je .B30
        cmpb $0, 29(%rsp,%rax)|jne .B39|cmpb $0, 30(%rsp,%rax)|jne .B39
        cmpb $0, 31(%rsp,%rax)|jne .B28|cmpb $0, 32(%rsp,%rax)|leaq 4(%rax), %rax
        je .B20|jmp .B28|.B27:|movl $204, %r14d|.B28:|movq %rsi, %rcx''')+[
        'callq '+n['quarantine'],'leaq 32(%rsp), %rcx','callq '+n['buffers']]+L('''
        movq %r14, %rax|.B29:|addq $1344, %rsp|popq %rbx|popq %rbp|popq %rdi|popq %rsi
        popq %r12|popq %r14|popq %r15|retq|.B30:|movl $4, %eax|movl $205, %r14d|.B31:
        cmpb $0, 28(%rsp,%rax)|jne .B39|cmpb $0, 29(%rsp,%rax)|jne .B39
        cmpb $0, 30(%rsp,%rax)|jne .B39|cmpb $0, 31(%rsp,%rax)|jne .B39
        cmpq $1024, %rax|je .B43|cmpb $0, 32(%rsp,%rax)|leaq 5(%rax), %rax|je .B31
        jmp .B28|.B39:|movl $205, %r14d|jmp .B28|.B43:|leaq 32(%rsp), %rdx
        movl $1, %r8d|movq %rbx, %rcx|callq PublicSha3BatchObserve|cmpl $1, %eax|jne .B28
        movabsq $4294967296, %rax|orq %rax, %rdi|testb %bpl, %bpl|movl $206, %esi
        cmovneq %rdi, %rsi|leaq 32(%rsp), %rcx''')+['callq '+n['buffers'],'movq %rsi, %rax','jmp .B29']
    return out


def avx2(n,live,page):
    out=L('''pushq %r15|pushq %r14|pushq %rsi|pushq %rdi|pushq %rbp|pushq %rbx|subq $1400, %rsp
        testq %rdx, %rdx|setne %al|testl $4095, %edx|sete %r10b|testb %r10b, %al|je .B1
        movq %r9, %rax|subq %r8, %rax|setb %r10b|cmpq $-4097, %rdx|ja .B1
        testb %r10b, %r10b|jne .B1|cmpq $65536, %rax|jne .B1|leaq 4096(%rdx), %rax
        cmpq %r8, %rax|seta %al|cmpq %rdx, %r9|seta %r10b|testb %r10b, %al|jne .B1''')+[
        f'movq {live}(%rip), %rax','testq %rcx, %rcx','je .B10','testq %rax, %rax','je .B15',
        f'cmpq %rdx, {page}(%rip)','jne .B24','cmpq $3, %rcx','jne .B27',
        f'movq {live}+16(%rip), %rdx',f'movq $0, {live}(%rip)','movq %rax, %rcx',
        'callq '+n['drop'],f'movq $0, {page}(%rip)','movl $4, %esi','jmp .B51','.B1:',
        'movl $200, %esi',f'cmpq $0, {live}(%rip)','je .B51',f'movq {live}+16(%rip), %rdi']
    out+=life.clear('avx2','rdi')+life.quarantine('avx2','rdi',4)+L('''
        .B51:|movq %rsi, %rax|addq $1400, %rsp|popq %rbx|popq %rbp|popq %rdi|popq %rsi
        popq %r14|popq %r15|retq|.B10:|testq %rax, %rax|je .B16''')+[
        f'movq {live}+16(%rip), %rsi']+life.clear('avx2')+life.quarantine('avx2',label=13)+L('''
        movl $201, %esi|jmp .B51|.B15:|movl $202, %esi|jmp .B51|.B24:''')+[
        f'movq {live}+16(%rip), %rsi']+life.clear('avx2')+life.quarantine('avx2',label=26)+L('''
        movl $203, %esi|jmp .B51|.B16:|movl $4096, %r8d|movq %rdx, %rcx|movq %rdx, %rsi
        xorl %edx, %edx|callq memset|leaq 40(%rsp), %rcx|movq %rsi, %rdi|movq %rsi, %rdx''')+[
        'callq '+n['new']]+L('''cmpq $0, 40(%rsp)|je .B17|movq 56(%rsp), %rax|movq %rax, 80(%rsp)
        vmovups 40(%rsp), %xmm0|vmovaps %xmm0, 64(%rsp)''')+[
        f'movq {live}(%rip), %rcx','testq %rcx, %rcx','je .B20',
        f'movq {live}+16(%rip), %rdx','callq '+n['drop'],'.B20:',
        'movq 80(%rsp), %rax',f'movq %rax, {live}+16(%rip)',
        'vmovaps 64(%rsp), %xmm0',f'vmovups %xmm0, {live}(%rip)',f'movq %rdi, {page}(%rip)']+L('''
        movl $1, %esi|jmp .B51|.B27:|movq %r8, %r15|movq %rcx, %r14|leaq 64(%rsp), %rbx
        movq %rbx, %rdi|subq $-1024, %rdi|setb %bpl|movl $1328, %r8d|movq %rbx, %rcx
        xorl %edx, %edx|movq %r9, %rsi|callq memset|movq %rsi, %rax|movl $204, %esi
        cmpq %rax, %rdi|ja .B53|testb %bpl, %bpl|je .B53|cmpq %rbx, %r15|ja .B53
        cmpq $-305, %rdi|ja .B53|cmpq %rdi, %r15|ja .B53|leaq 1392(%rsp), %rcx
        cmpq %rax, %rcx|ja .B53|movq %r14, %rcx|leaq 64(%rsp), %rdx''')+[
        'callq '+n['receive'],'movl %eax, %ebx','testb %al, %al','jne .B35',
        f'movq {live}+16(%rip), %rcx','callq '+n['quarantine'],'.B35:',
        'leaq 64(%rsp), %rcx','callq '+n['buffers_clear']]+L('''
        movl $1028, %eax|movl $205, %esi|.B36:|cmpb $0, 60(%rsp,%rax)|jne .B53
        cmpb $0, 61(%rsp,%rax)|jne .B53|cmpb $0, 62(%rsp,%rax)|jne .B53
        cmpb $0, 63(%rsp,%rax)|jne .B53|cmpq $1328, %rax|je .B41
        cmpb $0, 64(%rsp,%rax)|leaq 5(%rax), %rax|je .B36|.B53:''')+[
        f'movq {live}+16(%rip), %rcx','callq '+n['quarantine'],'.B50:',
        'leaq 64(%rsp), %rcx','callq '+n['buffers'],'jmp .B51']+L('''
        .B17:|movl $207, %esi|jmp .B51|.B41:|movl $4, %eax|.B42:
        cmpb $0, 60(%rsp,%rax)|jne .B53|cmpb $0, 61(%rsp,%rax)|jne .B53
        cmpb $0, 62(%rsp,%rax)|jne .B53|cmpb $0, 63(%rsp,%rax)|jne .B53
        cmpq $1024, %rax|je .B48|cmpb $0, 64(%rsp,%rax)|leaq 5(%rax), %rax|je .B42
        jmp .B53|.B48:|leaq 64(%rsp), %rdx|movl $1, %r8d|movq %rdi, %rcx
        callq PublicSha3BatchObserve|cmpl $1, %eax|jne .B53|movabsq $4294967296, %rax
        orq %rax, %r14|testb %bl, %bl|movl $206, %esi|cmovneq %r14, %rsi|jmp .B50''')
    return out


def readback_offsets(lane):
    # Model the exact public loop counters in the checked bodies, not memory
    # contents. No early error path is counted as a successful zero receipt.
    start=32 if lane=='scalar' else 64;header=288 if lane=='scalar' else 304
    payload=[]
    for counter in range(4,1025,5):
        payload += [start-4+counter+i for i in range(4)]
        if counter!=1024:payload.append(start+counter)
    if lane=='scalar':
        head=[29+counter+i for counter in range(1027,1315,4) for i in range(4)]
    else:
        head=[]
        for counter in range(1028,1329,5):
            head += [60+counter+i for i in range(4)]
            if counter!=1328:head.append(64+counter)
    s.require(payload==list(range(start,start+1024)) and head==list(range(start+1024,start+1024+header)),
              'successful readback visits every header/payload byte exactly once')
    return dict(payload=[start,start+1024],header=[start+1024,start+1024+header],
                payload_reads=len(payload),header_reads=len(head))


def inspect(bodies,ir,lane,prior,storage):
    s.require(lane in life.LAYOUT,'only sequential worker routes')
    s.require(storage['state_destructor']['typed_payload_cleanup_composed'] and
              storage['state_pointer_inside_owner'],'state cleanup and bounded subobjects prerequisite')
    placed=resident.inspect(bodies,ir,lane,prior);n=placed['functions']
    live=n['receive'].removesuffix('7receive')+'4LIVE'+('.0' if lane=='scalar' else '')
    page=n['receive'].removesuffix('7receive')+'9LIVE_PAGE.0' if lane=='avx2' else None
    expected=scalar(n,live) if lane=='scalar' else avx2(n,live,page)
    s.require(life.code(bodies['RetainedWork'])==expected,'complete retained worker admission/construction/receive/cleanup/retirement')
    s.require('(i64 noundef %operation, ptr noundef %page, i64 noundef %low, i64 noundef %high, i64 noundef %_output)' in
              life.reuse.abi(ir,'RetainedWork'),'actual worker entry argument roles')
    # Independent finite normal-CFG check complements whole-body equality.
    start='.B11' if lane=='scalar' else '.B27'
    returns=s.normal_returns(bodies['RetainedWork'],start,['callq '+n['buffers']])
    return dict(resident=placed,instructions_and_labels_checked=len(expected),live_metadata=live,page_identity_metadata=page,
        serialized_C_entry_required=True,page_allocation_and_residency_provided_by_C=True,
        page_alignment=4096,page_bytes=4096,stack_window_bytes=65536,
        worker_checks_page_stack_nonoverlap=lane=='avx2',
        scalar_page_stack_nonoverlap_requires_linked_C=lane=='scalar',
        initialization_precedes_live_publication=True,exact_page_identity_before_receive=True,
        typed_teardown_and_full_page_erasure_before_close_success=True,
        buffer_readback=readback_offsets(lane),post_buffer_construction_normal_return_sites=returns,
        receiver_nested_call_lifetimes_qualified=False,all_unwind_paths_qualified=False,
        whole_image_stack_residency_and_erasure_qualified=False,shared_completion_package=8)
