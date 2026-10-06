"""Saved SIMD owned-field erasure and normal error cleanup, not whole-frame proof."""
import re
import windows_enclave_kmac_shapes as s


def instructions(body):
    return [line for line in s.lines(body) if line.startswith('.B') or
            not (line.startswith('.') or line.endswith(':'))]


def exact(body,expected):
    s.require(instructions(body)==expected,'complete owned-storage destructor instructions')


def symbols(bodies):
    return {key:s.one(bodies,pattern) for key,pattern in {
        'cpu':r'crypto_cpu.*scratch.*Workspace4wipe$',
        'workspace':r'hash_sha2.*workspace.*Workspace4wipe$',
        'scalar':r'HardenedSha2Owner4wipe$',
        'drop':r'^_RIN.*drop_glue.*workspace9WorkspaceE',
        'output':r'output.*SecretBatchOutput.*Drop4drop$',
        'resident':r'Resident6digest$'}.items()}


def regions(lane):
    narrow=lane=='simd256'
    cpu=[(0,256),(256,2048 if narrow else 2560),(2304 if narrow else 2816,256),
         (2560 if narrow else 3072,192)]
    scalar=[(1024,64),(0,128),(1152,16),(1168,2),(128,640),(768,128),(896,128),(1088,64)]
    fields=([(512,256),(768,256),(0,512),(1024,256)]+
        ([(1280,64),(4096,8),(5274,1)] if narrow else [(4544,32),(4576,4),(5750,1)]))
    return cpu,scalar,fields,(1344,4104,5280) if narrow else (1280,4580,5760)


def linear_wipe(body,spans):
    expected=['pushq %rsi','subq $32, %rsp','movq %rcx, %rsi']
    for i,(offset,size) in enumerate(spans):
        last=i==len(spans)-1
        if i==0:
            if offset: expected.append(f'addq ${offset}, %rcx')
            expected += [f'movl ${size}, %edx','callq '+s.ZERO]
        elif last:
            expected += [f'addq ${offset}, %rsi',f'movl ${size}, %edx','movq %rsi, %rcx',
                         'addq $32, %rsp','popq %rsi','jmp '+s.ZERO]
        elif offset:
            expected += [f'leaq {offset}(%rsi), %rcx',f'movl ${size}, %edx','callq '+s.ZERO]
        else: expected += [f'movl ${size}, %edx','movq %rsi, %rcx','callq '+s.ZERO]
    exact(body,expected)


def wiping(bodies,lane):
    names=symbols(bodies);cpu,scalar,fields,(cp,sp,size)=regions(lane)
    linear_wipe(bodies[names['cpu']],cpu);linear_wipe(bodies[names['scalar']],scalar)
    expected=['pushq %rsi','subq $32, %rsp','movq %rcx, %rsi']
    for i,(offset,width) in enumerate(fields):
        if i==0: expected += [f'addq ${offset}, %rcx',f'movl ${width}, %edx']
        elif offset: expected += [f'leaq {offset}(%rsi), %rcx',f'movl ${width}, %edx']
        else: expected += [f'movl ${width}, %edx','movq %rsi, %rcx']
        expected.append('callq '+s.ZERO)
    expected += [f'leaq {sp}(%rsi), %rcx','callq '+names['scalar'],f'addq ${cp}, %rsi',
                 'movq %rsi, %rcx','addq $32, %rsp','popq %rsi','jmp '+names['cpu']]
    exact(bodies[names['workspace']],expected)
    exact(bodies[names['drop']],['pushq %rsi','subq $32, %rsp','movq %rcx, %rsi',
        'callq '+names['workspace'],f'leaq {sp}(%rsi), %rcx','callq '+names['scalar'],
        f'addq ${cp}, %rsi','movq %rsi, %rcx','addq $32, %rsp','popq %rsi','jmp '+names['cpu']])
    owned=fields+[(cp+o,n) for o,n in cpu]+[(sp+o,n) for o,n in scalar]
    covered=[byte for offset,width in owned for byte in range(offset,offset+width)]
    end=5275 if lane=='simd256' else 5751
    s.require(len(covered)==len(set(covered)) and set(covered)==set(range(end)),
              'every declared workspace byte covered without overlap')
    return dict(cpu_regions=cpu,scalar_regions=scalar,workspace_regions=owned,
        workspace_bytes=size,declared_field_bytes=end,unwiped_alignment_padding=[end,size],
        inactive_lanes_cleared=True,individual_compiler_copy_erasure_claimed=False)


def output_drop(bodies,lane):
    name=symbols(bodies)['output'];size=128 if lane=='simd256' else 64
    code=['pushq %rsi','pushq %rdi','subq $40, %rsp','movq %rcx, %rsi','xorl %edi, %edi',
        f'cmpq ${size}, %rdi','jne .B2','jmp .B4','.B3:','addq $16, %rdi',
        f'cmpq ${size}, %rdi','je .B4','.B2:','movq (%rsi,%rdi), %rcx','testq %rcx, %rcx',
        'je .B3','movq 8(%rsi,%rdi), %rdx','testq %rdx, %rdx','je .B3','callq '+s.ZERO,
        'addq $16, %rdi',f'cmpq ${size}, %rdi','jne .B2','.B4:',
        'subq $-128, %rsi' if size==128 else 'addq $64, %rsi',
        'movl $8, %edx','movq %rsi, %rcx','addq $40, %rsp','popq %rdi','popq %rsi','jmp '+s.ZERO]
    exact(bodies[name],code)
    return dict(function=name,slots=size//16,pointer_length_stride=16,identity_bytes_cleared=8,
        null_or_empty_slot_not_dereferenced=True,destination_validity_from_caller_required=True)


def ordinary_rejection(tag):
    """Public error-discriminant model matching the saved engine decision."""
    s.require(type(tag) is int and 0<=tag<=255,'byte-sized error tag')
    adjusted=(tag-3) % (1<<64)
    return ((adjusted-4) % (1<<32))<4 or (adjusted % (1<<32))==2


def normal_paths(bodies,lane):
    names=symbols(bodies);body=bodies[names['resident']];checked={}
    if lane=='simd256':
        s.sequences(body,[
            '.B81:|addq $-3, %rax|leal -4(%rax), %ecx|cmpl $4, %ecx|'+
            'leaq 10792(%rbx), %r13|jb .B83|cmpl $2, %eax|jne .B34',
            '.B34:|leaq 6688(%rbx), %rcx|vzeroupper|callq '+names['workspace']+'|'+
            'movq 88(%rbx), %rax|movb $0, 16(%rax)|jmp .B84',
            '.B83:|leaq 6688(%rbx), %rcx|callq '+names['workspace'],
            '.B90:|leaq 3936(%rbx), %rcx|movl $256, %edx|callq '+s.ZERO+'|'+
            'leaq 6688(%rbx), %rcx|callq '+names['workspace']+'|movq %r13, %rcx|callq '+names['scalar']+'|'+
            'movq %r14, %rcx|callq '+names['cpu']+'|testb $1, %dil|je .B31|jmp .B32',
            '.B31:|movq 152(%rbx), %rsi|leaq 16(%rsi), %rcx|movl $256, %edx|callq '+s.ZERO+'|'+
            'movb $2, (%rsi)|movb $2, 280(%rsi)|movq 8(%rsi), %rax|movb $0, 16(%rax)',
            'leaq 3936(%rbx), %rcx|movl $256, %edx|callq '+s.ZERO+'|leaq 6688(%rbx), %rcx|'+
            'callq '+names['drop']+'|jmp .B32'])
        for label in ('.B34','.B83','.B90','.B251'):
            checked[label]=[s.normal_returns(body,label,event) for event in (
                ['leaq 3936(%rbx), %rcx','movl $256, %edx','callq '+s.ZERO],
                ['leaq 6688(%rbx), %rcx','callq '+names['workspace']])]
    else:
        s.sequences(body,[
            '.B68:|leaq 1376(%rbx), %rcx|movl $256, %edx|vzeroupper|callq '+s.ZERO+'|'+
            'leaq 7200(%rbx), %rcx|callq '+names['workspace']+'|movq %r12, %rcx|callq '+names['scalar']+'|'+
            'movq %r13, %rcx|callq '+names['cpu']+'|jmp .B27',
            'leaq 1376(%rbx), %rcx|movl $256, %edx|callq '+s.ZERO+'|leaq 7200(%rbx), %rcx|'+
            'callq '+names['drop']+'|jmp .B29'])
        for label in ('.B66','.B67','.B68','.B81'):
            checked[label]=[s.normal_returns(body,label,event) for event in (
                ['leaq 1376(%rbx), %rcx','movl $256, %edx','vzeroupper','callq '+s.ZERO],
                ['leaq 7200(%rbx), %rcx','callq '+names['workspace']])]
        executor=bodies[s.one(bodies,r'Executor13digest_secret$')]
        s.sequences(executor,[
            '.B1:|movzbl %r14b, %eax|addq $-3, %rax|leal -4(%rax), %ecx|cmpl $4, %ecx|'+
            'jb .B3|cmpl $2, %eax|jne .B13',
            '.B14:|movq %rdi, %rcx|vzeroupper|callq '+names['workspace']+'|movq 1048(%rbp), %rax|'+
            'movb $1, 16(%rax)|movq (%rax), %rax|testq %rax, %rax|je .B16|movb $0, 16(%rax)',
            '.B3:|movq %rdi, %rcx|vzeroupper|callq '+names['workspace']+'|jmp .B16'])
        for label in ('.B1','.B12','.B14'):
            checked['executor'+label]=[s.normal_returns(executor,label,event) for event in (
                ['movq %rdi, %rcx','vzeroupper','callq '+names['workspace']],
                ['movl $8, %edx','movq %rdi, %rcx','callq '+s.ZERO])]
    return dict(selected_error_returns=checked,ordinary_private_error_tags=[5,7,8,9,10],
        complete_error_entry_coverage_pending=True,success_storage_transfer_pending=True)


def worker_retirement(bodies,lane):
    narrow=lane=='simd256';body=bodies['RetainedWork']
    payload,header,owner_out,owner_phase,auth=(8192,288,16,280,8) if narrow else (4096,160,24,288,16)
    drop=s.one(bodies,r'drop_glue.*worker7BuffersE')
    clear=s.one(bodies,r'worker.*Buffers5clear$')
    expected=['pushq %rsi','subq $32, %rsp','movq %rcx, %rsi',f'addq ${payload}, %rcx',
        f'movl ${header}, %edx','callq '+s.ZERO,f'movl ${payload}, %edx','movq %rsi, %rcx',
        'addq $32, %rsp','popq %rsi','jmp '+s.ZERO]
    exact(bodies[drop],expected);exact(bodies[clear],expected)
    buffer_returns=s.normal_returns(body,'.B23',['leaq 64(%rsp), %rcx','callq '+drop])
    s.sequences(body,[f'movl ${payload+header}, %r8d|movq %rbx, %rcx|xorl %edx, %edx|'+
        'movq %r9, %rsi|callq memset',
        '.B31:|leaq 64(%rsp), %rcx|callq '+clear])
    live=set(re.findall(r'(_RNv\w+worker4LIVE)\(%rip\)',body))
    page=set(re.findall(r'(_RNv\w+worker9LIVE_PAGE\.0)\(%rip\)',body))
    s.require(len(live)==len(page)==1,'unique retained allocation and page identity')
    live=live.pop();page=page.pop()
    s.sequences(body,[f'cmpq %rdx, {page}(%rip)|jne '+('.B47' if narrow else '.B48')+'|'+
        'cmpq $3, %rcx|jne .B23',
        f'movq {live}+16(%rip), %rdi|movq $0, {live}(%rip)|leaq {owner_out}(%rdi), %rcx|'+
        'movl $256, %edx|callq '+s.ZERO+'|'+('movb $2, (%rdi)' if narrow else 'movw $-1, (%rdi)')+'|'+
        f'movb $2, {owner_phase}(%rdi)|movq {auth}(%rdi), %rax|movb $0, 16(%rax)|'+
        'xorl %eax, %eax|.p2align 4|.B21:'])
    loop='|'.join('movb $0, '+('' if i==0 else str(i))+'(%rsi,%rax)' for i in range(8))
    for label in ('.B16','.B21'):
        s.sequences(body,[label+':|'+loop+'|addq $8, %rax|cmpq $4096, %rax|jne '+label])
    retirement=s.normal_returns(body,'.B21',[f'movq $0, {page}(%rip)'])
    cancel_name=s.one(bodies,r'Resident6cancel$');cancel=bodies[cancel_name]
    operation=s.one(bodies,r'Owner9operation$')
    s.sequences(cancel,[f'movzbl {owner_phase}(%rcx), %r9d|cmpb $2, %r9b|jne .B2',
        '.B2:|movq %rdx, %r8|movq %rcx, %rdx|leaq 32(%rsp), %rcx|callq '+operation+'|'+
        'cmpb $2, 40(%rsp)|jne .B4',
        '.B4:|movq 32(%rsp), %rsi|'+f'leaq {owner_out}(%rsi), %rcx|movl $256, %edx|callq '+s.ZERO+'|'+
        ('movb $2, (%rsi)' if narrow else 'movw $-1, (%rsi)')+f'|movb $0, {owner_phase}(%rsi)|movb $-1, %al'])
    cancelled=s.normal_returns(cancel,'.B4',[f'leaq {owner_out}(%rsi), %rcx','movl $256, %edx','callq '+s.ZERO])
    return dict(worker_buffer_payload_bytes=payload,worker_buffer_header_bytes=header,
        postconstruction_returns_call_buffer_drop=buffer_returns,page_retirement_bytes=4096,
        retirement_clears_live_before_destroy=True,retirement_page_identity_clear_returns=retirement,
        admitted_cancel_clears_output_returns=cancelled,shared_window_reclamation_package=8,
        transport_admission_and_full_worker_composition_pending=True)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'saved SIMD storage lane')
    return dict(wiping=wiping(bodies,lane),output_drop=output_drop(bodies,lane),
        normal_cleanup=normal_paths(bodies,lane),worker_retirement=worker_retirement(bodies,lane),
        whole_frame_qualified=False)
