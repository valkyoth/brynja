"""Saved SIMD worker request/copy/export composition, not OS-copy qualification."""
import re
import windows_enclave_kmac_shapes as s


def identity(value,narrow):
    s.require(type(value) is int and 0<=value<1<<64,'wire identity is u64')
    if narrow: return {224:0,256:1}.get(value)
    # Emitted unsigned subtract/compare: named variants 512..515, or general t.
    offset=(value-512) % (1<<64)
    if offset<4: return offset
    if value==384 or offset<((1<<64)-511): return None
    return (value<<16)|4


def admitted_lane(lane,operation,code,length,last,source):
    s.require(lane in ('simd256','simd512'),'known worker lane')
    for value in (operation,code,length,last,source):
        s.require(type(value) is int and 0<=value<1<<64,'public wire u64')
    narrow=lane=='simd256';digest=100 if narrow else 90;block=64 if narrow else 128
    if operation==digest+2: return code==length==last==source==0
    if identity(code,narrow) is None: return False
    if operation==digest+1: return length==last==source==0
    return (operation==digest and block<=length<=1024 and 1<=last<=8 and
            (length!=block or last==8) and source!=0 and source+length<1<<64)


def role(bodies,suffix):
    return s.one(bodies,r'worker7receive$' if suffix=='receive' else suffix)


def admitted_window(page,low,high):
    for value in (page,low,high):
        s.require(type(value) is int and 0<=value<1<<64,'public address is u64')
    return (page!=0 and page%4096==0 and high-low==65536 and
            page+4096<1<<64 and (page+4096<=low or page>=high))


def entry(bodies,lane):
    narrow=lane=='simd256';body=bodies['RetainedWork']
    payload,header,fail,ready,done=(8192,288,42,43,45) if narrow else (4096,160,43,44,46)
    prefix='PublicSha'+('256' if narrow else '512')+'Simd'
    live=re.findall(r'movq (_RNv\w+worker4LIVE)\(%rip\), %rsi','\n'.join(s.lines(body)))
    s.require(live and len(set(live))==1,'one live metadata source');live=live[0]
    s.sequences(body,[
        'testq %rdx, %rdx|setne %al|testl $4095, %edx|sete %r10b|testb %r10b, %al|je .B1|'+
        'movq %r9, %rax|subq %r8, %rax|setb %r10b|cmpq $-4097, %rdx|ja .B1|'+
        'testb %r10b, %r10b|jne .B1|cmpq $65536, %rax|jne .B1|leaq 4096(%rdx), %rax|'+
        'cmpq %r8, %rax|seta %al|cmpq %rdx, %r9|seta %r10b|testb %r10b, %al|jne .B1|'+
        f'movq {live}(%rip), %rsi|testq %rcx, %rcx|je .B8|testq %rsi, %rsi|je .B11',
        f'.B23:|movq %r8, %r15|movq %rcx, %r14|leaq 64(%rsp), %rbx|movq %rbx, %rdi|'+
        f'subq $-{payload}, %rdi|setb %bpl|movl ${payload+header}, %r8d|'+
        'movq %rbx, %rcx|xorl %edx, %edx|movq %r9, %rsi|callq memset|movq %rsi, %rax|'+
        f'movl $204, %esi|cmpq %rax, %rdi|ja .B{fail}|testb %bpl, %bpl|je .B{fail}|'+
        f'cmpq %rbx, %r15|ja .B{fail}|cmpq $-{header+1}, %rdi|ja .B{fail}|cmpq %rdi, %r15|ja .B{fail}|'+
        f'leaq {64+payload+header}(%rsp), %rcx|cmpq %rax, %rcx|ja .B{fail}|'+
        'movq %r14, %rcx|leaq 64(%rsp), %rdx|callq '+role(bodies,'receive')+'|movl %eax, %ebx|'+
        'testb %al, %al|jne .B31'])
    # These are read-only zero checks after buffer clearing; their complete index
    # ranges include every byte, including the narrow payload's final short group.
    s.sequences(body,[f'movl ${payload+3}, %eax|movl $205, %esi|.B32:|cmpq ${payload+header+3}, %rax|je .B33|'+
        '|'.join(f'cmpb $0, {offset}(%rsp,%rax)|jne .B{fail}' for offset in (61,62,63))+
        '|cmpb $0, 64(%rsp,%rax)|leaq 4(%rax), %rax|je .B32'])
    if narrow:
        s.sequences(body,['.B33:|movl $2, %eax|movl $205, %esi|.B34:|'+
            f'cmpb $0, 62(%rsp,%rax)|jne .B{fail}|cmpb $0, 63(%rsp,%rax)|jne .B{fail}|'+
            f'cmpq $8192, %rax|je .B{ready}|cmpb $0, 64(%rsp,%rax)|leaq 3(%rax), %rax|je .B34|jmp .B{fail}'])
    else:
        s.sequences(body,['.B33:|movl $3, %eax|movl $205, %esi|.B34:|cmpq $4099, %rax|je .B44|'+
            '|'.join(f'cmpb $0, {offset}(%rsp,%rax)|jne .B{fail}' for offset in (61,62,63))+
            '|cmpb $0, 64(%rsp,%rax)|leaq 4(%rax), %rax|je .B34|jmp .B43'])
    s.sequences(body,[f'.B{ready}:|leaq 64(%rsp), %rdx|movl $1, %r8d|movq %rdi, %rcx|callq {prefix}Observe|'+
        ('' if narrow else 'movl $205, %esi|')+f'cmpl $1, %eax|jne .B{fail}|'+
        'movabsq $4294967296, %rax|orq %rax, %r14|testb %bl, %bl|movl $206, %esi|'+
        f'cmovneq %r14, %rsi|jmp .B{done}'])
    return dict(page_bytes=4096,page_alignment=4096,worker_window_bytes=65536,
        page_window_disjoint=True,buffer_ranges_checked_before_receive=True,
        cleanup_receipt_covers_all_buffer_bytes=True,host_reentrancy_and_page_lifetime_package=8)


def decode(bodies,lane):
    narrow=lane=='simd256';body=bodies[role(bodies,'receive')]
    start,header,payload,version,digest,fail,end=(368,288,8192,21,100,26,27) if narrow else (224,160,4096,20,90,27,28)
    prefix='PublicSha'+('256' if narrow else '512')+'Simd'
    s.sequences(body,[
        'movq %rdx, %rsi|movq %rcx, %rdi|callq '+prefix+'Source|'+f'leaq {payload}(%rsi), %r14|'+
        f'xorl %ebx, %ebx|movl ${header}, %r9d|xorl %ecx, %ecx|movq %r14, %rdx|movq %rax, %r8|'+
        f'callq {prefix}Input|testl %eax, %eax|jne .B{end}',
        f'cmpq ${version}, {start}(%rsp)|jne .B{fail}|movq {start+8}(%rsp), %rax|testq %rax, %rax|'+
        f'je .B{fail}|cmpq $2, {start+24}(%rsp)|jne .B{fail}|leaq -{digest+1}(%rdi), %rcx|'+
        f'cmpq $2, %rcx|jae .B7|cmpq $0, {start+16}(%rsp)|jne .B{fail}|xorl %ecx, %ecx|jmp .B9|'+
        f'.B7:|cmpq ${digest}, %rdi|jne .B{fail}|movq {start+16}(%rsp), %rcx',
        f'.B10:|vmovdqu {start}(%rsp,%rcx), %ymm0|vptest %ymm0, %ymm0|jne .B{fail}|'+
        f'.B11:|addq $32, %rcx|incq %rdx|addq $4, %rax|je .B{25 if narrow else 29}|'+
        f'.B12:|cmpq ${digest+2}, %rdi|je .B10'])
    if narrow:
        s.sequences(body,[
            'movq $-32, %rax|movl $32, %ecx|xorl %edx, %edx|jmp .B12',
            'movq 664(%rsp,%rax,8), %r10|movq 672(%rsp,%rax,8), %r9|movq 680(%rsp,%rax,8), %r8|'+
            'movq 656(%rsp,%rax,8), %r11|cmpq $224, %r11|je .B16|cmpq $256, %r11|jne .B26|'+
            'movb $1, %r11b|jmp .B17|.B16:|xorl %r11d, %r11d|.B17:|movb %r11b, 48(%rsp,%rdx)',
            'cmpq $101, %rdi|jne .B19|orq %r10, %r8|orq %r9, %r8|je .B11|jmp .B26'])
    else:
        s.sequences(body,[
            'movq $-16, %rax|movl $32, %ecx|xorl %edx, %edx|jmp .B12',
            'movq 384(%rsp,%rax,8), %r11|movq 392(%rsp,%rax,8), %r10|'+
            'movq 400(%rsp,%rax,8), %r9|movq 408(%rsp,%rax,8), %r8|'+
            'leaq -512(%r11), %rbx|cmpq $4, %rbx|jae .B15|movl %ebx, %r11d|jmp .B18|'+
            '.B15:|cmpq $384, %r11|je .B27|cmpq $-511, %rbx|jb .B27|shll $16, %r11d|orl $4, %r11d|'+
            '.B18:|cmpw $-1, %r11w|je .B27|movl %r11d, 96(%rsp,%rax)|'+
            'cmpq $91, %rdi|jne .B21|orq %r10, %r8|orq %r9, %r8|je .B11|jmp .B27'])
    block=64 if narrow else 128
    s.sequences(body,[f'.B{19 if narrow else 21}:|leaq -{block}(%r10), %r11|cmpq ${1024-block}, %r11|'+
        f'ja .B{fail}|leaq -1(%r9), %r11|cmpq $7, %r11|ja .B{fail}|cmpq ${block}, %r10|'+
        'sete %bl|cmpq $8, %r9|setne %bpl|movq %r8, %r11|addq %r10, %r11|setb %r11b|'+
        f'testb %bpl, %bl|jne .B{fail}|testq %r8, %r8|je .B{fail}|testb %r11b, %r11b|jne .B{fail}'])
    return dict(version=version,header_bytes=header,lanes=8 if narrow else 4,
        lane_capacity=1024,nonzero_sequence=True,exact_command_budget_rules=True,
        identities_checked=True,minimum_complete_block=block,last_bits_range=[1,8],
        opaque_host_pointer_nonzero_and_nonwrapping=True,os_copy_implementation_package=8)


def input_copies(bodies,lane):
    narrow=lane=='simd256';body=bodies[role(bodies,'receive')]
    prefix='PublicSha'+('256' if narrow else '512')+'Simd'
    if narrow:
        for index in range(8):
            code=[f'movq {72+8*index}(%rsp), %r9','cmpq $1024, %r9','ja .B26']
            if index==0: code += ['movq 144(%rsp), %r8','movl $1, %ecx','movq %rsi, %rdx','vzeroupper']
            else: code += [f'leaq {1024*index}(%rsi), %rdx',f'movq {144+8*index}(%rsp), %r8',f'movl ${index+1}, %ecx']
            s.sequences(body,['|'.join(code)+f'|callq {prefix}Input|testl %eax, %eax|jne .B26'])
        build=role(bodies,r'try_from_fn.*worker7receive');helper=bodies[build]
        regs=('r8','rbx','rdi','rsi','r11','r14','r9','rax')
        checks=['movq 8(%rdx), %rax','movq (%rax), %r8','cmpq $1025, %r8','jae .B15']
        for index,reg in enumerate(regs[1:],1):
            checks += [f'movq {8*index}(%rax), %{reg}',f'cmpq $1024, %{reg}',f'ja .B{2*index}']
        s.sequences(helper,['|'.join(checks)])
        s.sequences(body,['leaq 72(%rsp), %rax|leaq 136(%rsp), %rcx|leaq 48(%rsp), %rdx|'+
            'movq %rdx, 208(%rsp)|movq %rax, 216(%rsp)|movq %rcx, 224(%rsp)|movq %rsi, 232(%rsp)|'+
            'leaq 368(%rsp), %rsi|leaq 208(%rsp), %rdx|movq %rsi, %rcx|callq '+build])
        s.sequences(helper,['movq 24(%rdx), %rdx|movq %rdx, (%rcx)'])
        for index,reg in ((1,'r15'),(2,'rax'),(3,'rax'),(4,'rax'),(5,'rax'),(6,'rax')):
            s.sequences(helper,[f'leaq {index*1024}(%rdx), %{reg}|movq %{reg}, {index*24}(%rcx)'])
        s.sequences(helper,['addq $7168, %rdx|movq %rdx, 168(%rcx)'])
        suffix='leaq 208(%rsp), %rcx|movq %rsi, %r9|callq '
    else:
        s.sequences(body,[
            '.B37:|movq 112(%rsp), %r15|cmpq $1024, %r15|ja .B27',
            'movq 120(%rsp), %rdi|movq 128(%rsp), %rax|movq %rax, 64(%rsp)|'+
            'movq 136(%rsp), %rax|movq %rax, 48(%rsp)',
            'movl $1, %ecx|movq %rsi, %rdx|movq %r15, %r9|vzeroupper|'+
            f'callq {prefix}Input|testl %eax, %eax|jne .B27',
            'movq 72(%rsp), %r8|cmpq $1024, %rdi|ja .B27|leaq 1024(%rsi), %rdx|movl $2, %ecx|'+
            f'movq %rdx, 184(%rsp)|movq %rdi, %r9|callq {prefix}Input|testl %eax, %eax|jne .B27'])
        for index,length,pointer,source in ((2,64,72,56),(3,48,56,216)):
            end='jne .B27' if index==2 else 'je .B72'
            s.sequences(body,[f'cmpq $1024, {length}(%rsp)|ja .B27|leaq {index*1024}(%rsi), %rdx|'+
                f'movl ${index+1}, %ecx|movq %rdx, {pointer}(%rsp)|movq {source}(%rsp), %r8|'+
                f'movq {length}(%rsp), %r9|callq {prefix}Input|testl %eax, %eax|'+end])
        s.sequences(body,['.B72:|movq %rsi, 224(%rsp)|movq %r15, 232(%rsp)',
            'movq 184(%rsp), %rax|movq %rax, 248(%rsp)|movq %rdi, 256(%rsp)',
            'movq 72(%rsp), %rax|movq %rax, 272(%rsp)|movq 64(%rsp), %rax|movq %rax, 280(%rsp)',
            'movq 56(%rsp), %rax|movq %rax, 296(%rsp)|movq 48(%rsp), %rax|movq %rax, 304(%rsp)'])
        suffix='leaq 80(%rsp), %rcx|leaq 224(%rsp), %r9|movq 208(%rsp), %r8|callq '
    s.sequences(body,[suffix+role(bodies,r'Resident6digest$')])
    calls=[line for line in s.lines(body) if line==f'callq {prefix}Input']
    s.require(len(calls)==(9 if narrow else 5),'header plus exact input-copy population')
    return dict(exclusive_lane_stride=1024,lanes=8 if narrow else 4,
        host_addresses_used_only_by_copy_adapter=True,digest_receives_private_lane_pointers=True,
        narrow_slice_failstop_precluded_by_unchanged_validated_lengths=narrow,
        transport_synchronous_no_reentrancy_contract_required=True)


def export(bodies,lane):
    narrow=lane=='simd256';body=bodies[role(bodies,'receive')]
    out,phase,auth,failed,success,done=(16,280,8,62,65,27) if narrow else (24,288,16,56,73,28)
    prefix='PublicSha'+('256' if narrow else '512')+'Simd'
    s.sequences(body,['movb $1, %r9b|vzeroupper|callq '+role(bodies,r'Owner9operation$')])
    if narrow:
        s.sequences(body,['movzbl 376(%rsp), %ebx|cmpb $2, %bl|je .B26|movq 368(%rsp), %rdi|'+
            'movzbl (%rdi), %eax|cmpb $2, %al|sete %cl|cmpb %sil, %al|setne %al|orb %cl, %al|jne .B62'])
        for index in range(1,8):
            instructions=(['movl %esi, %eax',f'shrl ${index*8}, %eax'] if index<4 else
                ['movq %rsi, %rax',f'shrq ${index*8}, %rax'] if index<7 else ['shrq $56, %rsi'])
            reg='sil' if index==7 else 'al'
            s.sequences(body,['|'.join(instructions)+f'|cmpb %{reg}, {index}(%rdi)|jne .B62'])
    else:
        s.sequences(body,['movzbl 232(%rsp), %r15d|cmpb $2, %r15b|je .B27|movq 224(%rsp), %rdi|'+
            'movzwl (%rdi), %eax|cmpw $-1, %ax|je .B56|cmpw %bp, %ax|jne .B56|'+
            'cmpw $4, %bp|jne .B45|cmpw %r14w, 2(%rdi)|jne .B56',
            '.B45:|cmpw %bx, 4(%rdi)|jne .B56|cmpw $4, %bx|jne .B48|cmpw %r13w, 6(%rdi)|jne .B56',
            '.B48:|cmpw %r12w, 8(%rdi)|jne .B56|cmpw $4, %r12w|jne .B51|cmpw %si, 10(%rdi)|jne .B56',
            '.B51:|movzwl 42(%rsp), %eax|cmpw %ax, 12(%rdi)|jne .B56|cmpw $4, 42(%rsp)|'+
            'jne .B54|movzwl 44(%rsp), %eax|cmpw %ax, 14(%rdi)|jne .B56'])
    s.sequences(body,[f'leaq {out}(%rdi), %rsi|movl $256, %edx|movq %rsi, %rcx|callq {prefix}Output|'+
        f'testl %eax, %eax|jne .B{failed}|movq {auth}(%rdi), %rcx|callq '+role(bodies,r'^_RNvCs.*simd5check$')+
        f'|cmpb $-1, %al|je .B{success}'])
    invalid='movb $2, (%rdi)' if narrow else 'movw $-1, (%rdi)'
    s.sequences(body,[f'.B{failed}:|testb $1, '+('%bl' if narrow else '%r15b')+
        f'|jne .B{26 if narrow else 27}|leaq {out}(%rdi), %rcx|movl $256, %edx|callq '+s.ZERO+'|'+
        invalid+f'|movb $2, {phase}(%rdi)|movq {auth}(%rdi), %rax|movb $0, 16(%rax)|jmp .B{26 if narrow else 27}',
        f'.B{success}:|movl $256, %edx|movq %rsi, %rcx|callq '+s.ZERO+'|'+invalid+
        f'|movb $0, {phase}(%rdi)|movb $1, %bl|jmp .B{done}'])
    returns=s.normal_returns(body,f'.B{success}',['movl $256, %edx','movq %rsi, %rcx','callq '+s.ZERO])
    return dict(plan_identities=8 if narrow else 4,general_t_parameters_compared=not narrow,
        retained_phase_required=True,copy_width=256,revalidate_after_copy=True,
        successful_export_clears_before_return=returns,armed_failure_clears_and_quarantines=True,
        public_copy_transactionality_assigned_to_transport=True)


def inspect(bodies,lane):
    return dict(entry=entry(bodies,lane),request=decode(bodies,lane),input_copies=input_copies(bodies,lane),export=export(bodies,lane),
                digest_engine_and_enclosing_frame_review_pending=True)
