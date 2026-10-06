"""Saved SIMD digest caller admission and retained-output lifetime contracts.

These compose private callers with reviewed cleanup routines. They do not yet
close the inner lane engine, generic aliasing, or shared runtime/window cleanup.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_storage as storage


def admission_bits(length,last,tail):
    s.require(all(type(v) is int for v in (length,last,tail)) and
              0<=length<(1<<64) and 0<=last<=255 and 0<=tail<=255,'typed input geometry')
    if length>1024: return None
    if length==0: return 0 if last==0 else None
    if ((last-1)&255)>7: return None
    if last<=7 and tail&(255>>last): return None
    return (last+8*length-8)


def output_width(tag,parameter=0):
    s.require(type(tag) is int and 0<=tag<5 and type(parameter) is int and
              0<=parameter<65536,'typed SHA-512 family identity')
    bits=(384,512,224,256,parameter)[tag]
    # Valid Algorithm::General values additionally come from the reviewed
    # worker decoder. The private width computation itself only bounds storage.
    return (bits>>3)+int((bits&7)>=1)


def admission(bodies,lane):
    narrow=lane=='simd256';names=storage.symbols(bodies);body=bodies[names['resident']]
    mask=s.one(bodies,r'12mask_is_zero$');operation=s.one(bodies,r'Owner9operation$')
    frame,workspace,owner,flag,end=(11992,6688,152,55,32) if narrow else (12984,7200,64,54,29)
    s.sequences(body,[f'movl ${frame}, %eax|callq __chkstk|subq %rax, %rsp|.seh_stackalloc {frame}|'
        'leaq 128(%rsp), %rbp|.seh_setframe %rbp, 128|.seh_endprologue|andq $-32, %rsp|movq %rsp, %rbx',
        f'movq %r9, %rdi|movq %rcx, %rsi|leaq {workspace}(%rbx), %rcx|xorl %r9d, %r9d|callq '+operation+'|'
        f'movzbl {workspace+8}(%rbx), %eax|cmpb $2, %al|jne .B2|movzbl {workspace}(%rbx), %eax|'
        f'movb %al, (%rsi)|movb $-1, 24(%rsi)|jmp .B{end}',
        f'movq {workspace}(%rbx), %rax|movq %rax, {owner}(%rbx)',
        f'movb %al, {flag}(%rbx)'])
    # Success of operation() always yields an armed, initially false flag.
    s.sequences(bodies[operation],['movq %rbx, (%rsi)|movb $0, 8(%rsi)'])
    length,source=('rsi','r13') if narrow else ('r13','r12')
    if narrow:
        s.sequences(body,['leaq 576(%rbx), %r12|'+'|'.join(f'movb $2, {576+40*i}(%rbx)' for i in range(8)),
            'movl $17, %r15d|jmp .B5',
            '.B5:|cmpq $209, %r15|je .B14|movq -9(%rdi,%r15), %rsi|cmpq $1024, %rsi|ja .B27|'
            'movq -17(%rdi,%r15), %r13|movzbl -1(%rdi,%r15), %r14d'])
        target='.B4:|movzbl (%rdi,%r15), %edx|movq %r13, -32(%r12)|movb %sil, -24(%r12)|'
        target+='movl %ecx, -23(%r12)|movq %rcx, %r8|shrq $48, %r8|movb %r8b, -17(%r12)|'
        target+='shrq $32, %rcx|movw %cx, -19(%r12)|movq %rax, -16(%r12)|movb %r14b, -8(%r12)|'
        target+='movb %dl, (%r12)|addq $24, %r15|addq $40, %r12'
    else:
        s.sequences(body,['|'.join(f'movw $-1, {224+40*i}(%rbx)' for i in range(4))+'|addq $20, %rdi',
            'movl $34, %r15d|jmp .B5',
            '.B5:|cmpq $194, %r15|je .B14|movq -12(%rdi), %r13|cmpq $1024, %r13|ja .B24|'
            'movq -20(%rdi), %r12|movzbl (%rdi), %r14d'])
        target='.B4:|movl -4(%rdi), %edx|movq %r12, 158(%rbx,%r15)|movb %r13b, 166(%rbx,%r15)|'
        target+='movl %ecx, 167(%rbx,%r15)|movq %rcx, %r8|shrq $48, %r8|movb %r8b, 173(%rbx,%r15)|'
        target+='shrq $32, %rcx|movw %cx, 171(%rbx,%r15)|movq %rax, 174(%rbx,%r15)|'
        target+='movb %r14b, 182(%rbx,%r15)|movl %edx, 190(%rbx,%r15)|addq $24, %rdi|addq $40, %r15'
    s.sequences(body,[target,
        f'testq %{length}, %{length}|je .B11|leal -1(%r14), %eax|cmpb $7, %al|ja .B13|'
        f'cmpb $7, %r14b|ja .B3|leaq -1(%{length}), %rax|movb $-1, %dl|movl %r14d, %ecx|'
        f'shrb %cl, %dl|addq %{source}, %rax|movq %rax, %rcx|callq '+mask+'|'
        'cmpl $1, %eax|je .B3|jmp .B13',
        f'.B3:|movzbl %r14b, %eax|leaq (%rax,%{length},8), %rax|addq $-8, %rax|'
        f'movq %{length}, %rcx|shrq $8, %rcx',
        '.B11:|testb %r14b, %r14b|jne .B13|'+
        f'xorl %{ "esi" if narrow else "r13d"}, %{ "esi" if narrow else "r13d"}|'
        'xorl %ecx, %ecx|xorl %eax, %eax|xorl %r14d, %r14d|jmp .B4'])
    out,phase,auth=(16,280,8) if narrow else (24,288,16)
    clear=[f'movq {owner}(%rbx), %rsi',f'leaq {out}(%rsi), %rcx','movl $256, %edx','callq '+s.ZERO]
    clear += [('movb $2' if narrow else 'movw $-1')+', (%rsi)',f'movb $2, {phase}(%rsi)',
              f'movq {auth}(%rsi), %rax','movb $0, 16(%rax)']
    guard=(f'movzbl {flag}(%rbx), '+('%edi|testb $1, %dil' if narrow else '%eax|testb $1, %al')+f'|jne .B{end}')
    s.sequences(body,[guard+('|.B31:' if narrow else '')+'|'+'|'.join(clear)])
    # The only write to this saved guard flag is the successful operation result.
    writes=[l for l in s.lines(body) if l.endswith(f', {flag}(%rbx)')]
    s.require(writes==[f'movb %al, {flag}(%rbx)'],'armed operation flag has no later normal-path store')
    armed='\n'.join(s.lines(body)).replace(guard.replace('|','\n'),guard.rsplit('|',1)[0].replace('|','\n')+'\nnop')
    rejects={label:s.normal_returns(armed,label,clear) for label in
             (('.B13','.B27','.B29') if narrow else ('.B13','.B24','.B25'))}
    return dict(input_lanes=8 if narrow else 4,input_stride=24,internal_input_stride=40,
        internal_input_offset=544 if narrow else 192,maximum_bytes_per_lane=1024,
        canonical_low_bits_checked=True,empty_requires_zero_tail=True,maximum_bit_count=8192,
        armed_pre_workspace_failures_clear_owner=rejects,operation_flag_offset=flag,
        caller_valid_private_slice_and_enum_required=True,private_frame_allocation=frame)


def staging(bodies,lane):
    narrow=lane=='simd256';body=bodies[storage.symbols(bodies)['resident']]
    if narrow:
        # Preserve the eight typed input identities, rather than reconstructing
        # the retained plan from outputs supplied by a generic callback.
        s.sequences(body,[
            'movzbl 17(%rdi), %r10d|movzbl 41(%rdi), %r9d|movb %r9b, 104(%rbx)|'
            'movzbl 65(%rdi), %ecx|movb %cl, 56(%rbx)|movzbl 89(%rdi), %edx|movb %dl, 80(%rbx)|'
            'movzbl 161(%rdi), %eax|movzbl 185(%rdi), %r8d|shlq $56, %r8|shlq $48, %rax|'
            'orq %r8, %rax|movzbl 113(%rdi), %r8d|shll $24, %edx|shll $8, %r9d|'
            'movq %r10, 96(%rbx)|orq %r10, %r9|orq %rdx, %r9|movzbl 137(%rdi), %edx|'
            'shll $16, %ecx|orq %rcx, %r9|movq %r8, 72(%rbx)|movq %r8, %rcx|shlq $32, %rcx|'
            'orq %rcx, %r9|movq %rdx, 128(%rbx)|movq %rdx, %rcx|shlq $40, %rcx|orq %rcx, %r9',
            'orq %rax, %r9|movq %r9, 312(%rbx)',
            'leaq 3936(%rbx), %r14|movl $2752, %r8d|movq %rsi, %rcx|movq %r14, %rdx|vzeroupper|callq memcpy'])
        seq=[]
        for i,field in enumerate((96,104,56,80,72,128)):
            seq += (['movq %r14, 864(%rbx)'] if i==0 else
                    [f'leaq {3936+32*i}(%rbx), %rax',f'movq %rax, {864+16*i}(%rbx)'])
            seq += [f'movzbl {field}(%rbx), %eax','leaq 28(,%rax,4), %rax',f'movq %rax, {872+16*i}(%rbx)']
        for i in (6,7):
            seq += [f'leaq {3936+32*i}(%rbx), %rax',f'movq %rax, {864+16*i}(%rbx)']
            if i==6: seq += ['movq 312(%rbx), %rcx']
            seq += ['movq %rcx, %rax',f'shrq ${8*i}, %rax','andl $1, %eax',
                    'leaq 28(,%rax,4), %rax',f'movq %rax, {872+16*i}(%rbx)']
        seq += ['vxorps %xmm0, %xmm0, %xmm0']
        seq += [f'vmovaps %ymm0, {at}(%rbx)' for at in range(4160,3935,-32)]
        seq += ['movq $0, 992(%rbx)']
        s.sequences(body,['|'.join(seq)])
    else:
        s.sequences(body,[
            'movzwl 16(%rdi), %eax|movzwl 18(%rdi), %ecx|movw %cx, 62(%rbx)|movw %ax, 84(%rbx)|'
            'movzwl %ax, %eax|movl %eax, 116(%rbx)|movzwl 40(%rdi), %eax|movw %ax, 82(%rbx)|'
            'movzwl %ax, %eax|movl %eax, 112(%rbx)|movzwl 42(%rdi), %eax|movw %ax, 60(%rbx)|'
            'movzwl 64(%rdi), %eax|movzwl 66(%rdi), %ecx|movw %cx, 58(%rbx)|'
            'movzwl 88(%rdi), %ecx|movzwl 90(%rdi), %edx|movw %dx, 56(%rbx)',
            'addq $20, %rdi|movw %ax, 80(%rbx)|movzwl %ax, %eax|movl %eax, 108(%rbx)|'
            'movw %cx, 78(%rbx)|movzwl %cx, %eax|movl %eax, 104(%rbx)',
            'leaq 1376(%rbx), %r14|movl $3264, %r8d|movq %r13, %rcx|movq %r14, %rdx|vzeroupper|callq memcpy|'
            'vxorps %xmm0, %xmm0, %xmm0|'+'|'.join(f'vmovaps %ymm0, {at}(%rbx)' for at in range(1600,1375,-32)),
            'movzwl %ax, %eax|movzwl %cx, %ecx|movzwl %dx, %edx|leaq 1440(%rbx), %r9|'
            'leaq 1504(%rbx), %r10|leaq 1568(%rbx), %r11|movzwl %r8w, %r8d',
            'movq %r14, 352(%rbx)|movq %rax, 360(%rbx)|movq %r9, 368(%rbx)|movq %rcx, 376(%rbx)|'
            'movq %r10, 384(%rbx)|movq %rdx, 392(%rbx)|movq %r11, 400(%rbx)|movq %r8, 408(%rbx)'])
    return dict(scratch_offset=3936 if narrow else 1376,scratch_bytes=256,
        descriptor_offset=864 if narrow else 352,descriptor_stride=16,
        slots=8 if narrow else 4,slot_bytes=32 if narrow else 64,
        scratch_zeroed_before_secret_output=True,plan_preserved_from_typed_inputs=True,
        inner_engine_must_preserve_destination_provenance=True)


def wide_widths(bodies,assembly=None):
    body=bodies[s.one(bodies,r'Resident6digest$')];tables={}
    for index,(first,merge,param,reg32,reg16) in enumerate(((23,35,62,'ecx','cx'),
            (37,42,60,'edx','dx'),(44,49,58,'r8d','r8w'),(51,56,56,'r9d','r9w'))):
        labels=(first,merge-1,merge-3,merge-2,merge-4)
        for label,width in zip(labels[:4],(384,512,224,256)):
            s.sequences(body,[f'.B{label}:|movw ${width}, %{reg16}'+('' if label==merge-1 else f'|jmp .B{merge}')])
        load=('eax','ecx','edx','r8d')[index]
        s.sequences(body,[f'.B{merge-4}:|movzwl {param}(%rbx), %{load}|movl %{load}, %{reg32}|jmp .B{merge}'])
        result=('eax','ecx','edx','r8d')[index];result16=('ax','cx','dx','r8w')[index]
        s.sequences(body,[f'.B{merge}:|movzwl %{reg16}, %{result}|shrl $3, %{result}|andl $7, %{reg32}|'
            f'cmpw $1, %{reg16}|sbbw $-1, %{result16}|'+
            (f'cmpw $64, %{result16}|ja .B66' if index<3 else 'cmpw $65, %r8w|jae .B66')])
        name=f'.LJTI35_{index}';tables[name]=list(labels)
        if assembly is not None:
            rows=re.findall(r'^'+re.escape(name)+r':\n((?:\s*\.long\s+[^\n]+\n)+)',assembly,re.M)
            s.require(len(rows)==1,'unique SIMD output-width dispatch table')
            s.require(re.findall(r'\.long\s+([^\s]+)',rows[0])==[
                f'.LBB35_{label}-{name}' for label in labels],'exact SIMD output-width variant dispatch')
    return tables


def output_copies(bodies,lane):
    narrow=lane=='simd256';names=storage.symbols(bodies);body=bodies[names['resident']]
    copy=s.one(bodies,r'secret_memory18copy_secret_region$');check=s.one(bodies,r'^_RNvCs.*simd5check$')
    if narrow:
        s.sequences(body,[
            '.B143:|leaq 2920(%rbx), %rax|movq %rax, 176(%rbx)',
            '.B261:|movl $16, %esi|.B262:|cmpq $272, %rsi|je .B266|movq 176(%rbx), %rax|'
            'movq -8(%rax), %r8|testq %r8, %r8|je .B269|movq 176(%rbx), %rax|'
            'movq (%rax), %rdx|cmpq $32, %rdx|ja .B270|movq 152(%rbx), %rax|'
            'leaq (%rax,%rsi), %rcx|movq %rdx, %r9|callq '+copy+'|movl %eax, %ecx|'
            'addq $32, %rsi|addq $16, 176(%rbx)|movb $7, %al|cmpb $-1, %cl|je .B262|jmp .B251',
            '.B269:|movb $2, %al|jmp .B251|.B270:|movb $3, %al|jmp .B251',
            '.B266:|movq 3040(%rbx), %rax|movq %rax, 992(%rbx)|'+
            '|'.join(f'vmovups {2912+32*i}(%rbx), %ymm{i}' for i in range(4))+'|'+
            '|'.join(f'vmovaps %ymm{i}, {864+32*i}(%rbx)' for i in range(3,-1,-1))+'|'
            'leaq 864(%rbx), %rcx|vzeroupper|callq '+names['output']+'|movq 152(%rbx), %rax|'
            'movq 8(%rax), %rcx|movb $0, 71(%rbx)|.Ltmp66:|callq '+check+'|nop|.Ltmp67:|'
            'cmpb $-1, %al|je .B271|movq 160(%rbx), %rcx|movb %al, (%rcx)|movb $-1, 24(%rcx)|jmp .B257',
            '.B271:|movq 152(%rbx), %rax|movq 312(%rbx), %rcx|movq %rcx, (%rax)|movb $1, 280(%rax)',
            '.B251:|movq 160(%rbx), %rcx|movb %al, (%rcx)|movb $-1, 24(%rcx)|xorl %esi, %esi|'
            'cmpq $128, %rsi|jne .B253|jmp .B256|.B252:|addq $16, %rsi|cmpq $128, %rsi|je .B256|'
            '.B253:|movq 2912(%rbx,%rsi), %rcx|testq %rcx, %rcx|je .B252|movq 2920(%rbx,%rsi), %rdx|'
            'testq %rdx, %rdx|je .B252|vzeroupper|callq '+s.ZERO+'|addq $16, %rsi|cmpq $128, %rsi|jne .B253|'
            '.B256:|leaq 3040(%rbx), %rcx|movl $8, %edx|vzeroupper|callq '+s.ZERO])
        drop=['leaq 864(%rbx), %rcx','vzeroupper','callq '+names['output']]
        alternative=['leaq 3040(%rbx), %rcx','movl $8, %edx','vzeroupper','callq '+s.ZERO]
        start='.B261';scratch=3936;work=6688;exit_label=32;published='.B271'
    else:
        s.sequences(body,[
            '.Ltmp73:|cmpb $-1, %al|jne .B81|movq 352(%rbx), %r8|testq %r8, %r8|je .B80|'
            'movq 360(%rbx), %rdx|cmpq $64, %rdx|jbe .B70|.B65:|movb $3, %al|jmp .B81',
            '.B70:|movq 64(%rbx), %rax|leaq 24(%rax), %rcx|movq %rdx, %r9|callq '+copy+'|'
            'cmpb $-1, %al|je .B72|.B71:|movb $7, %al|jmp .B81'])
        for i in (1,2):
            s.sequences(body,[(('.B72:|' if i==1 else '')+f'movq {352+16*i}(%rbx), %r8|'
                f'testq %r8, %r8|je .B80|movq {360+16*i}(%rbx), %rdx|cmpq $64, %rdx|ja .B65|'
                f'movq 64(%rbx), %rax|leaq {24+64*i}(%rax), %rcx|movq %rdx, %r9|callq '+copy+'|'
                'cmpb $-1, %al|jne .B71')])
        s.sequences(body,['movq 400(%rbx), %r8|testq %r8, %r8|movb $2, %al|je .B81|'
            'movq 408(%rbx), %rdx|movb $3, %al|cmpq $64, %rdx|ja .B81|movq 64(%rbx), %rax|'
            'leaq 216(%rax), %rcx|movq %rdx, %r9|callq '+copy+'|movl %eax, %ecx|movb $7, %al|'
            'cmpb $-1, %cl|jne .B81|movq 416(%rbx), %rax|movq %rax, 4704(%rbx)|'
            'vmovups 352(%rbx), %ymm0|vmovups 384(%rbx), %ymm1|vmovaps %ymm1, 4672(%rbx)|'
            'vmovaps %ymm0, 4640(%rbx)|leaq 4640(%rbx), %rcx|vzeroupper|callq '+names['output']+'|'
            'movq 64(%rbx), %rax|movq 16(%rax), %rcx|movb $0, 55(%rbx)|.Ltmp74:|callq '+check+'|'
            'nop|.Ltmp75:|cmpb $-1, %al|je .B90|movb %al, (%rsi)|jmp .B67',
            '.B80:|movb $2, %al|.B81:|movb %al, (%rsi)|movb $-1, 24(%rsi)|'
            'leaq 352(%rbx), %rcx|vzeroupper|callq '+names['output']+'|jmp .B68',
            '.B90:|movq 64(%rbx), %rax|'+ '|'.join(
                f'movzwl {off}(%rbx), %ecx|movw %cx, '+(f'{2*i}' if i else '')+'(%rax)'
                for i,off in enumerate((84,62,82,60,80,58,78,56)))+'|movb $1, 288(%rax)'])
        drop=['leaq 4640(%rbx), %rcx','vzeroupper','callq '+names['output']]
        alternative=['leaq 352(%rbx), %rcx','vzeroupper','callq '+names['output']]
        start='.Ltmp73';scratch=1376;work=7200;exit_label=29;published='.B90'
    wiped=[f'leaq {scratch}(%rbx), %rcx','movl $256, %edx','callq '+s.ZERO]
    returns=dict(output=s.normal_returns(body,start,drop,[alternative]),
        scratch=s.normal_returns(body,start,wiped,[wiped[:2]+['vzeroupper',wiped[2]]]),
        workspace=s.normal_returns(body,start,[f'leaq {work}(%rbx), %rcx','callq '+names['workspace']],
                                   [[f'leaq {work}(%rbx), %rcx','callq '+names['drop']]]))
    s.sequences(body,['|'.join(wiped)+f'|leaq {work}(%rbx), %rcx|callq '+names['drop']+f'|jmp .B{exit_label}'])
    s.normal_returns(body,published,wiped)
    return dict(lanes=8 if narrow else 4,retained_slot_bytes=32 if narrow else 64,
        copied_width_bounded=True,missing_slot_rejected=True,output_drop_before_final_revalidation=True,
        plan_and_retained_phase_published_after_revalidation=True,all_returns_after_result_admission=returns,
        scratch_bytes=256,inner_engine_result_pointer_provenance_pending=True)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'saved SIMD digest caller')
    return dict(admission=admission(bodies,lane),staging=staging(bodies,lane),output=output_copies(bodies,lane),
        wide_output_tables=wide_widths(bodies) if lane=='simd512' else None,
        complete_inner_lane_engine_qualified=False,whole_frame_erasure_qualified=False)
