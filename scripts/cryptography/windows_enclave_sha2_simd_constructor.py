"""Public startup KAT and placement in two frozen Windows SIMD constructors.

This is an exact emitted-body review, not a general x86 interpreter. The stack
data here is public; enclosing-window and shared-runtime obligations remain.
"""
import hashlib
import math
import windows_enclave_kmac_shapes as s


def parameters(lane):
    s.require(lane in ('simd256','simd512'),'known SIMD constructor')
    # word bits, frame, states, padded blocks, scratch, temporary schedule
    return (32,5616,544,32,800,3568) if lane=='simd256' else (64,6640,32,288,3360,800)


def constants(lane):
    bits,*_=parameters(lane);word=bits//8;mask=(1<<bits)-1
    initial=b''.join((math.isqrt(p<<(2*bits))&mask).to_bytes(word,'little')
                     for p in (2,3,5,7,11,13,17,19))
    answer=getattr(hashlib,'sha'+str(bits*8))(b'abc').digest()
    answer=b''.join(answer[i:i+word][::-1] for i in range(0,len(answer),word))
    named=lambda raw:[('__ymm@'+int.from_bytes(raw[i:i+32],'little').to_bytes(32,'big').hex(),raw[i:i+32])
                      for i in range(0,len(raw),32)]
    return named(initial),named(answer)


def block_stores(lane):
    """Literal stores, in emitted order; their independently checked byte meaning."""
    narrow=lane=='simd256';_,_,_,start,*_=parameters(lane)
    zero=lambda at:(at,bytes(32))
    integer=lambda at,n,width:(at,(n% (1<<(8*width))).to_bytes(width,'little'))
    result=[zero(at) for at in ((511,484) if narrow else (767,740,708,676))]
    result += [integer(start,-2140970399,4)]
    zeros=((36,63),(100,127),(191,164),(228,255),(319,292),(383,356),(447,420)) if narrow else (
        (292,324,356,383),(420,452,484,511),(548,580,612,639))
    for index,offsets in enumerate(zeros):
        result += [zero(at) for at in offsets]
        at=start+(index+1)*(64 if narrow else 128)-1
        result += [integer(at,1667391768,4),integer(at+4,-128,1)]
    return result+[integer(start+511,24,1)]


def public_blocks(lane):
    bits,_,_,start,*_=parameters(lane);block=bits*2;values={}
    for at,raw in block_stores(lane):
        for offset,value in enumerate(raw): values[at+offset]=value
    s.require(set(values)==set(range(start,start+512)),'KAT initializes exactly 512 public input bytes')
    result=bytes(values[i] for i in range(start,start+512))
    expected=(b'abc\x80'+bytes(block-5)+b'\x18')*(256//bits)
    s.require(result==expected,'every startup lane is the complete padded abc block')
    return result


def shape(bodies,lane):
    bits,frame,states,blocks,scratch,temp=parameters(lane);narrow=bits==32;width=256//bits
    schedule=2048 if narrow else 2560;work=scratch+256+schedule
    zero='vxorps' if narrow else 'vpxor';move='vmovups' if narrow else 'vmovdqu'
    aligned='vmovaps' if narrow else 'vmovdqa';initial,answer=constants(lane)
    symbol=lambda pattern:s.one(bodies,pattern)
    compiled=symbol(r'Kernel8compiled$');wipe=symbol(r'crypto_cpu.*scratch.*Workspace4wipe$')
    transfer=lambda words,pack:symbol(r'transfer9transposeKj'+str(words)+'_Kb'+str(pack)+'_')
    code=[]
    for reg in ('rbp','r14','rsi','rdi','rbx'): code += [f'pushq %{reg}',f'.seh_pushreg %{reg}']
    code += [f'movl ${frame}, %eax','callq __chkstk','subq %rax, %rsp',f'.seh_stackalloc {frame}',
        'leaq 128(%rsp), %rbp','.seh_setframe %rbp, 128','.seh_endprologue','andq $-32, %rsp',
        'movq %rdx, %rdi','movq %rcx, %rsi',f'{aligned} {initial[0][0]}(%rip), %ymm0']
    if narrow: code += [f'{move} %ymm0, {at}(%rsp)' for at in range(states,states+256,32)]
    else:
        code += [f'{move} %ymm0, 32(%rsp)',f'{aligned} {initial[1][0]}(%rip), %ymm1',
                 f'{move} %ymm1, 64(%rsp)']
        code += [f'{move} %ymm{i}, {at+32*i}(%rsp)' for at in (96,160,224) for i in range(2)]
    code += [f'{zero} %xmm0, %xmm0, %xmm0']
    for at,raw in block_stores(lane):
        if len(raw)==32: code += [f'{move} %ymm0, {at}(%rsp)']
        else:
            value=int.from_bytes(raw,'little',signed=True);op='l' if len(raw)==4 else 'b'
            code += [f'mov{op} ${value}, {at}(%rsp)']
    code += ['movl $224, %eax','.p2align 4','.B1:']
    code += [f'{move} %ymm0, {temp-224+i}(%rsp,%rax)' for i in range(0,256,32)]
    code += ['addq $256, %rax',f'cmpq ${schedule+224}, %rax','jne .B1',f'{zero} %xmm0, %xmm0, %xmm0']
    code += [f'{aligned} %ymm0, {at}(%rsp)' for at in range(scratch+224,scratch-1,-32)]
    code += [f'leaq {scratch+256}(%rsp), %rbx',f'leaq {temp}(%rsp), %rdx',f'movl ${schedule}, %r8d',
        'movq %rbx, %rcx','vzeroupper','callq memcpy',f'{zero} %xmm0, %xmm0, %xmm0']
    code += [f'{aligned} %ymm0, {at}(%rsp)' for at in range(work,work+448,32)]
    code += ['xorl %ecx, %ecx','vzeroupper','callq '+compiled,'testb %al, %al','je .B10',
        f'leaq {scratch}(%rsp), %r14','movq %r14, %rcx','callq '+wipe,
        f'leaq {states}(%rsp), %rdx',f'movl ${width}, %r8d','movq %r14, %rcx','xorl %r9d, %r9d',
        'callq '+transfer(8,1),f'leaq {blocks}(%rsp), %rdx',f'movl ${width}, %r8d',
        'movq %rbx, %rcx','callq '+transfer(10,1),'movq %r14, %rcx',
        'callq '+symbol(r'hardened_batch3x8615compress_secret$'),'xorl %ecx, %ecx',
        'callq '+compiled,'testb %al, %al','je .B10']
    if narrow: code += ['leaq 24(%rdi), %rbx']
    code += [f'leaq {work}(%rsp), %rdx',f'leaq {states}(%rsp), %rcx']
    if narrow: code += ['xorl %r14d, %r14d']
    code += [f'movl ${width}, %r8d','xorl %r9d, %r9d','callq '+transfer(8,0),
        f'leaq {scratch}(%rsp), %rcx','callq '+wipe,f'{aligned} {answer[0][0]}(%rip), %ymm0']
    if narrow:
        code += ['.p2align 4','.B5:','cmpq $256, %r14','je .B11','vmovups %ymm0, 3568(%rsp)',
            'vmovdqu 544(%rsp,%r14), %ymm1','vpxor 3568(%rsp), %ymm1, %ymm1','xorl %eax, %eax',
            'vptest %ymm1, %ymm1','setne %al','movb $2, %cl','subb %al, %cl','cmpq $224, %r14',
            'leaq 32(%r14), %r14','movzbl %cl, %ecx','cmovnel %ecx, %eax','cmpb $2, %al','je .B5',
            'movzbl %al, %eax','testl %eax, %eax','jne .B8','.B11:']
    else:
        code += ['vmovdqu %ymm0, 800(%rsp)',f'vmovdqa {answer[1][0]}(%rip), %ymm1',
                 'vmovdqu %ymm1, 832(%rsp)']
        for at in (32,96,160,224):
            if at!=32: code += ['vmovdqu %ymm0, 800(%rsp)','vmovdqu %ymm1, 832(%rsp)']
            a,b=(0,1) if at==224 else (2,3)
            code += [f'vmovdqu {at}(%rsp), %ymm{a}',f'vmovdqu {at+32}(%rsp), %ymm{b}',
                f'vpxor 832(%rsp), %ymm{b}, %ymm{b}',f'vpxor 800(%rsp), %ymm{a}, %ymm{a}',
                f'vpor %ymm{b}, %ymm{a}, %ymm{a}',f'vptest %ymm{a}, %ymm{a}','jne .B8']
    code += [f'leaq {scratch}(%rsp), %rcx','vzeroupper','callq '+wipe,'movb $0, (%rdi)',
        'movb $0, 7(%rdi)','movw $0, 5(%rdi)','movl $0, 1(%rdi)',f'leaq {compiled}(%rip), %rax',
        'movq %rax, 8(%rdi)','movw $1, 16(%rdi)']
    code += ['xorl %ecx, %ecx','callq '+compiled,'testb %al, %al','je .B13']*2
    code += (['movq $2, 24(%rdi)','movq %rdi, 32(%rdi)'] if narrow else
             ['leaq 24(%rdi), %rax','movw $-1, 24(%rdi)','movb $5, 26(%rdi)','movq %rdi, 40(%rdi)'])
    out=40 if narrow else 48
    code += [f'{zero} %xmm0, %xmm0, %xmm0']
    code += [f'{move} %ymm0, {at}(%rdi)' for at in (*range(out,out+256,32),out+233)]
    code += ['movq %rdi, (%rsi)','movq %rdi, 8(%rsi)',
        'movq '+('%rbx' if narrow else '%rax')+', 16(%rsi)','jmp .B17','.B10:',
        f'leaq {scratch}(%rsp), %rcx','callq '+wipe,'.B8:',f'leaq {scratch}(%rsp), %rcx',
        'vzeroupper','callq '+wipe,'xorl %eax, %eax','.p2align 4','.B9:']
    clear=[f'movb $0, {i if i else ""}(%rdi,%rax)' for i in range(8)]+['addq $8, %rax','cmpq $4096, %rax']
    code += clear+['jne .B9','.B15:','movb $5, 8(%rsi)','movq $0, (%rsi)',
                  '.B17:','.seh_startepilogue',f'leaq {frame-128}(%rbp), %rsp']
    code += [f'popq %{reg}' for reg in ('rbx','rdi','rsi','r14','rbp')]
    code += ['.seh_endepilogue','vzeroupper','retq','.B13:','movb $0, 16(%rdi)','xorl %eax, %eax']
    if narrow: code += ['.p2align 4']
    return code+['.B14:']+clear+['jne .B14','jmp .B15']


def accepts(lane,outputs):
    """Public comparison model tied to the exact loop/unrolled body above."""
    bits,*_=parameters(lane);width=256//bits
    expected=b''.join(raw for _,raw in constants(lane)[1])
    s.require(len(outputs)==width and all(len(v)==bits for v in outputs),'fixed KAT output geometry')
    if lane=='simd256':
        offset=0
        while offset!=256:
            mismatch=int(any(a^b for a,b in zip(outputs[offset//32],expected)))
            result=(2-mismatch) if offset!=224 else mismatch
            offset+=32
            if result!=2: return result==0
        return True
    for output in outputs:
        if any((a^b)|(c^d) for a,b,c,d in zip(output[:32],expected[:32],output[32:],expected[32:])):
            return False
    return True


def inspect(bodies,lane):
    bits,frame,states,blocks,scratch,temp=parameters(lane)
    name=s.one(bodies,r'Resident3new$');body=s.lines(bodies[name]);expected=shape(bodies,lane)
    s.require(body[3:]==expected,'complete saved SIMD constructor/KAT/placement body')
    public_blocks(lane)
    schedule=2048 if bits==32 else 2560
    touched=[temp-224+a+i+j for a in range(224,schedule+224,256)
             for i in range(0,256,32) for j in range(32)]
    s.require(touched==list(range(temp,temp+schedule)),'complete public schedule initialization')
    # Four typed arguments, all public data generated within this frame. These
    # use the already reviewed transpose/kernel/wipe bodies, not an extra route.
    return dict(function=name,instructions=len(expected),public_message='abc',lanes=256//bits,
        compared_output_bytes=256,input_region=[blocks,blocks+512],state_region=[states,states+256],
        scratch_region=[scratch,scratch+256+schedule+448],public_schedule_region=[temp,temp+schedule],
        frame_allocation=frame,frame_alignment=32,compiled_checks=4,
        full_body_including_failure_edges=True,all_lanes_checked_before_publication=True,
        authority_page_offset=0,owner_page_offset=24,owner_output_bytes=256,
        failure_page_erasure_bytes=4096,secret_input=False,
        constants_require_linked_object_and_image_binding=True,
        enclosing_window_and_shared_runtime_qualification_pending=True,
        kat_proves_platform_migration_or_independent_review=False)
