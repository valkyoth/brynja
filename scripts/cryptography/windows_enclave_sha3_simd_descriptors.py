"""Receiver descriptor construction and bounded terminal-bit admission."""
import re
import windows_enclave_sha3_simd_receive as receive

life,s,L=receive.life,receive.s,receive.L


def array_shape():
    code=L('pushq %rsi|pushq %rdi|pushq %rbx|subq $512, %rsp|movq (%rdx), %rax|movzbl 8(%rdx), %r9d')
    for lane,offset in enumerate((416,320,217,114)):
        if lane:code+=L((
            'movq 16(%rdx), %r10|movzbl 24(%rdx), %r11d',
            'movq 32(%rdx), %rsi|movzbl 40(%rdx), %ebx',
            'movq 48(%rdx), %rdi|movzbl 56(%rdx), %edx')[lane-1])
        code+=L('''vmovups (%r8), %ymm0|vmovups %ymm0, (%rsp)|vmovups (%r8), %ymm1|
            vmovups %ymm1, 32(%rsp)|vmovups (%r8), %ymm2''')
        if lane==0:
            code+=L('''vmovups %ymm2, 64(%rsp)|vmovups %ymm2, 480(%rsp)|
                vmovups %ymm1, 448(%rsp)|vmovups %ymm0, 416(%rsp)|
                vmovups %ymm2, 64(%rcx)|vmovups %ymm1, 32(%rcx)|vmovups %ymm0, (%rcx)''')
        else:code+=L(f'''vmovups %ymm0, {offset}(%rsp)|vmovups %ymm2, {offset+64}(%rsp)|
                vmovups %ymm1, {offset+32}(%rsp)''')
    code+=L('movq %rax, 96(%rcx)|movb %r9b, 104(%rcx)')
    for lane,(source,reg,byte) in enumerate(((313,'r10','r11b'),(210,'rsi','bl'),(107,'rdi','dl')),1):
        for word in range(3):code.append(f'vmovups {source+32*word}(%rsp), %ymm{word}')
        for word in range(3):code.append(f'vmovups %ymm{word}, {105+112*(lane-1)+32*word}(%rcx)')
        code+=L(f'''movq {source+95}(%rsp), %rax|movq %rax, {200+112*(lane-1)}(%rcx)|
            movq %{reg}, {96+112*lane}(%rcx)|movb %{byte}, {104+112*lane}(%rcx)''')
    return code+L('addq $512, %rsp|popq %rbx|popq %rdi|popq %rsi|vzeroupper|retq')


def array_provenance(lines):
    """Byte-token execution of actual straight-line moves, including padding."""
    memory={key:[(key,i) for i in range(size)] for key,size in (
        ('plan',64),('empty',32),('frame',512),('output',448))}
    registers={};pointers={'rcx':'output','rdx':'plan','r8':'empty','rsp':'frame'}
    aliases={'eax':'rax','r9d':'r9','r9b':'r9','r11d':'r11','r11b':'r11','ebx':'rbx',
             'bl':'rbx','edx':'rdx','dl':'rdx'}
    written=set()
    def reg(value):return aliases.get(value.removeprefix('%'),value.removeprefix('%'))
    def address(value,width):
        match=re.fullmatch(r'([0-9]*?)\(%(rcx|rdx|r8|rsp)\)',value)
        s.require(match is not None,'only assigned descriptor addresses')
        key=pointers[match[2]];at=int(match[1] or 0)
        s.require(0<=at and at+width<=len(memory[key]),'bounded descriptor move')
        return key,at
    for line in lines:
        if line.startswith(('pushq ','popq ','subq ','addq ')) or line in ('vzeroupper','retq'):continue
        match=re.fullmatch(r'(vmovups|movq|movb|movzbl) (.+), (.+)',line)
        s.require(match is not None,'only modeled descriptor moves')
        op,source,destination=match.groups();width={'vmovups':32,'movq':8,'movb':1,'movzbl':1}[op]
        if '(' in source:
            key,at=address(source,width);value=memory[key][at:at+width].copy()
        else:
            s.require(reg(source) in registers,'defined source register')
            value=registers[reg(source)][:width]
        s.require(len(value)==width,'entire transferred register defined')
        if '(' in destination:
            key,at=address(destination,width);memory[key][at:at+width]=value
            if key=='output':written.update(range(at,at+width))
        else:registers[reg(destination)]=value+([0]*7 if op=='movzbl' else [])
    for lane in range(4):
        for part in range(3):
            at=112*lane+32*part
            s.require(memory['output'][at:at+32]==memory['empty'],'all three initial descriptors per lane retain empty provenance')
        at=112*lane+96
        s.require(memory['output'][at:at+9]==memory['plan'][16*lane:16*lane+9],
                  'all lane identity/output-width bytes preserve exact plan provenance')
    s.require(written==set(range(441)),'actual output physical writes stop before final padding')
    return dict(lanes=4,bit_descriptors=12,slot_semantic_bytes=36,physical_written_bytes=441,
        destination_extent=448,final_padding_unwritten_bytes=7,padding_initialization_or_cleanup_claimed=False)


def bit_shape(mask):
    saves=['r14','rsi','rdi','rbp','rbx']
    return ['pushq %'+r for r in saves]+L(f'''subq $32, %rsp|xorl %eax, %eax|
        movl %r9d, %r10d|subb $1, %r10b|setb %al|xorl %r11d, %r11d|
        cmpb $8, %r10b|setb %r11b|testq %r8, %r8|cmovel %eax, %r11d|
        testb %r11b, %r11b|je .B1|testq %r8, %r8|je .B3|
        movzbl %r9b, %eax|leaq (%rax,%r8,8), %rsi|addq $-8, %rsi|
        cmpb $8, %r9b|jae .B5|movb $-1, %al|movq %rcx, %rdi|
        movl %r9d, %ecx|shlb %cl, %al|leaq (%rdx,%r8), %rcx|decq %rcx|
        movq %rdx, %rbx|movl %eax, %edx|movl %r9d, %ebp|movq %r8, %r14|
        callq {mask}|movq %rbx, %rdx|movq %r14, %r8|movl %ebp, %r9d|
        movq %rdi, %rcx|testb %al, %al|jne .B5|movb $1, 8(%rcx)|jmp .B8|
        .B1:|movb $0, 8(%rcx)|.B8:|movq $0, (%rcx)|jmp .B9|
        .B3:|xorl %esi, %esi|.B5:|movq %rdx, (%rcx)|movq %r8, 8(%rcx)|
        movq %rsi, 16(%rcx)|movb %r9b, 24(%rcx)|.B9:|addq $32, %rsp''')+[
            'popq %'+r for r in reversed(saves)]+['retq']


def bit_admission(length,last,tail):
    s.require(0<=length<=1024 and 0<=last<=255 and 0<=tail<=255,'bounded bitstring model operands')
    valid=(last==0) if length==0 else ((last-1)&255)<8
    if not valid:return None
    if length==0:return dict(bits=0,read_index=None)
    if last<8 and tail&((255<<last)&255):return None
    return dict(bits=last+8*length-8,read_index=length-1 if last<8 else None)


def inspect(bodies,ir,receiver):
    n=receive.names(bodies)
    for role in ('array','bits'):
        s.require(receiver['functions'][role]==n[role],'descriptor caller names exact helper')
    s.require(receiver['all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'] and
        receiver['actual_bitstring_inputs_use_local_buffers_not_host_addresses'],'descriptor input allocation prerequisites')
    receive.abis(ir,n)
    mask=s.one(bodies,r'24secret_byte_mask_is_zero$');predicate=s.one(bodies,r'12mask_is_zero$')
    contracts={n['array']:array_shape(),n['bits']:bit_shape(mask),
        mask:L(f'subq $40, %rsp|callq {predicate}|cmpl $1, %eax|sete %al|addq $40, %rsp|retq'),
        predicate:L('movzbl %dl, %edx|movzbl (%rcx), %r10d|andl %edx, %r10d|sete %al|movzbl %al, %eax|xorl %r10d, %r10d|retq')}
    for name,expected in contracts.items():
        s.require(life.code(bodies[name])==expected,'entire descriptor/terminal-bit helper')
    target='"target-cpu"="x86-64" "target-features"="'+receive.worker.resident.session.zero.SIMD_FEATURES+'"'
    for name,result,args in ((mask,'noundef zeroext i1',
        'ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) dereferenceable(1) %0, i8 noundef range(i8 -128, 0) %1'),
        (predicate,'noundef i32','ptr noundef nonnull %0, i8 noundef zeroext range(i8 -128, 0) %1')):
        s.require(life.reuse.abi(ir,name)==f'define internal fastcc {result} @{name}({args}) unnamed_addr '+
            '{ noinline nounwind uwtable '+target+' } {','exact terminal-bit predicate ABI')
    return dict(functions=n|{'mask':mask,'predicate':predicate},instruction_positions={k:len(v) for k,v in contracts.items()},
        initial_array_provenance=array_provenance(life.code(bodies[n['array']])),
        empty_last_must_be_zero=True,nonempty_last_in_one_through_eight=True,
        bounded_bit_count_maximum=8192,partial_tail_checks_only_last_local_byte=True,
        pointer_length_bits_and_last_preserved_on_success=True,rejection_uses_null_result_pointer=True,
        no_input_pointer_published_to_global_or_heap_storage=True,
        descriptor_helpers_do_not_erase_their_full_frames=True,
        digest_caller_and_final_frame_cleanup_qualified=False)
