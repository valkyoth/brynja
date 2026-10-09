"""Exact private XOR wrapper/opaque leaf ABI and cleanup contracts."""
import windows_enclave_sha3_simd_absorb_shape as shape
life,s,L=shape.life,shape.s,shape.L


def wrapper(n):
    return L(f'''pushq %rsi|pushq %rbx|subq $40, %rsp|movzbl 96(%rsp), %r11d|
        movb $8, %al|subb %r9b, %al|testb %r9b, %r9b|sete %r9b|
        cmpb %al, %r8b|seta %bl|cmpb %al, %r11b|seta %r10b|orb %r9b, %bl|
        orb %r10b, %bl|jne .B2|movb $-1, %sil|movq %rcx, %r10|
        movl %eax, %ecx|shrb %cl, %sil|movzbl %r8b, %r8d|movzbl %r11b, %r9d|
        movzbl %sil, %eax|movl %eax, 32(%rsp)|movq %r10, %rcx|callq {n['xor_leaf']}|
        .B2:|movl %ebx, %eax|addq $40, %rsp|popq %rbx|popq %rsi|retq''')


def leaf():
    return L('''movq %rcx, %r10|movl 40(%rsp), %r11d|movzbl (%rdx), %eax|
        movl %r8d, %ecx|shrl %cl, %eax|andl %r11d, %eax|movl %r9d, %ecx|
        shll %cl, %eax|xorb %al, (%r10)|xorl %eax, %eax|xorl %ecx, %ecx|retq''')


def effect(source,right,count,left):
    s.require(0<=source<256 and 0<=right<256 and 0<=count<=8 and 0<=left<16,
              'private XOR compiler domain')
    remaining=(8-count)&255
    if count==0 or right>remaining or left>remaining:return None
    mask=255>>remaining
    return ((source>>right)&mask)<<left


def inspect(bodies,ir,n):
    body=bodies[n['xor_leaf']];markers=('BRYNJA_XOR_BEGIN','BRYNJA_XOR_ERASE','BRYNJA_XOR_END')
    s.require(life.code(bodies[n['xor']])==wrapper(n) and life.code(body)==leaf(),
              'complete XOR wrapper and leaf')
    s.require(body.count('#APP')==body.count('#NO_APP')==1 and
              all(body.count(m)==1 for m in markers),'one opaque XOR region and markers')
    opaque=body.split('#APP')[1].split('#NO_APP')[0]
    s.require(all(m in opaque for m in markers),'XOR markers inside opaque boundary')
    positions=[opaque.index(m) for m in markers]
    s.require(positions==sorted(positions),'ordered XOR erasure boundary')
    s.require(s.lines(opaque.split(markers[0])[1].split(markers[1])[0])==leaf()[2:9] and
        s.lines(opaque.split(markers[1])[1].split(markers[2])[0])==leaf()[9:11],
        'complete opaque XOR operation and working-register erasure')
    arguments={
        'xor':('noundef zeroext i1','ptr noalias nofree noundef nonnull dereferenceable(1) %0, '+
            'ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) dereferenceable(1) %1, '+
            'i8 noundef %2, i8 noundef range(i8 0, 9) %3, i8 noundef range(i8 0, 16) %4'),
        'xor_leaf':('void','ptr noundef nonnull %0, ptr noundef nonnull %1, '+
            'i32 noundef range(i32 0, 9) %2, i32 noundef range(i32 0, 9) %3, i32 noundef range(i32 0, 256) %4')}
    for role,(result,args) in arguments.items():
        s.require(life.reuse.abi(ir,n[role])==f'define internal fastcc {result} @{n[role]}({args}) unnamed_addr '+
            '{ noinline nounwind uwtable '+shape.squeeze.shape.digest.target()+' } {','exact XOR private ABI')
    return dict(functions={k:n[k] for k in ('xor','xor_leaf')},wrapper_stack_bytes=56,
        fifth_incoming_argument_from_lowered_rsp=96,leaf_mask_argument_from_entry_rsp=40,
        valid_count=[1,8],invalid_parameters_rejected_before_secret_read=True,
        erased_working_registers=['eax','ecx'],opaque_stack_accesses=0,
        whole_caller_frame_and_stack_lifetimes_qualified=False)
