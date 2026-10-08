"""Exact private resident construction/retirement; OS guarantees stay external."""
import windows_enclave_sha3_batch_lifecycle as life

s=life.s
KAT='_RNvNtNtCshYLbG8W7MpL_17brynja_crypto_cpu16static_execution10operations12known_answer'


def lines(text):
    return [item.strip() for line in text.strip().splitlines() for item in line.split('|') if item.strip()]


def page_loop(base,index,label):
    return [label+':']+[f'movb $0, '+('' if n==0 else str(n))+f'(%{base},%{index})' for n in range(8)]+[
        f'addq $8, %{index}',f'cmpq $4096, %{index}','jne '+label]


def names(bodies,lane):
    result={'clear':s.one(bodies,r'Owner5clear$'),
            'receive':s.one(bodies,r'worker7receive$'),
            'buffers':s.one(bodies,r'worker7BuffersE')}
    if lane=='scalar':result['quarantine']=s.one(bodies,r'Owner10quarantine$')
    else:
        result.update(quarantine=s.one(bodies,r'Resident10quarantine$'),
            new=s.one(bodies,r'Resident3new$'),drop=s.one(bodies,r'Resident.*Drop4drop$'),
            buffers_clear=s.one(bodies,r'worker.*Buffers5clear$'))
    return result


def constructor():
    # All copies here precede caller secret input. Padding/moved constructor
    # representations are not asserted to be separately erased or initialized.
    out=lines('''pushq %r15|pushq %r14|pushq %rsi|pushq %rdi|pushq %rbx|subq $2608, %rsp
        movq %rdx, %rdi|movq %rcx, %rsi''')+['callq '+KAT]+lines('''
        movb $2, %cl|subb %al, %cl|movq $2, (%rdi)|movb %cl, 8(%rdi)|movb $4, 9(%rdi)
        testb %al, %al|je .B1|leaq 32(%rdi), %r15|leaq 528(%rsp), %r14
        movl $1040, %r8d|movq %r14, %rcx|xorl %edx, %edx|callq memset
        vxorps %xmm0, %xmm0, %xmm0''')
    for at in range(399,254,-24):out += [f'vmovups %xmm0, {at}(%rsp)',f'movb $0, {at+16}(%rsp)']
    out+=lines('''vmovups %xmm0, 512(%rsp)|leaq 1568(%rsp), %rbx|movl $1040, %r8d
        movq %rbx, %rcx|movq %r14, %rdx|callq memcpy''')
    for src,dst in ((392,224),(368,192),(344,160),(320,128)):
        out += [f'vmovups {src}(%rsp), %xmm0',f'vmovaps %xmm0, {dst}(%rsp)',
                f'movq {src+16}(%rsp), %rax',f'movq %rax, {dst+16}(%rsp)']
    for src,dst in ((296,96),(272,64),(248,32)):
        out += [f'movq {src+16}(%rsp), %rax',f'movq %rax, {dst+16}(%rsp)',
                f'vmovups {src}(%rsp), %xmm0',f'vmovaps %xmm0, {dst}(%rsp)']
    out+=lines('''vmovups 472(%rsp), %ymm0|vmovups 496(%rsp), %ymm1
        vmovups %ymm1, 440(%rsp)|vmovups %ymm0, 416(%rsp)|movb $0, 32(%rdi)
        leaq 33(%rdi), %rcx|movl $1040, %r8d|movq %rbx, %rdx|vzeroupper|callq memcpy''')
    for src,dst in ((224,1073),(192,1097),(160,1121),(128,1145),(96,1169)):
        out += [f'movq {src+16}(%rsp), %rax',f'movq %rax, {dst+16}(%rdi)',
                f'vmovaps {src}(%rsp), %xmm0',f'vmovups %xmm0, {dst}(%rdi)']
    for src,dst in ((64,1193),(32,1217)):
        out += [f'vmovaps {src}(%rsp), %xmm0',f'vmovups %xmm0, {dst}(%rdi)',
                f'movq {src+16}(%rsp), %rax',f'movq %rax, {dst+16}(%rdi)']
    out+=lines('''movq $2, 2192(%rdi)|vmovups 416(%rsp), %ymm0|vmovups 440(%rsp), %ymm1
        vmovups %ymm1, 2224(%rdi)|vmovups %ymm0, 2200(%rdi)|movq %rdi, 2256(%rdi)
        movq $0, 2264(%rdi)|movw $0, 2280(%rdi)|movq %rdi, (%rsi)
        movq %rdi, 8(%rsi)|movq %r15, 16(%rsi)|jmp .B5|.B1:|xorl %eax, %eax''')
    out+=page_loop('rdi','rax','.B2')+lines('''movb $6, 8(%rsi)|movq $0, (%rsi)|.B5:
        addq $2608, %rsp|popq %rbx|popq %rdi|popq %rsi|popq %r14|popq %r15|vzeroupper|retq''')
    return out


def destructor():
    return lines('''pushq %rsi|pushq %rdi|pushq %rbx|subq $32, %rsp|movq %rdx, %rbx
        movq %rcx, %rsi|leaq 1216(%rdx), %rdi|movq %rdi, %rcx''')+[
        'callq '+life.DROP['avx2']]+life.clear_tail('avx2','rbx')+life.quarantine('avx2','rbx',2)+[
        'movq %rdi, %rcx','callq '+life.DROP['avx2'],'xorl %eax, %eax']+page_loop('rsi','rax','.B3')+[
        'addq $32, %rsp','popq %rbx','popq %rdi','popq %rsi','retq']


def quarantine(lane):
    size=16 if lane=='scalar' else 1216
    return life.frame(32)+['movq %rcx, %rsi',f'addq ${size}, %rcx','callq '+life.DROP[lane]]+\
        life.clear_tail(lane)+life.quarantine(lane,label=2)+life.frame(32,end=True)


def inspect(bodies,ir,lane,prior):
    n=names(bodies,lane);a=life.LAYOUT[lane];header=288 if lane=='scalar' else 304
    expected=life.frame(32)+['movq %rcx, %rsi','addq $1024, %rcx',f'movl ${header}, %edx',
        'callq '+life.ZERO,'movl $1024, %edx','movq %rsi, %rcx']+life.frame(32,end=True)[:-1]+['jmp '+life.ZERO]
    for name in {n['buffers'],n.get('buffers_clear',n['buffers'])}:
        s.require(life.code(bodies[name])==expected,'complete header/payload buffer destructor')
        abi=life.reuse.abi(ir,name)
        argument='_1' if name==n['buffers'] else 'self'
        s.require(f'(ptr noalias nofree noundef nonnull dereferenceable({1024+header}) %{argument})' in abi,
                  'complete exclusive worker buffer allocation')
    s.require(life.code(bodies[n['quarantine']])==quarantine(lane),'complete retained-owner quarantine helper')
    abi=life.reuse.abi(ir,n['quarantine'])
    pointer=(f'ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({a["size"]}) %0'
             if lane=='scalar' else 'ptr nonnull %.16.val')
    s.require('('+pointer+')' in abi,'quarantine retains actual placed-owner argument')
    result=dict(functions=n,header_bytes=header,payload_bytes=1024,complete_buffer_destructor_checked=True,
                public_constructor_copies_individually_erased=False)
    if lane=='avx2':
        s.require(KAT in prior['exact_body_reference_extent_and_abi'],'resident KAT prior semantics replayed')
        s.require(life.code(bodies[n['new']])==constructor(),'complete resident KAT/construction/rollback')
        s.require(life.code(bodies[n['drop']])==destructor(),'typed cleanup and authority revocation precede full-page retirement')
        abi=life.reuse.abi(ir,n['new'])
        s.require('(ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none) dereferenceable(24) %0, '
                  'ptr noalias nofree noundef nonnull align 4096 dereferenceable(4096) initializes((0, 16)) %1)' in abi,
                  'separate resident result and full exclusive aligned page')
        s.require('(ptr %.0.val, ptr nonnull %.16.val)' in life.reuse.abi(ir,n['drop']),
                  'backing and owner destructor argument roles')
        result.update(authority_page_offset=0,authority_bytes=16,owner_page_offset=32,owner_bytes=2272,
            authority_pointer_stored_at_page_offset=2256,owner_end=2304,
            kat_before_owner_publication=True,kat_failure_erases_page=True,page_erase_bytes=4096,
            drop_clears_borrowing_state_before_backing_page=True)
    return result
