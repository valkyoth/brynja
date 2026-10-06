"""Public SHA-NI startup KAT in the saved batch resident constructor."""
import windows_enclave_kmac_shapes as s

INITIAL='__ymm@5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667'
EXPECTED='__ymm@f20015adb410ff6196177a9cb00361a35dae2223414140de8f01cfeaba7816bf'
TABLE='anon.144b56272d44fa5dac32539943e266ef.3'


def inspect(bodies):
    name=s.one(bodies,r'static_execution.*operations12known_answer$');body=bodies[name]
    s.sequences(body,[
        'vmovaps '+INITIAL+'(%rip), %ymm0|vmovups %ymm0, (%rsp)|movq %rsp, %rax|'
        'vxorps %xmm0, %xmm0, %xmm0|'+
        '|'.join(f'vmovups %ymm0, {n}(%rsp)' for n in (256,224,192,160,128,96))+
        '|movl $1633837952, 32(%rsp)|vmovups %ymm0, 36(%rsp)|'
        'vmovups %ymm0, 60(%rsp)|movl $24, 92(%rsp)|movl $16, %eax',
        '.B1:|movl -28(%rsp,%rax,4), %ecx|movl 24(%rsp,%rax,4), %edx|movl %edx, %r8d|'
        'roll $15, %r8d|movl %edx, %r9d|roll $13, %r9d|xorl %r8d, %r9d|shrl $10, %edx|'
        'movl %ecx, %r8d|roll $25, %r8d|xorl %r9d, %edx|movl %ecx, %r9d|roll $14, %r9d|'
        'xorl %r8d, %r9d|shrl $3, %ecx|addl 4(%rsp,%rax,4), %edx|xorl %r9d, %ecx|'
        'addl -32(%rsp,%rax,4), %edx|addl %ecx, %edx|movl %edx, 32(%rsp,%rax,4)|'
        'incq %rax|cmpq $64, %rax|jne .B1',
        'movl (%rsp), %esi|movl 4(%rsp), %r11d|movl 8(%rsp), %r10d|movl 12(%rsp), %r9d|'
        'movl 16(%rsp), %r8d|movl 20(%rsp), %ecx|movl 24(%rsp), %eax|vmovd %ecx, %xmm0|'
        'vpinsrd $1, %r8d, %xmm0, %xmm0|vpinsrd $2, %r11d, %xmm0, %xmm0|movl 28(%rsp), %edx|'
        'vpinsrd $3, %esi, %xmm0, %xmm2|vmovd %edx, %xmm0|vpinsrd $1, %eax, %xmm0, %xmm0|'
        'vpinsrd $2, %r9d, %xmm0, %xmm0|vpinsrd $3, %r10d, %xmm0, %xmm1|'
        'xorl %edi, %edi|leaq '+TABLE+'(%rip), %rbx',
        '.B3:|movl 12(%rdi,%rbx), %ebp|addl 44(%rsp,%rdi), %ebp|'
        'movl 8(%rdi,%rbx), %r14d|addl 40(%rsp,%rdi), %r14d|movl (%rdi,%rbx), %r15d|'
        'movl 4(%rdi,%rbx), %r12d|addl 36(%rsp,%rdi), %r12d|addl 32(%rsp,%rdi), %r15d|'
        'vmovd %r15d, %xmm0|vpinsrd $1, %r12d, %xmm0, %xmm0|vpinsrd $2, %r14d, %xmm0, %xmm0|'
        'vpinsrd $3, %ebp, %xmm0, %xmm0|sha256rnds2 %xmm0, %xmm2, %xmm1|'
        'vpshufd $14, %xmm0, %xmm0|sha256rnds2 %xmm0, %xmm1, %xmm2|'
        'addq $16, %rdi|cmpq $256, %rdi|jne .B3',
        'vpextrd $2, %xmm2, %edi|vpextrd $3, %xmm2, %ebx|addl %esi, %ebx|'
        'vpextrd $3, %xmm1, %esi|addl %r11d, %edi|addl %r10d, %esi|vpextrd $2, %xmm1, %r10d|'
        'addl %r9d, %r10d|vpextrd $1, %xmm2, %r9d|addl %r8d, %r9d|vmovd %xmm2, %r8d|'
        'addl %ecx, %r8d|vpextrd $1, %xmm1, %ecx|addl %eax, %ecx|vmovd %xmm1, %eax|addl %edx, %eax|'+
        '|'.join(f'movl %{reg}, {str(4*i) if i else ""}(%rsp)'
                 for i,reg in enumerate(('ebx','edi','esi','r10d','r9d','r8d','ecx','eax')))+
        '|vmovaps '+EXPECTED+'(%rip), %ymm0|vmovups %ymm0, 32(%rsp)|vmovdqu (%rsp), %ymm0|'
        'vpxor 32(%rsp), %ymm0, %ymm0|vptest %ymm0, %ymm0|sete %al'])
    s.require(not any(l.startswith('call') for l in s.lines(body)),'public KAT has no further callees')
    returns=s.normal_returns(body,name,['vptest %ymm0, %ymm0','sete %al'])
    return dict(function=name,public_message='abc',padded_message_bits=24,
        schedule_words=64,rounds=64,full_256_bit_comparison=True,
        comparison_dominates_normal_returns=returns,constants_rebound_by_parent=True,
        secret_input=False,kat_is_platform_support_or_independent_review=False,
        constructor_stack_requires_enclosing_window_cleanup=True)
