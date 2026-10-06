"""TupleHash item framing and active cleanup in the saved Windows bodies."""
import windows_enclave_kmac_shapes as s


def owner(bodies,role):
    return s.one(bodies,r'Owner\d+'+role+'$')


def offsets(lane):
    return (1136,1152,2176,2184,2192,2200,2202,2203) if lane=='scalar' else (
            2016,0,2032,2040,2048,2064,2067,2066)


def items(bodies,lane):
    remaining,output,identity,sequence,width,packer,phase,last=offsets(lane)
    begin=bodies[owner(bodies,'begin_item')]
    fragment=bodies[owner(bodies,'fragment')]
    finish=bodies[owner(bodies,'finish_item')]
    append=s.one(bodies,r'Packer6append$')
    s.sequences(begin,[
        'movq %rbx, %rdx|movq %rdi, %r8|xorl %r9d, %r9d|callq '+s.ENCODE,
        f'movq %rbx, {remaining}(%rsi)|movq %rdi, {remaining+8}(%rsi)|movb $4, {phase}(%rsi)',
        'callq '+append+'|cmpb $-1, %al|je .B3'])
    s.sequences(fragment,[
        'cmpq $1024, 8(%rdi)|ja .B7',
        f'movq {remaining}(%rsi), %r14|movq {remaining+8}(%rsi), %r15|movq 16(%rdi), %r12|'
        'cmpq %r12, %r14|movq %r15, %rcx|sbbq $0, %rcx|jb .B7',
        'callq '+append+'|cmpb $-1, %al|je .B5',
        f'.B5:|subq %r12, %r14|sbbq $0, %r15|movq %r14, {remaining}(%rsi)|'
        f'movq %r15, {remaining+8}(%rsi)|movb $-1, %al'])
    s.sequences(finish,[f'movq {remaining}(%rsi), %rax|orq {remaining+8}(%rsi), %rax|je .B3',
                        f'.B3:|movb $3, {phase}(%rsi)|movb $-1, %al'])
    return dict(left_encoded_item_bits=True,remaining_u128_checked_before_append=True,
                remaining_committed_only_after_success=True,finish_requires_exact_zero=True,
                tuple_phase=3,item_phase=4,fragment_limit_bytes=1024)


def clear_event(lane,register='rsi'):
    remaining,output,identity,sequence,width,packer,phase,last=offsets(lane)
    ptr=f'leaq {output}(%rsi), %rcx' if output else 'movq %rsi, %rcx'
    event=(['leaq '+str(packer)+'(%rsi), %rcx','movl $1, %edx','callq '+s.ZERO,
            f'movb $0, {packer+1}(%rsi)',ptr,'movl $1024, %edx','callq '+s.ZERO]
           if lane=='scalar' else
           ['leaq '+str(packer)+'(%rsi), %rcx','movl $1, %edx','callq '+s.ZERO,
            f'movb $0, {packer+1}(%rsi)','movl $1024, %edx',ptr,'callq '+s.ZERO])
    suffix=[f'movq $0, {width}(%rsi)',f'movb $0, {last}(%rsi)',
            f'leaq {remaining}(%rsi), %rcx','movl $16, %edx','callq '+s.ZERO,
            f'movq $0, {identity}(%rsi)']
    return [line.replace('%rsi','%'+register) for line in event+suffix]


def clear(bodies,lane):
    name=owner(bodies,'clear');body=bodies[name];event=clear_event(lane)
    s.sequences(body,['|'.join(event)])
    returns=s.normal_returns(body,name,event)
    return dict(normal_return_sites=returns,pending_bytes=1,output_bytes=1024,remaining_bytes=16,
                identity_cleared=True,full_allocation_erasure_claim=False)


def packing(bodies,lane):
    name=s.one(bodies,r'Packer4bits$');body=bodies[name]
    s.sequences(body,[
        'movb %al, 32(%rsp)|movq %r14, %rcx|movq %rsi, %rdx|movl %ebp, %r8d|movb $1, %r9b|'
        'callq '+s.CORE+'13secret_memory20xor_secret_byte_bits',
        'movl $1, %edx|movq %r14, %rcx|callq '+s.ZERO+'|movb $0, 1(%r14)|xorl %eax, %eax',
        'incb %al|movb %al, 1(%r14)|cmpb $8, %al'])
    s.sequences(body,['cmpb $8, %al|jae '+('.B17' if lane=='scalar' else '.B14')])
    append=bodies[s.one(bodies,r'Packer6append$')]
    s.sequences(append,['cmpb $0, 1(%rcx)|je .B1'] if lane=='scalar' else
                      ['movzbl 1(%rcx), %eax|testb %al, %al|je .B14',
                       '.B14:|movq 16(%r8), %rax|shrq $3, %rax|movq 8(%r8), %r15',
                       'movq %rax, %r8|callq '+
                       '_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State6update'])
    return dict(one_bit_xor=True,destination_offset_below_eight=True,
                pending_cleared_after_flush=True,aligned_prefix_uses_bulk_path=True)


def inspect(bodies,lane):
    return dict(item_framing=items(bodies,lane),active_owner_cleanup=clear(bodies,lane),
                partial_bit_packer=packing(bodies,lane))
