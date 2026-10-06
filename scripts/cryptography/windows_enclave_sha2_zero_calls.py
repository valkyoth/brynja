"""Positive-length argument checks at every saved SIMD zeroizer call/tail call.

This local dominance check is composed with the parent's frozen control-flow
and jump-table bindings. It does not prove pointer validity, descriptor upper
bounds, indirect memory effects or enclosing storage lifetimes.
"""
import re
import windows_enclave_kmac_shapes as s


def preserves_length(line):
    # Exhaustive instructions found between literal setup and these calls.
    # In particular, no intervening label, call, flag branch or RDX write.
    return (line in ('vzeroupper', '.seh_startepilogue', '.seh_endepilogue',
                     'addq $32, %rsp', 'addq $40, %rsp', 'popq %rsi', 'popq %rdi')
            or re.fullmatch(r'movq %(?:rsi|rdi|r15|rbx|r13|r12), %rcx', line) is not None
            or line in ('leaq 11688(%rbx), %rcx', 'movq 928(%rbp), %rcx'))


def site(lines, at):
    s.require(lines[at] in ('callq '+s.ZERO, 'jmp '+s.ZERO), 'direct clearing transfer')
    end=at
    while at and preserves_length(lines[at-1]): at-=1
    s.require(at>0, 'zeroizer length must be established locally')
    literal=re.fullmatch(r'movl \$(\d+), %edx', lines[at-1])
    if literal:
        length=int(literal[1])
        s.require(0<length<(1<<32), 'positive representable 32-bit clearing length')
        return dict(kind='constant', length=length, start=at-1, transfer=end,
                    tail=lines[end].startswith('jmp '))
    # The only dynamic form is an unchanged full-width descriptor length,
    # tested immediately before entering the clear. No intervening entry label.
    s.require(at>=3, 'complete dynamic clearing guard')
    load,test,branch=lines[at-3:at]
    s.require(re.fullmatch(r'movq (?:8\(%rsi,%rdi\)|872\(%rbx,%rsi\)|'
                          r'2920\(%rbx,%rsi\)|824\(%rbp,%rsi\)), %rdx', load) is not None,
              'reviewed descriptor-length load')
    s.require(test=='testq %rdx, %rdx', 'full-width unchanged length test')
    target=re.fullmatch(r'je (\.B\d+)', branch)
    s.require(target is not None and lines.count(target[1]+':')==1, 'zero length branches away')
    s.require(lines[end].startswith('callq '), 'reviewed dynamic form is a call')
    return dict(kind='guarded_descriptor', start=at-3, transfer=end, tail=False,
                zero_target=target[1], upper_bound_and_pointer_validity_proven_elsewhere=False)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'), 'assigned zeroizer caller population')
    records=[]
    for name,body in bodies.items():
        if name==s.ZERO: continue
        lines=s.lines(body)
        for at,line in enumerate(lines):
            if s.ZERO not in line: continue
            record=site(lines,at)
            records.append(dict(function=name, **record))
    expected=(53,3) if lane=='simd256' else (51,2)
    s.require((len(records),sum(r['kind']=='guarded_descriptor' for r in records))==expected,
              'complete fixed and dynamic clearing call population')
    return dict(calls=records, total=len(records),
        constant_lengths=sum(r['kind']=='constant' for r in records),
        guarded_descriptor_lengths=expected[1], every_argument_strictly_positive=True,
        fixed_lengths_below_signed_pointer_limit=True,
        descriptor_upper_bounds_and_pointer_lifetimes_pending=True,
        parent_control_flow_and_jump_table_bindings_required=True,
        whole_frame_qualified=False)
