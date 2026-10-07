"""Final narrow input-pointer consumers, retaining distinct lane provenance."""
import windows_enclave_sha2_narrow_cfg as n
o,g,s=n.o,n.g,n.s


def definition_chain(lines,states,first,last,registers):
    """Every demanded value at the use must have its immediately assigned origin."""
    for use,reg,definition in registers:
        s.require(first<=definition<use<=last and states[use][reg]=={definition},
                  'unsubstituted input-pointer argument definition')


def inspect(lines,states,edges,bodies):
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    load=o.unique(lines,'movzbl (%rax,%r13), %eax')
    expected=['movzbl (%rax,%r13), %eax','cmpq $8, %rax','jae .B176',
        'leaq (%rax,%rax,4), %rax','cmpb $2, 576(%rbx,%rax,8)','je .B176',
        'leaq (%rbx,%rax,8), %rax','addq $544, %rax','movq 16(%rax), %rcx',
        'movq %rcx, %rdx','shrq $3, %rdx','cmpq 8(%rax), %rdx','ja .B176',
        'shrq $9, %rcx','cmpq %rcx, 136(%rbx)','jae .B176',
        'movq 136(%rbx), %r8','shlq $6, %r8','addq (%rax), %r8',
        'movl $64, %edx','movl $64, %r9d','movq %rdi, %rcx','callq '+copy]
    s.require(lines[load:load+len(expected)]==expected,'complete checked vector input construction')
    end=load+len(expected)-1;n.straight(edges,load,end)
    # The fresh compact index is checked on EVERY iteration, before conversion
    # to the original 40-byte typed descriptor. Compact-list storage integrity
    # is separate: any value outside 0..7 is rejected here regardless of source.
    checks=[(load+3,'rax',load),(load+6,'rax',load+3),(load+7,'rax',load+6)]
    checks += [(at,'rax',load+7) for at in (load+8,load+11,load+18)]
    checks += [(load+9,'rcx',load+8),(load+10,'rdx',load+9),
        (load+11,'rdx',load+10),(load+13,'rcx',load+8),
        (load+14,'rcx',load+13),(load+17,'r8',load+16),
        (load+18,'r8',load+17),(end,'r8',load+18)]
    definition_chain(lines,states,load,end,checks)
    for branch in (load+2,load+5,load+12,load+15):g.success_edge(edges,load,branch,end)
    # Scalar transfers consume the same saved lane pointer, but use three
    # different offsets: complete tail blocks, remaining bytes, and last byte.
    tail=o.unique(lines,'addq 112(%rbx), %r8');last=o.unique(lines,'movq 112(%rbx), %rcx')
    block=o.unique(lines,'.B155:')
    sequences=[(tail-3,['movq 168(%rbx), %rdx','movq %rdx, %r8','andq $-64, %r8',
        'addq 112(%rbx), %r8','andl $63, %edx','leaq 11688(%rbx), %rcx',
        'movq %rdx, %rsi','movq %rdx, %r9','callq '+copy]),
        (last-3,['cmpq $0, 120(%rbx)','je .B176','movq 120(%rbx), %rax',
        'movq 112(%rbx), %rcx','leaq (%rcx,%rax), %r8','decq %r8',
        'movl $1, %edx','movl $1, %r9d','movq %r15, %rcx','callq '+copy]),
        (block+1,['movl $64, %edx','movl $64, %r9d','leaq 11560(%rbx), %rcx',
        'movq %rdi, %r8','callq '+copy])]
    for first,code in sequences:
        s.require(lines[first:first+len(code)]==code,'complete scalar input transfer argument path')
        n.straight(edges,first,first+len(code)-1)
    definition_chain(lines,states,tail-3,tail+5,[(tail-2,'rdx',tail-3),
        (tail-1,'r8',tail-2),(tail,'r8',tail-1),(tail+5,'r8',tail)])
    definition_chain(lines,states,last,last+6,[(last+1,'rcx',last),
        (last+2,'r8',last+1),(last+6,'r8',last+2)])
    s.require(states[last+1]['rax']=={last-1},'last-byte address uses matching original length')
    s.require(states[block+5]['r8']=={block+4},'block transfer consumes current live start pointer')
    return dict(vector_gather_call=end,vector_descriptor_pointer_load=load+18,
        scalar_tail_copy=tail+5,scalar_last_byte_copy=last+6,scalar_block_copy=block+5,
        vector_lane_range=[0,7],descriptor_stride=40,descriptor_pointer_offset=544,
        argument_definitions_and_fresh_index_guards_checked=True,
        original_length_fields_compact_storage_and_external_input_lifetimes_required=True)
