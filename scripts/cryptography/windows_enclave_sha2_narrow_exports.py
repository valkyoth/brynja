"""Narrow final-copy and owner-transfer arguments under live descriptor bounds.

Only the eight original destination-null preflight edges are excluded: their
nonnull origins are established by the separate construction/lifetime proof.
All length, health, error, and transfer-result branches remain in the graph.
"""
import windows_enclave_sha2_narrow_vector as vector
import windows_enclave_sha2_simd_commit as commit
import windows_enclave_sha2_failstop as guarded
a,p,n,o,s=vector.a,vector.p,vector.n,vector.o,vector.s
POINTERS=(184,104,72,128,112,136,232,224)
LENGTHS=(144,168,120,304,296)


def prepare(bodies,assembly,nonnull=False):
    name,lines,_,edges=a.prepare(bodies,assembly);admitted=lines[:];excluded=[]
    if nonnull:
        for i in range(8):
            at=o.unique(lines,f'je .B{192+4*i}')
            s.require(lines[at-1]==f'cmpq $0, {864+16*i}(%rbx)',
                      'only the original destination-null preflight is excluded')
            n.straight(edges,at-1,at);admitted[at]='nop';excluded.append(at)
    _,graph,spans=n.prepare(admitted,assembly,name)
    probe=o.unique(admitted,'callq __chkstk');slots=tuple(set(n.SLOTS+POINTERS+LENGTHS+(176,)))
    states=o.definitions(admitted,name,o.source.paths.jump_tables(assembly,admitted),slots,spans,
                         bases=n.BASES,call_clobbers={probe:{'rax'}})
    return name,lines,admitted,states,graph,excluded


def field(lines,states,at,reg,offset,slots=()):
    return n.trace(lines,states,at,reg,lambda site,loc:site>=0 and isinstance(loc,str) and
                   lines[site]==f'movq {offset}(%rbx), %{loc}',slots)


def exports(bodies,assembly):
    commit.narrow(bodies)
    name,lines,admitted,states,edges,excluded=prepare(bodies,assembly,True)
    copy=s.one(bodies,r'secret_memory18copy_secret_region$');calls=[]
    for i in range(8):
        begin=o.unique(lines,f'.B{222+3*i}:');end=o.unique(lines,f'.B{225+3*i}:')
        sites=[at for at in range(begin,end) if lines[at]=='callq '+copy]
        s.require(len(sites)==1,'one final copy per narrow output lane');at=sites[0]
        n.straight(edges,begin,at)
        destination=field(admitted,states,at,'rcx',864+16*i)
        capacity=field(admitted,states,at,'rdx',872+16*i)
        length=field(admitted,states,at,'r9',872+16*i,LENGTHS)
        origins=n.trace(admitted,states,at,'r8',lambda site,loc:site>=0 and isinstance(loc,str) and
                        lines[site]==f'leaq {7712+32*i}(%rbx), %{loc}',POINTERS)
        s.require(len(length)==len(origins)==1,'one current prepared source and original lane length')
        load=length[0];first=load+(1 if i<3 else 2);second=first+2
        operand=('%r9' if i==0 else '%r12' if i==1 else '%r15' if i==2 else '%rax')
        other=operand if i<3 else f'{LENGTHS[i-3]}(%rbx)'
        target=f'.B{193+4*i}' if i<7 else '.B221'
        target28=target if i<7 else '.B222'
        s.require(lines[first:second+4]==[f'cmpq $32, {operand}','je '+target,
            f'cmpq $28, {other}','leaq 10792(%rbx), %r13','je '+target28,'jmp .B34'],
            'exact two accepted narrow output widths and explicit rejection')
        n.straight(edges,load,second+3)
        # A valid copy must cross either the 32-byte or 28-byte accepted edge.
        cut=guarded.filtered(edges,edges=[(first+1,o.unique(lines,target+':')),
                                         (second+2,o.unique(lines,target28+':'))])
        n.g.dominates(edges,0,load,at)
        s.require(at not in n.g.reachable(cut,load),'every final copy crosses its own width admission')
        calls.append(dict(line=at,target=copy,role='final_copy',lane=i,destination_loads=destination,
            capacity_loads=capacity,length_load=load,source_origins=origins,width_values=[28,32],
            footprints=[['reads','frame',7712+32*i,7744+32*i],
                        ['writes','frame',3936+32*i,3968+32*i]]))
    return dict(function=name,calls=calls,excluded_original_null_edges=excluded,
                original_nonnull_preserved_destinations_required=True,other_normal_edges_retained=True)


def owner_transfer(bodies,assembly,descriptors):
    name,lines,_,states,edges,_=prepare(bodies,assembly)
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    start=o.unique(lines,'.B261:');head=start+2;at=start+16;step=at+2;cursor_step=at+3;back=at+6
    expected=['.B261:','movl $16, %esi','.B262:','cmpq $272, %rsi','je .B266',
        'movq 176(%rbx), %rax','movq -8(%rax), %r8','testq %r8, %r8','je .B269',
        'movq 176(%rbx), %rax','movq (%rax), %rdx','cmpq $32, %rdx','ja .B270',
        'movq 152(%rbx), %rax','leaq (%rax,%rsi), %rcx','movq %rdx, %r9','callq '+copy,
        'movl %eax, %ecx','addq $32, %rsi','addq $16, 176(%rbx)','movb $7, %al',
        'cmpb $-1, %cl','je .B262','jmp .B251','.B266:']
    s.require(lines[start:start+len(expected)]==expected,'complete eight-lane owner-transfer loop')
    n.straight(edges,head,back+1)
    s.require(n.predecessors(edges,head)=={start+1,back} and
              states[head]['rsi']==states[step]['rsi']==states[at]['rsi']=={start+1,step},
              'owner output index has only the guarded sixteen-plus-thirty-two induction')
    seed=o.unique(lines,'movq %rax, 176(%rbx)')
    s.require(lines[seed-1]=='leaq 2920(%rbx), %rax' and states[seed]['rax']=={seed-1} and
              all(states[i][176]=={seed,cursor_step} for i in (start+5,start+9,cursor_step)),
              'returned-descriptor cursor has only this lifetime initializer and matched advancement')
    n.g.dominates(edges,0,seed,head)
    for use in (start+6,start+10):
        s.require(states[use]['rax']=={use-1},'same current returned descriptor cursor is dereferenced')
    s.require(states[at]['rdx']=={start+10} and states[at]['r9']=={at-1} and
              states[at-1]['rdx']=={start+10} and states[at]['r8']=={start+6},
              'owner copy retains its checked source, exact capacity and matching length')
    original=a.life.authority(lines,states,edges,bodies)
    n.trace(lines,states,start+14,'rax',lambda site,loc:site==original['owner_initializer']-1 and
            loc=='rax',(152,))
    for branch in (head+2,start+8,start+12):n.g.success_edge(edges,head,branch,at)
    cut=guarded.filtered(edges,edges=[(back,head)])
    for required in (at,step,cursor_step):n.g.dominates(cut,head,required,back)
    s.require(at not in n.g.reachable(cut,at+1),'no copy replay without matched cursor and owner advances')
    forward=descriptors['copies'][0]
    s.require(descriptors['function']==name,'same original-to-returned descriptor lifetime')
    n.g.dominates(edges,0,forward['last_line'],at)
    return dict(line=at,target=copy,role='owner_transfer',owner_offsets=list(range(16,272,32)),
        descriptor_offsets=list(range(2912,3040,16)),cursor_seed=seed,cursor_step=cursor_step,
        length_range=[0,32],footprints=[['reads','frame',2912,3040],['reads','frame',3936,4192],
                                     ['writes','owner',16,272]])
