"""Bounded dynamic clearing loops and direct descriptor-write lifetimes.

This joins saved constructor geometry and byte-exact moves to normal-CFG
descriptor reads. It is conditional on helper/ABI noninterference, live frames,
and (for the wide child) the caller's original R9 descriptor argument. Unwind
activation, wide return admission and whole-frame cleanup remain separate.
"""
import windows_enclave_sha2_cleanup_regions as r
import windows_enclave_sha2_descriptor_bounds as bounds
import windows_enclave_sha2_simd_storage as storage
import windows_enclave_sha2_zero_calls as zero
import windows_enclave_sha2_cleanup_invokes as invokes
o,g,s,n=r.o,r.g,r.s,r.n


def graph(lines,assembly):
    return g.graph(lines,o.source.paths.jump_tables(assembly,lines))


def constructor(bodies,name,lane,edges):
    lines=s.lines(bodies[name]);offset=864 if lane=='simd256' else 352
    first=o.unique(lines,f'movq %r14, {offset}(%rbx)')
    last=o.unique(lines,'movq %rax, 984(%rbx)' if lane=='simd256' else 'movq %r8, 408(%rbx)')
    n.straight(edges,first,last)
    return first,last,bounds.inspect(bodies,lane)


def narrow(bodies,assembly):
    name=storage.symbols(bodies)['resident'];lines=s.lines(bodies[name])
    _,edges,indexed=n.prepare(lines,assembly,name)
    first,last,geometry=constructor(bodies,name,'simd256',edges)
    early=r.loop(lines,edges,o.unique(lines,'.B84:')+2,'.B85','.B86','.B89','rsi',
        ('864(%rbx,%rsi)','872(%rbx,%rsi)'),128,('movzbl 55(%rbx), %edi',))
    later=r.loop(lines,edges,o.unique(lines,'.B251:')+4,'.B252','.B253','.B256','rsi',
        ('2912(%rbx,%rsi)','2920(%rbx,%rsi)'),128,vector=True)
    forward=r.copy(bodies,name,'movzbl 864(%rbx), %eax','movb %al, 2912(%rbx)',
        ('rbx',864),('rbx',2912),136,edges)
    reverse=r.copy(bodies,name,'movq 3040(%rbx), %rax','vmovaps %ymm0, 864(%rbx)',
        ('rbx',2912),('rbx',864),136,edges)
    drop=storage.symbols(bodies)['output'];call=o.unique(lines,'callq '+drop)
    s.require(lines[call-2:call]==['leaq 864(%rbx), %rcx','vzeroupper'],
              'normal narrow drop receives the restored original descriptors')
    n.straight(edges,reverse['first_line'],call)
    initializers={last:[('original',None)],forward['last_line']:[('returned','original')],
        reverse['last_line']:[('original','returned')]}
    reads={early['read']:['original'],later['read']:['returned'],call:['original'],
        forward['first_line']:['original'],reverse['first_line']:['returned']}
    guarded,unwind=invokes.inspect(bodies,assembly,'simd256',name,drop)
    lifetime,_=r.lifetime(lines,edges,n.BASES,{'original':(864,992),'returned':(2912,3040)},
        initializers,reads,indexed,flags=(71,),guarded=guarded)
    return dict(function=name,geometry=geometry,construction=[first,last],loops=[early,later],
        copies=[forward,reverse],normal_drop=call,direct_write_lifetime=lifetime,unwind_requirements=unwind,
        descriptor_regions=[[864,992],[2912,3040]])


def wide(bodies,assembly):
    parent=storage.symbols(bodies)['resident'];pl=s.lines(bodies[parent]);pe=graph(pl,assembly)
    first,last,geometry=constructor(bodies,parent,'simd512',pe)
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);edges=graph(lines,assembly)
    start=o.unique(lines,'vmovups (%r9), %ymm0');end=start+3
    s.require(lines[start:end+1]==['vmovups (%r9), %ymm0','vmovups 32(%r9), %ymm1',
        'vmovups %ymm1, 848(%rbp)','vmovups %ymm0, 816(%rbp)'],
        'all four original argument descriptors copied without substitution')
    n.straight(edges,start,end)
    tables=o.source.paths.jump_tables(assembly,lines)
    raw=o.definitions(lines,name,tables,(),bases=o.BASES)
    s.require(all(at in raw for at,line in enumerate(lines) if not line.startswith('.')),
              'all assigned wide child instructions have reachable definition states')
    s.require(raw[start]['r9']==raw[start+1]['r9']=={-1},'descriptor copy reads original R9 argument')
    spans=o.indexed_effects(lines,raw,tables)
    early=r.loop(lines,edges,o.unique(lines,'.B16:')+4,'.B17','.B18','.B21','rsi',
        ('816(%rbp,%rsi)','824(%rbp,%rsi)'),64)
    returned=r.copy(bodies,name,'vmovups 816(%rbp), %ymm0','movq %rax, 64(%rsi)',
        ('rbp',816),('rsi',0),72,edges)
    guarded,unwind=invokes.inspect(bodies,assembly,'simd512',name,storage.symbols(bodies)['output'])
    lifetime,_=r.lifetime(lines,edges,o.BASES,{'original':(816,880)},
        {end:[('original',None)]},{early['read']:['original'],returned['first_line']:['original']},
        spans,guarded=guarded)
    parent_forward=r.copy(bodies,parent,'movzbl 4640(%rbx), %eax','movb %al, 352(%rbx)',
        ('rbx',4640),('rbx',352),72,pe)
    parent_reverse=r.copy(bodies,parent,'movq 416(%rbx), %rax','vmovaps %ymm0, 4640(%rbx)',
        ('rbx',352),('rbx',4640),72,pe)
    return dict(function=name,parent=parent,geometry=geometry,construction=[first,last],
        argument_copy=[start,end],loops=[early],copies=[returned,parent_forward,parent_reverse],
        direct_write_lifetime=lifetime,unwind_requirements=unwind,descriptor_regions=[[816,880]],
        original_R9_caller_bounds_and_wide_return_discriminant_join_pending=True)


def inspect(bodies,assembly,lane):
    s.require(lane in ('simd256','simd512'),'assigned dynamic clearing route')
    result=(narrow if lane=='simd256' else wide)(bodies,assembly)
    drop=storage.output_drop(bodies,lane);name=drop['function'];lines=s.lines(bodies[name])
    # The exact destructor above validates the tail call separately. Treat that
    # already assigned terminal transfer as a CFG exit for the loop proof only.
    tail=o.unique(lines,'jmp '+s.ZERO);closed=lines[:];closed[tail]='retq'
    item=r.loop(closed,graph(closed,assembly),o.unique(lines,'xorl %edi, %edi'),
        '.B3','.B2','.B4','rdi',('(%rsi,%rdi)','8(%rsi,%rdi)'),128 if lane=='simd256' else 64)
    covered={(result['function'],v['call']) for v in result['loops']}|{(name,item['call'])}
    actual={(v['function'],v['transfer']) for v in zero.inspect(bodies,lane)['calls']
            if v['kind']=='guarded_descriptor'}
    s.require(covered==actual,'every dynamic clearing site has one complete bounded-loop assignment')
    return dict(**result,destructor_loop=item,destructor=drop,dynamic_sites=len(covered),
        exact_pointer_length_pair_and_all_loop_indices_checked=True,
        normal_direct_descriptor_write_lifetimes_checked=True,
        destructor_invocation_and_unwind_lifetime_join_pending=True,
        indirect_helper_effects_and_live_frame_composition_required=True,
        descriptor_bounds_fully_qualified=False,whole_frame_qualified=False)
