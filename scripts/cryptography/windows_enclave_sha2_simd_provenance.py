"""Saved SIMD descriptor allocation identity and non-escape review at LLVM IR.

Machine-code stack-slot lifetimes and complete engine/frame composition remain
separate obligations. This is not a generic memory-safety proof or release gate.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_descriptor_ir as graph


def once(lines,wanted):
    s.require(lines.count(wanted)==1,'unique descriptor contract: '+wanted)


def cleanup_index(lines,lane,root,drop):
    narrow=lane=='simd256'
    loop,initial,index,compare,access,alias,step=(887,886,888,889,890,891,892) if narrow else (986,984,987,988,989,990,991)
    back='.backedge261' if narrow else '.backedge'
    end='900' if narrow else drop+'.exit'
    capacity=8 if narrow else 4
    expected=[f'{loop}:',f'%{index} = phi i64 [ 0, %{initial} ], [ %{step}, %{back} ]',
        f'%{compare} = icmp eq i64 %{index}, {16*capacity}',
        f'br i1 %{compare}, label %{end}, label %{access}',f'{access}:',
        f'%{alias} = getelementptr inbounds nuw i8, ptr {root}, i64 %{index}',
        f'%{step} = add nuw nsw i64 %{index}, 16']
    at=lines.index(expected[0]);s.require(lines[at:at+len(expected)]==expected,'bounded descriptor cleanup loop')
    once(lines,back+':')
    at=lines.index(back+':');s.require(lines[at+1]==f'br label %{loop}','descriptor cleanup backedge')
    return {f'%{index}':tuple(range(0,16*capacity,16))}


def calls_for(root,capacity,drop,lane):
    descriptor=16*capacity;size=descriptor+8
    def allow(name,args,tail,aliases,used):
        if name in ('llvm.lifetime.start.p0','llvm.lifetime.end.p0'):
            s.require(len(args)==1 and graph.pointer(args[0])==root and used=={root},'descriptor lifetime root')
            return dict(kind=name)
        if name=='llvm.memcpy.p0.p0.i64':
            s.require(len(args)==4 and args[3]=='i1 false','nonvolatile descriptor aggregate copy')
            destination,source=map(graph.pointer,args[:2])
            if lane=='simd512' and destination==root:
                s.require(source=='%3' and args[2]=='i64 64' and used=={root},'wide descriptor input copy')
                return dict(kind='initialize',offset=0,bytes=64)
            expected=('%0',root,0,72) if lane=='simd512' else ('%.sroa.622','%.sroa.622.0..sroa_idx',1,135)
            target,origin,offset,length=expected
            s.require((destination,source)==(target,origin) and aliases.get(source)==(offset,) and
                      args[2]==f'i64 {length}' and used=={source},'descriptor read-only return transfer')
            return dict(kind='return_copy',offset=offset,bytes=length)
        if name==s.ZERO:
            s.require(len(args)==2 and args[1]=='i64 noundef 8','descriptor identity-only clearing')
            pointer=graph.pointer(args[0])
            s.require(aliases.get(pointer)==(descriptor,) and used=={pointer},'clear cannot overwrite descriptor pointers')
            return dict(kind='clear_identities',offset=descriptor,bytes=8)
        if name==drop:
            s.require(len(args)==1 and graph.pointer(args[0])==root and used=={root} and
                      '[ "funclet"(token ' in tail and f'dereferenceable({size})' in args[0],
                      'descriptor access only by reviewed unwind destructor')
            return dict(kind='unwind_drop')
        raise ValueError('unreviewed descriptor address consumer: '+name)
    return allow


def source_offset(defs,value,root):
    if value==root: return 0
    match=graph.gep(defs.get(value,''))
    s.require(match is not None and match[1]==root and not match[2].startswith('%'),
              'descriptor points into the original scratch allocation')
    return int(match[2])


def validate_writes(lines,result,lane):
    narrow=lane=='simd256';capacity=8 if narrow else 4;end=16*capacity
    writes=result['writes'];initial=[w for w in writes if w['offset']<end]
    if narrow:
        s.require([(w['offset'],w['type']) for w in initial]==
                  [(i*8,'ptr' if i%2==0 else 'i64') for i in range(16)],
                  'exact one-time descriptor initialization, no later overwrites')
        defs=graph.definitions(lines)
        s.require(defs.get('%18')=='alloca [256 x i8], align 1','private output scratch allocation')
        for i,write in enumerate(initial[::2]):
            s.require(source_offset(defs,write['value'],'%18')==32*i,'all eight original scratch slots')
        first,last=initial[0]['line'],initial[-1]['line']
        s.require(not any(re.search(r'\b(br|switch|invoke|call|ret|indirectbr)\b',l)
                          or l.endswith(':') for l in lines[first:last+1]),'uninterrupted descriptor initialization')
        initial_end=last
    else:
        s.require(not initial,'wide descriptors immutable after their single incoming copy')
        copies=[c for c in result['calls'] if c['kind']=='initialize']
        s.require(len(copies)==1,'one wide descriptor initialization')
        initial_end=copies[0]['line']
    s.require(all(r['line']>initial_end for r in result['reads']),'no descriptor read before initialization')
    identities=[w for w in writes if w['offset']>=end]
    s.require([(w['offset'],w['type']) for w in identities]==
              [(end,'i64')]+[(end+i, 'i8' if narrow else 'i16') for i in range(0,8,1 if narrow else 2)]
              and identities[0]['value']=='0','identity writes confined to the eight-byte tail')
    kinds=[c['kind'] for c in result['calls']]
    for kind in ('unwind_drop','clear_identities','return_copy','llvm.lifetime.start.p0'):
        s.require(kinds.count(kind)==1,'exact descriptor consumer count: '+kind)
    s.require(kinds.count('llvm.lifetime.end.p0')==(2 if narrow else 1),'descriptor lifetime exits')


PHIS={
    'simd256':('%.sroa.0.1','%.sroa.8.1','%.sroa.11.1','%.sroa.14176.1',
               '%.sroa.17.1187','%.sroa.20.1','%.sroa.23177.1','%.sroa.26.1'),
    'simd512':('%.sroa.0.0205','%.sroa.8203.0','%.sroa.13.0206','%.sroa.18204.0'),
}


def prepared_sources(lines,result,lane,copy):
    """Every prepared output pointer is null or its original workspace slot."""
    defs=graph.definitions(lines);loads={r['name']:r for r in result['reads']}
    narrow=lane=='simd256';workspace='%19' if narrow else '%4';stride=32 if narrow else 64
    records=[]
    for slot,phi in enumerate(PHIS[lane]):
        source=825+8*slot if narrow else 942+10*slot
        present=source-1;absent=(736 if slot==0 else source-5) if narrow else (898 if slot==0 else source-5)
        incoming=f'[ null, %{absent} ], [ %{source}, %{present} ]'
        if narrow: incoming+=f', [ %{source}, %{present} ]'
        s.require(defs.get(phi)=='phi ptr '+incoming,'prepared source has only null or admitted workspace input')
        s.require(defs.get('%'+str(source))==
                  f'getelementptr inbounds nuw i8, ptr {workspace}, i64 {1024+stride*slot}',
                  'prepared source retains exact workspace slot')
        checks=0;copies=0
        for line in lines:
            if phi not in re.findall(graph.SSA,line) or line.startswith(phi+' = '): continue
            if re.fullmatch(graph.SSA+r' = icmp eq ptr '+re.escape(phi)+', null',line):
                checks+=1;continue
            name,args,tail=graph.call(line)
            s.require(name==copy and len(args)==4 and graph.pointer(args[2])==phi and
                      'readonly ' in args[2],'prepared source only enters the reviewed read-only copy')
            destination=graph.pointer(args[0]);length=args[1].split()[-1]
            s.require(destination in loads and length in loads and
                      loads[destination]['type']=='ptr' and loads[destination]['offsets']==[16*slot] and
                      loads[length]['type']=='i64' and loads[length]['offsets']==[16*slot+8],
                      'copy uses the matching original destination pointer and length')
            s.require(phi not in re.findall(graph.SSA,tail),'prepared source cannot escape through call tail')
            copies+=1
        s.require((checks,copies)==(1,1),'one null guard and one use per prepared source')
        records.append(dict(slot=slot,workspace_offset=1024+stride*slot,descriptor_offset=16*slot))
    return records


def inspect(bodies,ir,lane):
    s.require(lane in ('simd256','simd512'),'SIMD descriptor route')
    narrow=lane=='simd256';capacity=8 if narrow else 4;root='%10' if narrow else '%14'
    name=s.one(bodies,r'Resident6digest$' if narrow else r'Executor13digest_secret$')
    drop=s.one(bodies,r'SecretBatchOutput.*Drop4drop$')
    lines=graph.function(ir,name)
    dynamic=cleanup_index(lines,lane,root,drop)
    result=graph.scan(lines,root,16*capacity+8,dynamic,calls_for(root,capacity,drop,lane))
    validate_writes(lines,result,lane)
    sources=prepared_sources(lines,result,lane,s.one(bodies,r'secret_memory18copy_secret_region$'))
    return dict(function=name,allocation=root,bytes=16*capacity+8,aliases=len(result['aliases']),
        reads=len(result['reads']),writes=len(result['writes']),calls=result['calls'],
        prepared_sources=sources,
        descriptor_initialization='eight disjoint original scratch slots' if narrow else 'single incoming 64-byte copy',
        descriptor_pointers_and_lengths_have_no_subsequent_IR_writes=True,
        unknown_alias_operations_and_address_escapes_rejected=True,
        cleanup_index_offsets=list(next(iter(dynamic.values()))),
        machine_stack_slot_lifetime_composition_pending=True,whole_frame_qualified=False)
