"""Exhaustive saved-LLVM output descriptor uses; not whole-executor safety.

The owned allocation's addresses and its borrowed pointer values are distinct.
The latter are restricted to null checks, output copying and erasure here.
"""
import re
from collections import Counter
import windows_enclave_sha2_descriptor_ir as graph
import windows_enclave_sha3_simd_digest as digest
s=digest.s


def sequence(lines,text):
    expected=[x.strip() for x in text.strip().splitlines()]
    matches=[i for i in range(len(lines)) if lines[i:i+len(expected)]==expected]
    s.require(len(matches)==1,'unique output IR sequence')
    return matches[0]


def cleanup_indices(lines,drop):
    sequence(lines,f'''br label %903
903:
%904 = phi i64 [ 0, %901 ], [ %908, %.backedge ]
%905 = icmp eq i64 %904, 64
br i1 %905, label %{drop}.exit, label %906
906:
%907 = getelementptr inbounds nuw i8, ptr %17, i64 %904
%908 = add nuw nsw i64 %904, 16''')
    sequence(lines,'.backedge:\nbr label %903')
    return {'%904':(0,16,32,48)}


def allow_call(n):
    def allow(name,args,tail,aliases,used):
        if name in ('llvm.lifetime.start.p0','llvm.lifetime.end.p0'):
            s.require(args==['ptr nonnull %17'] and used=={'%17'},'output lifetime root')
            return dict(kind=name)
        if name=='llvm.memcpy.p0.p0.i64':
            s.require(len(args)==4 and args[3]=='i1 false','output aggregate transfer')
            dest,source=map(graph.pointer,args[:2])
            if dest=='%17':
                s.require(source=='%3' and args[2]=='i64 64' and used=={'%17'},'only original output descriptors imported')
                return dict(kind='initialize')
            s.require((dest,source)==('%0','%17') and args[2]=='i64 104' and used=={'%17'},'only whole output owner returned')
            return dict(kind='return')
        if name=='llvm.memset.p0.i64':
            s.require(args==['ptr noundef nonnull align 8 dereferenceable(32) %18','i8 0','i64 32','i1 false'] and
                aliases.get('%18')==(64,) and used=={'%18'},'only output bit metadata zero initialized')
            return dict(kind='initialize_bits')
        if name==n['validate']:
            expected=['ptr noalias nofree noundef nonnull readonly align 8 captures(address, read_provenance) dereferenceable(448) %2',
                'ptr noalias nofree noundef nonnull readonly align 8 captures(address, read_provenance) dereferenceable(64) %17']
            s.require(args==expected and used=={'%17'},'read-only output shape validation')
            return dict(kind='validate')
        if name==n['output_drop']:
            s.require(args==['ptr noalias nofree noundef nonnull align 8 dereferenceable(104) %17'] and
                used=={'%17'} and tail==' [ "funclet"(token %799) ]','only reviewed exceptional output destructor')
            return dict(kind='unwind_drop')
        if name==digest.life.ZERO:
            s.require(len(args)==2,'output metadata wipe arity')
            ptr=graph.pointer(args[0]);expected={'%19':(96,4),'%18':(64,32)}
            s.require(ptr in expected and aliases.get(ptr)==(expected[ptr][0],) and used=={ptr} and
                args[1] in (f'i64 noundef {expected[ptr][1]}',
                f'i64 noundef range(i64 0, -9223372036854775808) {expected[ptr][1]}'),'wipe excludes output pointer/length descriptors')
            return dict(kind='clear_metadata')
        raise ValueError('unreviewed output descriptor consumer: '+name)
    return allow


def pointer_uses(lines,result,n):
    reads={row['name']:row for row in result['reads']}
    expected={'%806':[0],'%847':[16],'%862':[32],'%877':[48],'%909':[0,16,32,48]}
    s.require({name:row['offsets'] for name,row in reads.items() if row['type']=='ptr'}==expected,
        'complete output pointer load population')
    lengths={'%806':'%834','%847':'%813','%862':'%821','%877':'%829','%909':'%913'}
    sources={'%806':('%843','%842'),'%847':('%858','%857'),'%862':('%873','%872'),'%877':('%885','%884')}
    report={}
    for ptr,offsets in expected.items():
        s.require(reads[lengths[ptr]]['offsets']==[v+8 for v in offsets] and
            reads[lengths[ptr]]['type']=='i64','same-slot destination length')
        checks=calls=0
        for line in lines:
            if ptr not in re.findall(graph.SSA,line) or line.startswith(ptr+' = '):continue
            if re.fullmatch(graph.SSA+r' = icmp eq ptr '+re.escape(ptr)+', null',line):checks+=1;continue
            name,args,tail=graph.call(line)
            if ptr=='%909':
                s.require(name==digest.life.ZERO and len(args)==2 and graph.pointer(args[0])==ptr and
                    args[1]=='i64 noundef range(i64 0, -9223372036854775808) %913','output failure clears original slots')
            else:
                origin,length=sources[ptr]
                s.require(name==n['copy'] and len(args)==4 and graph.pointer(args[0])==ptr and
                    args[1]=='i64 noundef '+lengths[ptr] and graph.pointer(args[2])==origin and
                    args[3]=='i64 noundef '+length,'copy only into the matching original destination')
            s.require(set(re.findall(graph.SSA,tail)).isdisjoint(expected),'no hidden output pointer tail escape')
            calls+=1
        s.require(checks==1 and calls==1,'all pointer uses limited to null check and reviewed transfer/clear')
        report[ptr]=dict(offsets=offsets,length=lengths[ptr],calls=calls,null_checks=checks)
    return report


def inspect(ir,n):
    lines=graph.function(ir,n['executor']);dynamic=cleanup_indices(lines,n['output_drop'])
    result=graph.scan(lines,'%17',104,dynamic,allow_call(n))
    expected_reads=[('%806',[0],'ptr'),('%813',[24],'i64'),('%821',[40],'i64'),
        ('%829',[56],'i64'),('%834',[8],'i64'),('%839',[8],'i64'),('%847',[16],'ptr'),
        ('%851',[24],'i64'),('%862',[32],'ptr'),('%866',[40],'i64'),('%877',[48],'ptr'),
        ('%881',[56],'i64'),('%909',[0,16,32,48],'ptr'),('%913',[8,24,40,56],'i64')]
    s.require([(r['name'],r['offsets'],r['type']) for r in result['reads']]==expected_reads,
        'exact typed descriptor reads; no integer reinterpretation of pointers')
    writes=[(w['offset'],w['type'],w['value']) for w in result['writes']]
    s.require(writes==[(96,'i32','0'),(97,'i8','%928'),(72,'i64','%930'),
        (98,'i8','%938'),(80,'i64','%940'),(99,'i8','%948'),(88,'i64','%950'),
        (96,'i8','%955'),(64,'i64','%957')],'all scalar writes confined to output metadata, no pointer overwrite')
    counts=Counter(call['kind'] for call in result['calls'])
    s.require(counts==Counter({'llvm.lifetime.start.p0':1,'llvm.lifetime.end.p0':1,
        'initialize':1,'initialize_bits':1,'return':1,'validate':2,'unwind_drop':1,'clear_metadata':2}),
        'complete output descriptor consumer population')
    initialized=next(c['line'] for c in result['calls'] if c['kind']=='initialize')
    first_branch=next(i for i,l in enumerate(lines) if re.match(r'(br|switch|invoke|ret)\b',l))
    s.require(initialized<first_branch and all(r['line']>initialized for r in result['reads']),
        'unconditional descriptor initialization before branching or reads')
    sequence(lines,'920:\ncall void @llvm.lifetime.end.p0(ptr nonnull %17)\nret void')
    pointers=pointer_uses(lines,result,n)
    return dict(allocation_bytes=104,descriptor_bytes=64,aliases={k:list(v) for k,v in result['aliases'].items()},
        reads=result['reads'],writes=result['writes'],consumers=result['calls'],pointer_uses=pointers,
        output_descriptor_ir_addresses_do_not_escape=True,output_descriptor_fields_immutable_after_import=True,
        successful_return_copies_original_destinations=True,
        padding_erasure_qualified=False,machine_stack_aliasing_and_executor_body_qualified=False)
