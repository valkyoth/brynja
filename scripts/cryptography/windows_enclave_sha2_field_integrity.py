"""Saved SIMD input/authority/index preservation, conditional on object layout.

The enclosing machine review supplies bounded public index geometry and original
pointer origins. This additional exhaustive IR access inventory checks that
metadata fields remain unchanged while computation can read them, including
unwind edges. It does not prove separate external allocations cannot alias.
"""
import re
from collections import Counter
import windows_enclave_sha2_field_ir as g
import windows_enclave_sha2_field_effects as effects
s=g.s


def iterator_temporaries(lines):
    expected=[f'%{slot} = alloca i64, align 8' for slot in (7,8)]
    expected += [f'call void @llvm.lifetime.start.p0(ptr nonnull %{slot})' for slot in (7,8)]
    expected += ['%327 = ptrtoint ptr %325 to i64','store i64 %327, ptr %7, align 8',
        '%333 = phi ptr [ %8, %322 ], [ %7, %314 ]','store ptr %334, ptr %333, align 8',
        '%.0..0..0.5.i.i.i.i = load i64, ptr %7, align 8',
        '%.0..0..0..i.i.i.i = load i64, ptr %8, align 8']
    expected += [f'call void @llvm.lifetime.end.p0(ptr nonnull %{slot})' for slot in (7,8)]*3
    actual=[line for line in lines if set(re.findall(g.SSA,line)) & {'%7','%8','%333','%327'}]
    s.require(Counter(actual)==Counter(expected),'complete nonescaping iterator temporary access population')


def configuration(lines,lane):
    narrow=lane=='simd256';defs=g.ir.definitions(lines)
    roots={'%20':[('inputs',0,0)],'%19':[('workspace',0,0)],'%38':[('owner',0,0)]} if narrow else {
        '%2':[('inputs',0,0)],'%4':[('workspace',0,0)],'%1':[('owner',0,0)]}
    groups=(
        (('%86','%317','%380','%454','%547','%373','%434','%447','%481','%501','%516','%505','%570','%577','%318'),7),
        (('%578',),280),(('%622',),63),
    ) if narrow else (
        (('%179','%187','%214','%233','%310','%372','%391','%412','%430','%531','%201','%357',
          '%455','%479','%494','%483','%554','%560'),3),
        (('%561',),120),(('%593',),127),(('%695',),64),
        (('%859',),1),(('%867',),2),(('%875',),3),
    )
    bounds={name:(0,maximum) for names,maximum in groups for name in names}
    s.require(all(name in defs for name in bounds),'all assigned field index expressions exist')
    if narrow:
        iterator_temporaries(lines)
        s.require(defs.get('%19')=='alloca [5280 x i8], align 32' and
                  defs.get('%20')=='alloca [320 x i8], align 8','private narrow metadata allocations')
        # The public compaction interpreter and narrow pointer lifetime proof
        # independently bind this iterator's emitted pointer/integer roundtrip.
        expected={
            '%312':'getelementptr inbounds nuw i8, ptr %19, i64 512',
            '%324':'getelementptr inbounds nuw [32 x i8], ptr %312, i64 %317',
            '%325':'getelementptr inbounds nuw { [32 x i8], i8, [7 x i8] }, ptr %20, i64 %317',
            '%334':'phi ptr [ %324, %322 ], [ null, %314 ]',
            '%327':'ptrtoint ptr %325 to i64',
            '%337':'inttoptr i64 %.0..0..0.5.i.i.i.i to ptr',
            '%338':'inttoptr i64 %.0..0..0..i.i.i.i to ptr',
            '%333':'phi ptr [ %8, %322 ], [ %7, %314 ]',
            '%.0..0..0.5.i.i.i.i':'load i64, ptr %7, align 8',
            '%.0..0..0..i.i.i.i':'load i64, ptr %8, align 8',
            '%969':'phi ptr [ %967, %966 ], [ %974, %997 ]',
            '%974':'getelementptr inbounds nuw i8, ptr %969, i64 32',
            '%970':'phi i64 [ 256, %966 ], [ %975, %997 ]',
            '%975':'add nsw i64 %970, -32',
            '%972':'icmp eq i64 %970, 0',
            '%996':'icmp ugt i64 %995, 32',
        }
        s.require(all(defs.get(k)==v for k,v in expected.items()),'exact compaction iterator address roundtrip')
        roots.update({'%337':[('inputs',0,280)],'%338':[('workspace',512,736)],
                      '%969':[('owner',16,240)]})
        uses=[line for line in lines if re.search(r'%327\b',line)]
        s.require(uses==['%327 = '+expected['%327'],'store i64 %327, ptr %7, align 8'],
                  'integer descriptor address only enters reviewed temporary')
    known,_=g.aliases(lines,roots,bounds)
    authority_fields=[alias for alias,spans in known.items()
                      if spans==[('owner',8 if narrow else 0,8 if narrow else 0)]]
    authorities={name for name,expr in defs.items() if any(expr==f'load ptr, ptr {alias}, align 8'
                                                         for alias in authority_fields)}
    s.require(len(authorities)==(5 if narrow else 7),'complete authority field reload population')
    for name in authorities:roots[name]=[('authority',0,0)]
    return roots,bounds


def special(lane):
    def allow(at,line,used,known):
        if re.fullmatch(g.SSA+r' = icmp eq ptr '+g.SSA+', null',line):return True
        if lane=='simd256':
            return line in ('%327 = ptrtoint ptr %325 to i64','store ptr %334, ptr %333, align 8',
                           '%969 = phi ptr [ %967, %966 ], [ %974, %997 ]')
        return False
    return allow


def overlap(span,low,high):return span[1]<high and low<span[2]


def initialization_edges(lines,edges,narrow):
    """Definition blocks cannot be reached through an added bypass edge."""
    def predecessors(label,expected):
        at=lines.index(label+':')
        actual={i for i,targets in edges.items() if at in targets}
        s.require(actual=={lines.index(text) for text in expected},'complete metadata initializer predecessors')
    if narrow:
        defs=g.ir.definitions(lines)
        suffix='_RNvMNtCscJA3KwNFXab_16brynja_hash_core10bit_stringNtB2_9BitString3new.exit.i.thread3'
        s.require(defs['%86']==f'phi i64 [ %88, %{suffix} ], [ 0, %37 ]' and
                  defs['%exitcond.not']=='icmp eq i64 %86, 8' and
                  defs['%88']=='add nuw nsw i64 %86, 1','bounded paired input initialization induction')
        predecessors('94',['br i1 %exitcond.not, label %94, label %87'])
        predecessors('341',['br i1 %335, label %341, label %336'])
    else:predecessors('146',['br i1 %878, label %146, label %879','br label %146'])


def validate(lines,lane,known,records):
    narrow=lane=='simd256';start,end=(4096,4104) if narrow else (4576,4580)
    input_reads=[];index_reads=[];input_writes=[];index_writes=[];writes=[];calls=[]
    input_kills=[];index_kills=[]
    for row in records:
        at=row['line']
        if row['kind']=='call':
            spans,killed=effects.calls(row,known,lane);calls.append(row['target'])
            if any(root=='workspace' and low==high==0 for root,low,high in killed):index_kills.append(at)
            if any(root=='inputs' for root,_,_ in killed):input_kills.append(at)
        elif row['kind']=='write':spans=row['spans']
        else:
            for span in row['spans']:
                if span[0]=='inputs':input_reads.append(at)
                if span[0]=='workspace' and overlap(span,start,end):index_reads.append(at)
                if span[0]=='authority':
                    allowed={'ptr':[(8,16)],'i64':[(0,8)],'i8':[(16,17),(17,18)]}
                    s.require(tuple(span[1:]) in allowed.get(row['type'],[]),'authority field read identity and width')
            continue
        for span in spans:
            root,low,high=span;writes.append(dict(line=at,root=root,span=[low,high]))
            if root=='inputs':
                s.require(narrow and row['kind']=='write','input descriptors never written by callees')
                input_writes.append(row)
            if root=='authority':
                s.require(0<=low<high<=8 or 16<=low<high<=17,'immutable authority callback/backend fields')
            if root=='owner':
                s.require(not overlap(span,8 if narrow else 0,16 if narrow else 16),
                          'original authority/minimum fields preserved')
            if root=='workspace' and overlap(span,start,end):
                if at in index_kills:continue
                s.require(row['kind']=='write' and start<=low<high<=end,'only compact initialization writes indices')
                index_writes.append(row)
    # Exactly the assigned typed initialization stores, no later writes or
    # alternative alias destinations. Values are also bound, not only widths.
    if narrow:
        expected=[('i8','2',f'%{55+i}') for i in range(8)]+[
            ('ptr','%1028','%89'),('i8','%.sroa.9.sroa.0.1','%1053'),
            ('i56','%.sroa.9.sroa.9.sroa.0.1','%1054'),('i64','%.sroa.16.1','%.sroa.4.0..sroa_idx'),
            ('i8','%.sroa.17.1','%.sroa.5.0..sroa_idx'),('i8','%1052','%1055')]
        s.require([(r['type'],r['value'],r['address']) for r in input_writes]==expected,
                  'one complete narrow typed input initialization')
    else:s.require(not input_writes,'wide input descriptors immutable')
    expected=[('i64','0','%146'),('i8','%719','%720')] if narrow else [
        ('i8','1','%864'),('i8','2','%872'),('i8','3','%880'),('i8','0','%142')]
    s.require([(r['type'],r['value'],r['address']) for r in index_writes]==expected,
              'exact compact initializer write population')
    edges=g.cfg(lines)
    initialization_edges(lines,edges,narrow)
    # The compaction loop's completed block is the definition event. Any wipe,
    # lifetime end or attempted late initializer invalidates the old fact.
    complete=lines.index('341:' if narrow else '146:')
    input_complete=lines.index('94:') if narrow else 1
    g.lifetime(edges,input_reads,[input_complete],input_kills+[r['line'] for r in input_writes])
    g.lifetime(edges,index_reads,[complete],index_kills+[r['line'] for r in index_writes])
    return dict(input_reads=sorted(set(input_reads)),index_reads=sorted(set(index_reads)),
        input_initialization_writes=[r['line'] for r in input_writes],
        compact_initialization_writes=[r['line'] for r in index_writes],
        input_complete=input_complete,compaction_complete=complete,
        input_lifetime_ends=input_kills,workspace_invalidations=index_kills,
        write_effects=writes,call_count=len(calls))


def inspect(bodies,ir,lane):
    s.require(lane in ('simd256','simd512'),'assigned metadata SIMD route')
    name=s.one(bodies,r'Resident6digest$' if lane=='simd256' else r'Executor13digest_secret$')
    lines=g.ir.function(ir,name);seeds,bounds=configuration(lines,lane)
    known,records=g.inventory(lines,seeds,bounds,special(lane))
    result=validate(lines,lane,known,records)
    return dict(function=name,aliases=len(known),accesses=len(records),**result,
        conditional_input_and_authority_field_preservation_checked=True,
        compact_reads_require_completed_initialization_since_last_wipe=True,
        machine_geometry_primitive_and_pointer_origin_reviews_required=True,
        physical_allocation_separation_and_lifetime_composition_pending=True,
        caller_private_frames_and_failstop_composition_pending=True,whole_frame_qualified=False)
