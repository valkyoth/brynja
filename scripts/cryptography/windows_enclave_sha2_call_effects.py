"""Conditional argument-region composition for twelve scalar helper calls.

The parent replays complete primitive contracts and binds their emitted bytes.
This connects actual call arguments to object-relative regions; it does not
establish original object placement/lifetime, nor callee stack/home-space bounds.
"""
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_store_effects as e
import windows_enclave_sha2_simd_storage as storage


def region(pointer,offset,length):
    s.require(pointer is not None and pointer.object is not None and pointer.low==pointer.high,
              'exact named primitive pointer')
    s.require(type(length) is int and 0<length<(1<<63),'bounded positive primitive extent')
    low=pointer.low+offset;high=low+length
    s.require(0<=low<high<(1<<64),'nonwrapping primitive region')
    return dict(object=pointer.object,span=[low,high])


def disjoint(a,b):
    # Different symbolic objects are NOT proof of different physical storage.
    s.require(a['object']==b['object'],'relative disjointness needs common assigned object')
    return a['span'][1]<=b['span'][0] or b['span'][1]<=a['span'][0]


def footprint(role,regs,lane):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned scalar helper lane')
    if role=='zero':
        length=regs.get('rdx')
        s.require(length is not None and length.object is None and length.low==length.high,
                  'exact clearing length at call')
        return dict(reads=[],writes=[region(regs.get('rcx'),0,length.low)])
    if role=='wipe':
        parts=storage.regions(lane)[1]
        s.require(parts==[(1024,64),(0,128),(1152,16),(1168,2),(128,640),
                          (768,128),(896,128),(1088,64)],'complete scalar owner field extents')
        return dict(reads=[],writes=[region(regs.get('rcx'),off,size) for off,size in parts])
    s.require(role=='compress','assigned scalar helper role')
    state=region(regs.get('rcx'),0,32 if narrow else 64)
    block=region(regs.get('rdx'),0,64 if narrow else 128)
    # Both actual scalar kernels clear the complete 640-byte schedule/work area,
    # even though SHA-256's round schedule alone occupies only 256 bytes.
    scratch=region(regs.get('r8'),0,640)
    s.require(all(disjoint(a,b) for a,b in ((state,block),(state,scratch),(block,scratch))),
              'scalar state/block/scratch disjoint within assigned object')
    return dict(reads=[state,block,scratch],writes=[state,scratch])


def traces(lines,lane,names):
    narrow=lane=='simd256';frame=e.Value('frame',0,0);obj='frame' if narrow else 'workspace'
    origin=10792 if narrow else 4580
    regs={'rbx':frame} if narrow else {'rbp':frame,'rbx':e.Value(obj,origin,origin)}
    memory={} if narrow else {('frame',760):e.Value(obj,origin,origin),
        ('frame',1016):e.Value(obj,5604,5604),('frame',1024):e.Value(obj,5348,5348),
        ('frame',968):e.Value(obj,4708,4708),('frame',928):e.Value(obj,5476,5476)}
    calls={role:[i for i,line in enumerate(lines) if line=='callq '+name] for role,name in names.items()}
    s.require({role:len(v) for role,v in calls.items()}=={'wipe':2,'compress':1,'zero':3},
              'complete selected scalar-helper caller population')
    jobs=[]
    for at in calls['wipe']:
        jobs.append((at-(1 if narrow else 2),at+1,['wipe']))
    at=calls['compress'][0]
    s.require(calls['zero'][:2]==[at+3,at+6],'compression followed by schedule/block clears')
    jobs.append((at-5,at+7,['compress','zero','zero']))
    at=calls['zero'][2];jobs.append((at-2,at+1,['zero']))
    result=[]
    for begin,end,roles in jobs:
        s.require(0<=begin<end<=len(lines),'bounded helper argument slice')
        snapshots=[]
        stores=e.evaluate(lines[begin:end],regs,memory,set(names.values()),snapshots)
        s.require(not stores,'argument slices cannot hide memory writes')
        s.require([name for name,_ in snapshots]==[names[role] for role in roles],
                  'ordered exact helper-call slice')
        sites=[i for i in range(begin,end) if lines[i].startswith('callq ')]
        for site,role,(_,arguments) in zip(sites,roles,snapshots,strict=True):
            result.append(dict(line=site,role=role,target=names[role],**footprint(role,arguments,lane)))
    return sorted(result,key=lambda v:v['line'])


def expected(lane):
    narrow=lane=='simd256';obj='frame' if narrow else 'workspace'
    origin=10792 if narrow else 4580
    state=11816 if narrow else 5604;block=11560 if narrow else 5348
    scratch=10920 if narrow else 4708;pad=11688 if narrow else 5476
    def r(offset,size):return dict(object=obj,span=[offset,offset+size])
    wipe=dict(reads=[],writes=[r(origin+off,size) for off,size in storage.regions(lane)[1]])
    compress=dict(reads=[r(state,32 if narrow else 64),r(block,64 if narrow else 128),r(scratch,640)],
                  writes=[r(state,32 if narrow else 64),r(scratch,640)])
    clears=[dict(reads=[],writes=[r(p,n)]) for p,n in ((scratch,640),(block,128),(pad,128))]
    return [wipe,wipe,compress,*clears] if narrow else [wipe,compress,*clears,wipe]


def inspect(bodies,lane,frame):
    names={role:s.one(bodies,regex) for role,regex in (
        ('wipe',r'HardenedSha2Owner4wipe$'),
        ('compress',r'hardened10compress'+('32' if lane=='simd256' else '64')+r'6native6scalar$'),
        ('zero',r'secret_memory_volatile23zeroize_region_volatile$'))}
    lines=s.lines(bodies[frame['function']]);lines=lines[lines.index(frame['begin']+':'):lines.index(frame['end']+':')]
    effects=traces(lines,lane,names)
    s.require([dict(reads=v['reads'],writes=v['writes']) for v in effects]==expected(lane),
              'exact caller-composed primitive regions')
    inventory=frame['calls_pending_indirect_effect_composition']
    selected=[v for v in inventory if v['target'] in names.values()]
    s.require([dict(line=v['line'],target=v['target']) for v in effects]==selected,
              'all selected inventoried calls have composed argument effects')
    return dict(calls=effects,conditional_argument_call_count=len(effects),
        other_call_effects_pending=[v for v in inventory if v not in selected],
        parent_complete_primitive_contract_replay_required=True,
        original_live_pointer_and_slot_preservation_preconditions_required=True,
        callee_stack_and_home_space_composition_pending=True,
        complete_saved_pointer_lifetime_qualified=False,whole_frame_qualified=False)
