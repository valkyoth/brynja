"""Sixteen caller wipe footprints; runtime, other calls and lifetimes stay open."""
import re
import windows_enclave_sha3_simd_loop_effects as loop
w,o,s,life=loop.w,loop.o,loop.s,loop.life
SLOTS=tuple(sorted(set(loop.model.SLOTS)|set(w.SLOTS)|{488,496,712,720,776}))
WORKSPACE=(73,530,1588,1598)
STAGING=(533,1591,1601)
FRAMES={105:(32,72),110:(104,51),114:(0,32),118:(155,1)}
SCRATCH={1075:(2720,800),1314:(4960,40),1317:(5000,40),1320:(5040,200)}
SITES=set(WORKSPACE)|set(STAGING)|set(FRAMES)|set(SCRATCH)|{1329}


def constant_length(code,states,site,wanted):
    """No truncation, unknown register producer or stale predecessor may pass."""
    defs=states[site]['rdx']
    s.require(defs,'nonvacuous wipe length definitions')
    for at in defs:
        s.require(at>=0,'wipe length initialized on every predecessor')
        match=re.fullmatch(r'mov([lq]) \$(\d+), %(edx|rdx)',code[at])
        s.require(match is not None and (match[1],match[3]) in (('l','edx'),('q','rdx')) and
            int(match[2])==wanted and 0<wanted<=5260,'exact positive wipe length on all predecessors')


def guarded_frame_calls(code,edges,states):
    w.guarded_lane(code,edges,states)
    todo=[0];seen=set()
    while todo:
        at=todo.pop()
        if at in seen:continue
        seen.add(at);todo.extend(v for v in edges[at] if (at,v)!=(95,96))
    s.require(not (set(FRAMES)&seen),'unsigned lane guard dominates all four frame wipe calls')
    effects=[]
    for site,(offset,size) in FRAMES.items():
        s.require(code[site]=='callq '+life.ZERO and
            w.expression(code,states,site,'rcx')=={('workspace',3584+offset,156)},
            'original per-lane frame wipe receiver and actual volatile-clear callee')
        constant_length(code,states,site,size)
        spans=[[3584+156*lane+offset,3584+156*lane+offset+size] for lane in range(4)]
        s.require(all(3584+156*lane<=lo<hi<=3584+156*(lane+1)
            for lane,(lo,hi) in enumerate(spans)),'each frame wipe stays in its original lane')
        effects.append(dict(site=site,root='workspace',write_spans=spans,bytes_per_call=size))
    # The four actual calls partition the entire frame, rather than leaving
    # padding gaps or crossing into the next live lane.
    s.require(sorted(i for offset,size in FRAMES.values() for i in range(offset,offset+size))==list(range(156)),
        'complete nonoverlapping frame wipe partition')
    return effects


def separate(effects,geometry):
    s.require(effects,'nonvacuous clearing footprint population')
    objects=geometry['executor_entry_objects'];physical=[]
    for effect in effects:
        root=effect['root'];s.require(root in ('workspace','staging'),'assigned clearing allocation')
        start,end=objects[root]
        s.require(end-start=={'workspace':5260,'staging':1024}[root] and start>=-1200+1128,
            'original allocation size and separation from executor child frame')
        for lo,hi in effect['write_spans']:
            s.require(0<=lo<hi<=end-start,'wipe length contained in its original allocation')
            s.require(all(start+hi<=a or b<=start+lo for key,(a,b) in objects.items() if key!=root),
                'wipe excludes all other simultaneous caller objects')
            physical.append(dict(site=effect['site'],root=root,span=[start+lo,start+hi]))
    return physical


def inspect(bodies,assembly,caller,wipe,scalar,previous):
    n=o.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==wipe['function']==scalar['function']==previous['function']==n['executor'] and
        wipe['all_normal_predecessor_direct_pointer_origins_checked'] and
        scalar['whole_scalar_owner_wiped_before_checked_report_increment'] and
        previous['direct_executor_store_inventory_assigned'] and not previous['pending_non_frame_store_sites'],
        'replayed wipe origins, scalar clearing and complete direct-store population')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry()
    helper_geometry=o.reconcile.terminal.shape.reject.digest.helpers.geometry()
    s.require(caller['geometry']==geometry and caller['helpers']['geometry']==helper_geometry and
        caller['helpers']['functions']['workspace_wipe']==n['workspace_wipe'] and
        caller['helpers']['functions']['scalar_wipe']==n['scalar_wipe'],
        'same caller allocations and previously replayed complete helper write ranges')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,SLOTS);original=o.analyse(code,edges,spans)
    effects=guarded_frame_calls(code,edges,states)
    for site in WORKSPACE:
        s.require(code[site]=='callq '+n['workspace_wipe'] and original[site]['rcx']=={'workspace'},
            'whole workspace wipe receiver is only original workspace')
        effects.append(dict(site=site,root='workspace',write_spans=[[0,5260]],bytes_per_call=5260))
    for site in STAGING:
        s.require(code[site]=='callq '+life.ZERO and original[site]['rcx']=={'staging'},
            'staging wipe receiver is only original staging')
        constant_length(code,states,site,1024)
        effects.append(dict(site=site,root='staging',write_spans=[[0,1024]],bytes_per_call=1024))
    for site,(offset,size) in SCRATCH.items():
        s.require(code[site]=='callq '+life.ZERO and
            loop.roots(code,states,site,'rcx',slots=SLOTS)=={offset},
            'group/scalar scratch wipe has original workspace subobject origin')
        constant_length(code,states,site,size)
        effects.append(dict(site=site,root='workspace',write_spans=[[offset,offset+size]],bytes_per_call=size))
    s.require(code[1329]=='callq '+n['scalar_wipe'] and
        loop.roots(code,states,1329,'rcx',slots=SLOTS)=={4208} and
        helper_geometry['scalar_owner_bytes']==1040,'actual complete scalar owner wipe at original workspace offset')
    effects.append(dict(site=1329,root='workspace',write_spans=[[4208,5248]],bytes_per_call=1040))
    physical=separate(effects,geometry);pending=set(previous['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==37,'exact remaining callee-effect population')
    return dict(function=n['executor'],call_sites=sorted(SITES),write_effects=sorted(effects,key=lambda e:e['site']),
        parent_relative_effects=physical,frame_wipes_cover_each_156_byte_lane_exactly=True,
        original_all_predecessor_receivers_and_lengths_checked=True,
        writes_exclude_other_caller_allocations_and_child_frame=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        volatile_clear_runtime_and_win64_nonvolatile_abi_required=True,
        other_callee_memory_effects_and_pointer_preservation_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
