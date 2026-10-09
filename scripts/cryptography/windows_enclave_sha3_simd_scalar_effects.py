"""Scalar loop induction and three call footprints, not full lifetime closure."""
from collections import deque
import windows_enclave_sha3_simd_copy_effects as copies
import windows_enclave_sha3_simd_scalar_shape as shape
m=copies.loop.model
w,o,s,life=copies.w,copies.o,copies.s,copies.life
ROOTS={488:4960,496:4208,704:4256,712:5000,720:5040,888:5248,960:1920,1104:0}
SLOTS=tuple(sorted(set(ROOTS)|{952}))
NODES=set(range(1256,1338))
SITES={1303,1311,1325}
KERNEL=((4256,4456),(4960,5000),(5000,5040),(5040,5240))


def transfer(line,before,span=None):
    # Reuse the finite register domain, but independently handle every scalar
    # spill cell: slot 952 first holds authority, then the saved numeric lane.
    after=m.transfer(line,before)
    if span:
        op,args=o.instruction(line);lo,hi=span
        for slot in SLOTS:
            if lo<slot+8 and slot<hi:
                after[slot]=m.operand(args[0],before) if op=='movq' and (lo,hi)==(slot,slot+8) else m.UNKNOWN
    return after


def entry(code,edges,states):
    incoming={(at,v) for at,ds in edges.items() for v in ds if at not in NODES and v in NODES}
    s.require(incoming=={(1255,1260)} and code[1253:1261]==[
        '.B190:','xorl %esi, %esi','jmp .B192','.B191:','incq %rsi',
        'cmpq $4, %rsi','je .B206','.B192:'] and edges[1259]==[1338,1260],
        'single zero-initialized scalar entry and exact fourth-lane exit')
    for at in (1254,1255,1257,1258,1259):
        s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no bypass of scalar initialization/increment/guard')
    for slot,offset in ROOTS.items():
        s.require(copies.loop.roots(code,states,1260,slot,slots=SLOTS)=={offset},
            'original scalar-loop pointer cell on every external and backedge predecessor')


def check_lane(code,edges,spans,lane,n):
    s.require(type(lane) is int and 0<=lane<4,'one of four admitted scalar lanes')
    initial={k:m.UNKNOWN for k in (*o.REGS,*SLOTS)}
    initial.update({k:m.one('workspace',v) for k,v in ROOTS.items()})
    initial['rsi']=m.one('number',lane)
    states={1260:initial};todo=deque([1260]);backedges=set();exits=set();calls=set()
    state=1920+200*lane
    while todo:
        at=todo.popleft();before=states[at];after=transfer(code[at],before,spans.get(at))
        if at==1262:
            s.require(code[at]=='cmpb $1, (%rax,%rsi)' and before['rax']==m.one('workspace',5248) and
                before['rsi']==m.one('number',lane),'original readiness array indexed only by the bounded lane')
        if at in (1295,1296):
            s.require(before['rsi']==m.one('number',lane),'original lane survives both callback boundaries')
        if at in (1303,1325):
            dest,src=(4256,state) if at==1303 else (state,4256)
            s.require(code[at]=='callq '+n['copy'] and before['rcx']==m.one('workspace',dest) and
                before['r8']==m.one('workspace',src) and before['rdx']==before['r9']==m.one('number',200),
                'actual scalar copy with original lane/state roots and matching 200-byte extents')
            calls.add(at)
        if at==1311:
            s.require(code[at]=='callq '+n['scalar'] and all(before[reg]==m.one('workspace',span[0])
                for reg,span in zip(('rcx','rdx','r8','r9'),KERNEL,strict=True)),
                'actual scalar kernel receives four distinct original workspace regions')
            calls.add(at)
        destinations=edges[at]
        if at==1259:
            s.require(before['rsi']==m.one('number',lane+1) and
                all(before[k]==m.one('workspace',v) for k,v in ROOTS.items()),
                'every skip/completed-lane path restores its index and original pointer cells before increment')
            destinations=[1338 if lane==3 else 1260]
        for dest in destinations:
            if dest==1260:backedges.add(at);continue
            if dest not in NODES:exits.add((at,dest));continue
            merged=after if dest not in states else {k:m.merge(states[dest][k],after[k]) for k in initial}
            if states.get(dest)!=merged:states[dest]=merged;todo.append(dest)
    s.require(states.keys()==NODES and calls==SITES and (backedges=={1259} if lane<3 else not backedges),
        'complete scalar loop population and exactly the bounded lane backedge')
    return dict(lane=lane,reachable_positions=len(states),backedges=sorted(backedges),exits=sorted(exits),
        copy_cases=[dict(site=at,read_root='workspace',read=[src,src+200],write_root='workspace',
            write=[dest,dest+200],bytes=200) for at,dest,src in ((1303,4256,state),(1325,state,4256))])


def kernel_separation(regions,geometry):
    s.require(regions and len(regions)==4 and list(regions)==list(KERNEL),'exact four scalar state/scratch regions')
    for i,(lo,hi) in enumerate(regions):
        s.require(4208<=lo<hi<=5248 and all(hi<=a or b<=lo for a,b in regions[:i]),
            'four noalias buffers are pairwise disjoint and inside the scalar owner')
    return copies.clear.separate([dict(site=1311,root='workspace',write_spans=[list(v) for v in regions])],geometry)


def inspect(bodies,assembly,caller,scalar,frame,previous):
    n=shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==scalar['function']==frame['function']==previous['function']==n['executor'] and
        caller['helpers']['functions']['copy']==n['copy'] and caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['copy_leaf_length_limit']==1024 and scalar['scalar_kernel']['function']==n['scalar'] and
        scalar['scalar_kernel']['state_bytes']==200 and scalar['scalar_kernel']['scratch_bytes']==[40,40,200] and
        scalar['scalar_kernel']['opaque_stack_accesses']==0 and scalar['scalar_kernel']['linked_constants_independently_derived'] and
        scalar['scratch_wipes_before_copyback'] and scalar['whole_scalar_owner_wiped_before_checked_report_increment'] and
        frame['bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'] and
        previous['original_source_destination_and_length_definitions_checked'] and not previous['pending_non_frame_store_sites'],
        'replayed scalar kernel/ABI, copy helper, cleanup and previous caller footprints')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same original scalar caller allocation geometry')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,SLOTS);entry(code,edges,states)
    lanes=[check_lane(code,edges,spans,lane,n) for lane in range(4)]
    effects=[case for lane in lanes for case in lane['copy_cases']]
    physical=copies.physical_effects(effects,geometry,frame['child_frame_origin_in_parent'])
    kernel=kernel_separation(KERNEL,geometry)
    pending=set(previous['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==24,'exact remaining scalar-effect population')
    return dict(function=n['executor'],call_sites=sorted(SITES),per_lane_effects=lanes,
        copy_parent_relative_effects=physical,kernel_read_write_regions=[list(v) for v in KERNEL],
        kernel_parent_relative_effects=kernel,single_entry_four_lane_induction_checked=True,
        original_pointers_lengths_and_saved_index_restores_checked=True,
        scalar_copy_nonoverlap_and_kernel_noalias_regions_checked=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        callback_memory_effects_and_win64_nonvolatile_abi_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
