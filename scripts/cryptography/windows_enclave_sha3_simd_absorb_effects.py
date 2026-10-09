"""Absorption destination induction and internal-byte sources, not lifetimes."""
from collections import deque
import re
import windows_enclave_sha3_simd_squeeze_effects as previous
import windows_enclave_sha3_simd_absorb as absorb
w,o,s,life,loop,m=previous.w,previous.o,previous.s,previous.life,previous.loop,previous.m
COPIES=previous.copies
SITES={782,899}
XOR_SITES={782,827,851,899}
NODES=set(range(683,914))
SLOTS=tuple(sorted(set(m.SLOTS)|{512,528,536,544,552,560,568,576,584,760,768,816,
    840,848,872,904,920,952,960,976}))


def transfer(line,before,span=None):
    after=m.transfer(line,before)
    op,args=o.instruction(line)
    if op=='leaq':
        match=re.fullmatch(r'(-?\d*)\(%rbp\)',args[0])
        if match:after[o.ALIASES[args[-1]]]=m.one('child_frame',int(match[1] or 0))
    if span:
        lo,hi=span
        for slot in SLOTS:
            if lo<slot+8 and slot<hi:
                after[slot]=m.operand(args[0],before) if op=='movq' and (lo,hi)==(slot,slot+8) else m.UNKNOWN
    return after


def flow(code,edges,n):
    s.require(code[648:920]==absorb.shape.shape(n),'complete actual absorption instructions')
    incoming={(p,v) for p,ds in edges.items() for v in ds if p not in range(648,920) and v in range(648,920)}
    s.require(incoming=={(647,648)},'single original entry before absorption address setup')
    # Derive every edge from the instructions and already-linked nine-part table,
    # including exits and duplicate table targets. No bypass of setup is allowed.
    for at in range(648,920):
        op,args=o.instruction(code[at]);want=[at+1]
        if op.startswith('j'):
            want=[code.index('.B'+str(v)+':') for v in absorb.shape.TARGETS] if at in (718,759) else [code.index(args[0]+':')]
            if op not in ('jmp','jmpq'):want.append(at+1)
        s.require(edges[at]==want,'exact absorption branch, fallthrough and rejection edges')


def entry(code,edges,spans,states,lane,rate):
    s.require(type(lane) is int and 0<=lane<4 and type(rate) is int and rate in absorb.model.framing.RATES,
        'bounded original lane and validated positive rate')
    loop.loop_entry(code,edges,states)
    for at,slot,offset in ((649,824,3584),(656,960,1920)):
        s.require(loop.roots(code,states,at,slot,slots=SLOTS)=={offset},'original absorption frame/state root cells')
    observed=[]
    def observe(at,before):
        if at==648:
            s.require(before['r9']==m.one('number',lane) and before['r8']==m.one('number',112*lane) and
                before['rdx']==m.one('workspace',3624+156*lane), 'original lane/input/frame-length induction at absorption entry')
            observed.append(before.copy())
    m.check_lane(code,edges,spans,lane,observe)
    s.require(observed,'nonvacuous absorption-entry observation')
    initial={k:m.UNKNOWN for k in (*o.REGS,*SLOTS)}
    initial.update(observed[-1]);initial[960]=m.one('workspace',1920)
    for at in range(648,683):
        initial=transfer(code[at],initial,spans.get(at))
        # The actual linked table is replayed by absorb.inspect. The only
        # successful path here has the receiver-validated identity's rate.
        if at==660:initial['rax']=m.one('number',rate)
    frame=3584+156*lane;state=1920+200*lane
    s.require(initial['r11']==m.one('workspace',state) and initial['r12']==m.one('workspace',frame) and
        initial[576]==m.one('workspace',state+rate) and initial[568]==m.one('workspace',frame+155) and
        initial[512]==m.one('workspace',frame+104),'original first state byte, linked-rate end and internal source cells')
    return initial


def byte_induction(code,edges,spans,initial,n,lane):
    s.require(type(lane) is int and 0<=lane<4,'one original lane')
    initial=initial.copy();initial['r11']=m.one('byte_cursor',0);initial[576]=m.one('state_end',0)
    states={683:initial};todo=deque([683]);backedges=set();exits=set();calls=set()
    stable={slot:initial[slot] for slot in (512,568,576,824,960,1104)}
    while todo:
        at=todo.popleft();before=states[at];after=transfer(code[at],before,spans.get(at))
        if at in XOR_SITES:
            s.require(code[at]=='callq '+n['xor'] and before['rcx']==m.one('byte_cursor',0),
                'every XOR destination is the unchanged current state byte')
            if at in SITES:
                want=m.one('workspace',3584+156*lane+155) if at==782 else m.one('child_frame',176)
                s.require(before['rdx']==want,'actual one-byte internal suffix/padding source')
            calls.add(at)
        if at==913:
            s.require(before['r11']==m.one('byte_cursor',1) and before['r12']==m.one('workspace',3584+156*lane) and
                all(before[k]==v for k,v in stable.items()),
                'one-byte increment and unchanged end/source/root cells on every byte backedge')
        for dest in edges[at]:
            if dest==683:
                s.require(at==913,'only the guarded one-byte advance repeats the state loop');backedges.add(at);continue
            if dest not in NODES:exits.add((at,dest));continue
            joined=after if dest not in states else {k:m.merge(states[dest][k],after[k]) for k in initial}
            if states.get(dest)!=joined:states[dest]=joined;todo.append(dest)
    s.require(states.keys()==NODES and calls==XOR_SITES and backedges=={913},
        'all byte-loop positions, four XOR calls and the sole bounded backedge observed')
    return dict(lane=lane,reachable_positions=len(states),destination_sites=sorted(calls),backedges=sorted(backedges),exits=sorted(exits))


def physical(geometry):
    effects=[]
    for lane in range(4):
        dst=[1920+200*lane,1920+200*lane+168];suffix=3584+156*lane+155
        effects.extend((dict(site=782,read_root='workspace',read=[suffix,suffix+1],write=dst),
            dict(site=899,read_root='child_frame',read=[176,177],write=dst)))
    COPIES.clear.separate([dict(site=e['site'],root='workspace',write_spans=[e['write']]) for e in effects],geometry)
    origin,end=geometry['executor_entry_objects']['workspace'];s.require(end-origin==5260,'complete workspace allocation')
    rows=[]
    for e in effects:
        lo,hi=e['read'];root=e['read_root'];s.require(hi-lo==1,'one-byte XOR source')
        s.require(0<=lo<hi<=5260 if root=='workspace' else -128<=lo<hi<=1000,'internal source within original allocation')
        source=[(origin if root=='workspace' else -1200)+v for v in (lo,hi)];dest=[origin+v for v in e['write']]
        s.require(source[1]<=dest[0] or dest[1]<=source[0],'internal byte source and every destination byte disjoint')
        if root=='child_frame':
            s.require(all(source[1]<=a or b<=source[0] for a,b in geometry['executor_entry_objects'].values()),
                'child padding byte excludes caller allocations')
        rows.append(dict(site=e['site'],read=source,write_envelope=dest,access_bytes=1))
    return rows


def inspect(bodies,assembly,caller,absorbing,frame,prior):
    n=absorb.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==absorbing['function']==frame['function']==prior['function']==n['executor'] and
        absorbing['helpers']['functions']['xor']==n['xor'] and absorbing['helpers']['invalid_parameters_rejected_before_secret_read'] and
        absorbing['helpers']['valid_count']==[1,8] and absorbing['linked_rates']==list(absorb.model.framing.RATES) and
        absorbing['readonly_bit_sources_and_two_byte_splits_checked'] and
        absorbing['cursor_block_count_and_absorbing_to_ready_transition_checked'] and
        frame['child_frame_origin_in_parent']==-1200 and frame['bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'] and
        prior['original_state_staging_roots_and_lane_induction_checked'] and not prior['pending_non_frame_store_sites'],
        'replayed XOR ABI/one-byte helper, framing/rates, caller frame and prior effect contracts')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry();s.require(caller['geometry']==geometry,'same original caller geometry')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,SLOTS);flow(code,edges,n)
    lanes=[]
    for lane in range(4):
        for rate in sorted(set(absorb.model.framing.RATES)):
            initial=entry(code,edges,spans,states,lane,rate)
            row=byte_induction(code,edges,spans,initial,n,lane);row['rate']=rate;lanes.append(row)
    pending=set(prior['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==20,'exact remaining internal absorption call population')
    return dict(function=n['executor'],call_sites=sorted(SITES),destination_sites=sorted(XOR_SITES),
        byte_loop_inductions=lanes,parent_relative_internal_effects=physical(geometry),
        all_four_destinations_within_original_lane_rate=True,internal_sources_original_single_bytes=True,
        byte_cursor_spill_restore_and_single_increment_checked=True,
        external_source_sites_pending=[827,851],requires_receiver_validated_identity_and_live_descriptor_metadata=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        other_callee_effects_and_win64_nonvolatile_preservation_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
