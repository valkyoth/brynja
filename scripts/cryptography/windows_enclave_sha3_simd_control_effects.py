"""Original control/result/quarantine write roots; other memory effects stay open."""
from collections import deque
import re
import windows_enclave_sha3_simd_frame_effects as frames
origins=frames.origins
s,life=frames.s,frames.life
SLOTS=(440,800,952,960,968,976,1120)
UNKNOWN=origins.UNKNOWN
STORES={65:('authority',16,1),537:('executor',16,1),541:('authority',16,1),
    1375:('authority',16,1),1070:('control',16,8),1071:('control',24,8),
    1278:('control',16,8),1279:('control',24,8),546:('result',0,1),547:('result',129,1),
    1646:('result',96,8),1650:('result',64,16),1652:('result',80,8),1654:('result',88,8),
    1655:('result',32,32),1656:('result',0,32),1657:('result',105,4),1660:('result',111,1),
    1662:('result',109,2),1664:('result',112,8),1666:('result',120,8),1668:('result',128,1),
    1669:('result',104,1),1671:('result',129,1)}


def analyse(code,edges,spans):
    keys=(*origins.REGS,*SLOTS);initial={k:UNKNOWN for k in keys}
    initial.update(rcx=frozenset({'result'}),rdx=frozenset({'executor'}))
    initial[1120]=frozenset({'control'});states={0:initial};queue=deque([0])
    def value(v,state):
        if v.startswith('%') and v[1:] in origins.REGS:return state[v[1:]]
        match=re.fullmatch(r'(\d+)\(%rbp\)',v)
        if match:return state.get(int(match[1]),UNKNOWN)
        match=re.fullmatch(r'\(%(\w+)\)',v)
        if match and match[1] in origins.REGS:
            # This token is the pointer stored in executor field zero, not proof
            # it is nonnull, live or disjoint. Those caller prerequisites remain.
            return frozenset('authority' if root=='executor' else 'unknown' for root in state[match[1]])
        return UNKNOWN
    while queue:
        at=queue.popleft();before=states[at];after=before.copy();op,args=origins.instruction(code[at])
        if op=='callq':
            for r in origins.VOLATILE:after[r]=UNKNOWN
        elif op in ('divl','divq'):after['rax']=after['rdx']=UNKNOWN
        elif op in origins.WRITE|{'popq'} and args:
            reg=origins.ALIASES.get(args[-1]);incoming=value(args[0],before) if op=='movq' else UNKNOWN
            if reg:after[reg]=before[reg]|incoming if op.startswith('cmov') else incoming
            if at in spans:
                lo,hi=spans[at]
                for slot in SLOTS:
                    if lo<slot+8 and slot<hi:after[slot]=incoming if (lo,hi)==(slot,slot+8) else UNKNOWN
        for dest in edges[at]:
            merged=after if dest not in states else {k:states[dest][k]|after[k] for k in keys}
            if states.get(dest)!=merged:states[dest]=merged;queue.append(dest)
    return states


def writes(code,states):
    result=[]
    for at,(root,offset,width) in STORES.items():
        op,args=origins.instruction(code[at])
        match=re.fullmatch(r'(\d*)\(%(\w+)\)',args[-1]) if args else None
        if op=='vmovups':s.require(re.fullmatch(r'%[xy]mm\d+',args[0]) is not None,'assigned vector width')
        actual=(32 if args[0].startswith('%ymm') else 16) if op=='vmovups' else {
            'movb':1,'movw':2,'movl':4,'movq':8}.get(op)
        s.require(match is not None and int(match[1] or 0)==offset and actual==width,
            'exact assigned control/result store displacement and width')
        s.require(match[2] in states[at] and states[at][match[2]]=={root},
            'all store predecessors use only the original root')
        result.append(dict(site=at,root=root,write=[offset,offset+width]))
    return result


def placement(effects,geometry,child_origin):
    objects=geometry['executor_entry_objects'];physical=[]
    s.require(child_origin==-1200,'same bound child stack frame origin')
    for effect in effects:
        root=effect['root'];lo,hi=effect['write']
        if root=='authority':
            s.require((lo,hi)==(16,17),'authority writes only its health byte');continue
        s.require(root in ('control','result','executor'),'assigned caller allocation')
        start,end=objects[root]
        s.require(0<=lo<hi<=end-start,'write contained in the original caller allocation')
        span=(start+lo,start+hi)
        s.require(all(span[1]<=a or b<=span[0] for key,(a,b) in objects.items() if key!=root),
            'writes exclude every other simultaneous caller allocation')
        s.require(span[0]>=child_origin+1128,'writes exclude child frame, saved registers and incoming arguments')
        physical.append(dict(site=effect['site'],root=root,parent_relative_span=list(span)))
    return physical


def inspect(bodies,assembly,caller,frame_effects,terminal,vector,scalar):
    n=origins.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==frame_effects['function']==terminal['function']==
        vector['function']==scalar['function']==n['executor'] and
        terminal['ordinary_rejection_retains_reuse_and_integrity_failure_quarantines'] and
        terminal['vector_call_counter_preserved_across_mixed_width_serialization'] and
        vector['control_charge_committed_before_state_copy'] and
        scalar['whole_scalar_owner_wiped_before_checked_report_increment'],
        'replayed control/health/report semantics and same executor')
    geometry=origins.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same caller allocation geometry')
    edges,_=origins.reconcile.graph(code,assembly);spans,_,_=origins.frame_writes(code,edges)
    states=analyse(code,edges,spans);effects=writes(code,states)
    s.require(len(states)==1676 and all(state[1120]=={'control'} for state in states.values()),
        'complete normal CFG and untouched direct incoming control slot')
    physical=placement(effects,geometry,frame_effects['child_frame_origin_in_parent'])
    pending=set(frame_effects['pending_non_frame_store_sites'])
    s.require(set(STORES)<=pending and len(pending-set(STORES))==33,'exact remaining indirect store population')
    return dict(function=n['executor'],reachable_positions=len(states),write_effects=effects,
        caller_relative_effects=physical,tracked_pointer_slots=list(SLOTS),
        original_control_executor_result_and_authority_pointer_roots_checked=True,
        caller_allocated_writes_exclude_other_objects_and_child_frame=True,
        authority_writes_limited_to_health_byte=True,
        authority_allocation_lifetime_nonnull_and_physical_separation_required=True,
        original_executor_authority_field_preservation_by_other_effects_required=True,
        pending_non_frame_store_sites=sorted(pending-set(STORES)),
        pending_callee_effect_sites=frame_effects['pending_callee_effect_sites'],
        other_callee_and_indirect_memory_effects_still_required=True,
        private_frame_and_exception_cleanup_qualified=False)
