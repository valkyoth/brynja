"""Framing write roots/lanes; remaining loop effects and lifetimes stay open."""
from collections import deque
import re
import windows_enclave_sha3_simd_control_effects as control
origins=control.origins
s,life=control.s,control.life
SLOTS=(824,936,944,1104)
# Field offsets within one 156-byte frame; three other stores use lane arrays.
FIELDS={149:(104,2),151:(32,8),227:(40,8),231:(48,8),303:(56,8),304:(64,8),
    356:(80,8),364:(155,1),365:(88,8),386:(96,8),420:(16,8),421:(24,8),
    442:(72,8),446:(80,8),447:(155,1),448:(88,8)}
ARRAYS={423:(5252,1,1),424:(5256,1,1),425:(3520,8,8)}
SITES=set(FIELDS)|set(ARRAYS)


def definitions(code,edges,spans,slots=SLOTS):
    keys=(*origins.REGS,*slots);states={0:{k:frozenset({-1}) for k in keys}};queue=deque([0])
    while queue:
        at=queue.popleft();state=states[at].copy();op,args=origins.instruction(code[at])
        if op=='callq':
            for r in origins.VOLATILE:state[r]=frozenset({at})
        elif op in ('divl','divq'):state['rax']=state['rdx']=frozenset({at})
        elif op in origins.WRITE|{'popq'} and args:
            reg=origins.ALIASES.get(args[-1])
            if reg:state[reg]=state[reg]|{at} if op.startswith('cmov') else frozenset({at})
            if at in spans:
                lo,hi=spans[at]
                for slot in slots:
                    if lo<slot+8 and slot<hi:state[slot]=frozenset({at})
        for dest in edges[at]:
            merged=state if dest not in states else {k:states[dest][k]|state[k] for k in keys}
            if states.get(dest)!=merged:states[dest]=merged;queue.append(dest)
    return states


def guarded_lane(code,edges,states):
    s.require(code[86:99]==[
        'movq %r12, %rax','cmpq $-1, %r12','je .B233','leaq 1(%rax), %r12',
        'movzbl 104(%rcx,%rsi), %r13d','addq $112, %rsi','cmpl $255, %r13d',
        'je .B13','cmpq $3, %rax','ja .B212','movq %r8, 928(%rbp)',
        'movq %rdi, 960(%rbp)','imulq $156, %rax, %rdi'],
        'original zero-based lane and increment before unsigned frame guard')
    predecessors=lambda at:{p for p,ds in edges.items() if at in ds}
    s.require(all(predecessors(at)=={at-1} for at in (87,88,89,90,91,92,93,94,95,96,97,98)) and
        states[89]['rax']==states[94]['rax']==states[98]['rax']=={86} and
        states[98]['r12']=={89} and edges[95]==[code.index('.B212:'),96],
        'same lane definition and no guard/suffix bypass')
    # Remove the success edge: no assigned store may remain reachable. The
    # complete graph includes loop backs and both computed framing branches.
    todo=[0];seen=set()
    while todo:
        at=todo.pop()
        if at in seen:continue
        seen.add(at);todo.extend(v for v in edges[at] if (at,v)!=(95,96))
    s.require(not (SITES&seen),'unsigned lane guard dominates every assigned framing write')


def expression(code,states,at,key,trail=frozenset()):
    """Affine original-workspace + constant + lane*stride, lane in 0..3.

    Only two guard-anchored uses introduce the bounded lane symbol. Any other
    unknown, partial, cyclic, memory-derived or callee-produced address rejects.
    """
    s.require(at in states and key in states[at],'tracked workspace-address register or pointer slot')
    if (at,key) in ((89,'rax'),(98,'rax')):return frozenset({('number',0,1)})
    s.require((at,key) not in trail,'no unanchored workspace-address cycle')
    trail=trail|{(at,key)};result=set()
    def value(v):
        if v.startswith('$'):return {('number',int(v[1:]),0)}
        if v.startswith('%') and v[1:] in origins.REGS:return expression(code,states,site,v[1:],trail)
        match=re.fullmatch(r'(\d+)\(%rbp\)',v)
        s.require(match is not None and int(match[1]) in SLOTS,'known full-width pointer operand')
        return expression(code,states,site,int(match[1]),trail)
    def plus(left,right):
        merged=set()
        for ar,ac,ai in left:
            for br,bc,bi in right:
                s.require(ar=='number' or br=='number','no addition of two allocation roots')
                merged.add((br if ar=='number' else ar,ac+bc,ai+bi))
        return merged
    for site in states[at][key]:
        if site==-1:
            s.require(key==1104,'only original incoming workspace is an admitted root')
            result.add(('workspace',0,0));continue
        op,args=origins.instruction(code[site])
        dest=f'{key}(%rbp)' if isinstance(key,int) else '%'+key
        s.require(args and args[-1]==dest,'full-width exact address definition, not partial overlap/clobber')
        if op=='movq':out=value(args[0])
        elif op=='leaq':
            match=re.fullmatch(r'(-?\d*)\(%(\w+)(?:,%(\w+))?\)',args[0])
            s.require(match is not None,'assigned affine workspace address')
            out=plus(value('%'+match[2]),{('number',int(match[1] or 0),0)})
            if match[3]:out=plus(out,value('%'+match[3]))
        elif op=='addq':out=plus(expression(code,states,site,key,trail),value(args[0]))
        elif op=='imulq':
            s.require(len(args)==3 and args[0]=='$156','exact frame stride multiplication')
            out=set()
            for root,offset,stride in value(args[1]):
                s.require(root=='number','multiplication only on the bounded lane')
                out.add((root,offset*156,stride*156))
        else:s.require(False,'unsupported workspace-address producer: '+op)
        result.update(out)
    s.require(result,'nonvacuous workspace-address origins');return frozenset(result)


def writes(code,states):
    effects=[]
    for at in sorted(SITES):
        op,args=origins.instruction(code[at])
        match=re.fullmatch(r'(\d*)\(%(\w+)(?:,%(\w+)(?:,(\d+))?)?\)',args[-1])
        s.require(match is not None,'assigned workspace store address')
        width={'movb':1,'movw':2,'movq':8,'setae':1}.get(op)
        if at in FIELDS:
            field,want_width=FIELDS[at];offset,stride=3584+field,156
        else:offset,stride,want_width=ARRAYS[at]
        s.require(width==want_width,'exact workspace store width')
        targets=set()
        for root,base,step in expression(code,states,at,match[2]):
            s.require(root=='workspace','original workspace allocation root')
            indexes=expression(code,states,at,match[3]) if match[3] else {('number',0,0)}
            for ir,ic,ii in indexes:
                s.require(ir=='number','bounded numeric lane index')
                scale=int(match[4] or 1)
                targets.add((base+int(match[1] or 0)+ic*scale,step+ii*scale))
        s.require(targets=={(offset,stride)},'all predecessors retain exact workspace lane and field')
        spans=[[offset+lane*stride,offset+lane*stride+width] for lane in range(4)]
        s.require(all(0<=lo<hi<=5260 for lo,hi in spans),'writes fit the complete workspace')
        if at in FIELDS:
            s.require(all(3584+lane*156<=lo<hi<=3584+(lane+1)*156
                for lane,(lo,hi) in enumerate(spans)),'each frame write stays in its own lane')
        effects.append(dict(site=at,lane_write_spans=spans))
    return effects


def inspect(bodies,assembly,caller,framing,previous):
    n=origins.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==framing['function']==previous['function']==n['executor'] and
        framing['public_framing_fields_and_output_offsets_checked'] and
        previous['original_control_executor_result_and_authority_pointer_roots_checked'],
        'replayed framing semantics and preceding footprint review')
    geometry=origins.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same resident caller geometry')
    edges,_=origins.reconcile.graph(code,assembly);spans,_,_=origins.frame_writes(code,edges)
    states=definitions(code,edges,spans);guarded_lane(code,edges,states);effects=writes(code,states)
    start,end=geometry['executor_entry_objects']['workspace'];objects=geometry['executor_entry_objects']
    s.require(end-start==5260 and start>=-1200+1128,'workspace allocation excludes executor child frame')
    for effect in effects:
        for lo,hi in effect['lane_write_spans']:
            s.require(all(start+hi<=a or b<=start+lo for key,(a,b) in objects.items() if key!='workspace'),
                'workspace stores exclude every other simultaneous caller allocation')
    pending=set(previous['pending_non_frame_store_sites'])
    s.require(SITES<=pending and len(pending-SITES)==14,'exact remaining workspace store population')
    return dict(function=n['executor'],write_effects=effects,zero_based_lane_range=[0,3],
        frame_stride=156,workspace_bytes=5260,original_workspace_and_guarded_lane_checked=True,
        per_lane_frame_and_array_separation_checked=True,caller_and_child_frame_separation_checked=True,
        pending_non_frame_store_sites=sorted(pending-SITES),
        pending_callee_effect_sites=previous['pending_callee_effect_sites'],
        indirect_effects_and_nonvolatile_abi_preservation_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
