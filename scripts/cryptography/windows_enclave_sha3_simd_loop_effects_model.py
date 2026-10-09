"""Finite per-lane normal-CFG address analysis, conditional on callee effects."""
from collections import deque
import re
import windows_enclave_sha3_simd_workspace_effects as workspace
o,s=workspace.origins,workspace.s
UNKNOWN=frozenset({('unknown',0)})
NODES=set(range(624,992))|set(range(1351,1354))
SLOTS=(504,824,832,864,880,888,896,1104)
ROOTS={504:3624,824:3584,888:5248,1104:0}
STORES={633:(5248,1,1),702:(3584,156,8),703:(3592,156,8),866:(3592,156,8),
    914:(3600,156,8),917:(5256,1,1),968:(3552,8,8),1352:(3584,156,8),1353:(3592,156,8)}


def one(kind,value):return frozenset({(kind,value)})


def merge(a,b):
    result=a|b
    return UNKNOWN if ('unknown',0) in result or len(result)>8 else result


def operand(text,state):
    if text.startswith('$'):return one('number',int(text[1:]))
    if text in o.ALIASES:
        result=state[o.ALIASES[text]]
        if text=='%'+o.ALIASES[text]:return result
        # Only tracked numeric subregister reads are meaningful, never a
        # truncated allocation root. Unknown arithmetic remains unknown.
        if not (text.startswith('%e') or re.fullmatch(r'%r\d+d',text)):return UNKNOWN
        return frozenset(('number',v&0xffffffff) for k,v in result) if all(k=='number' for k,_ in result) else UNKNOWN
    m=re.fullmatch(r'(\d+)\(%rbp\)',text)
    return state.get(int(m[1]),UNKNOWN) if m else UNKNOWN


def add(left,right):
    result=set()
    for a,x in left:
        for b,y in right:
            if a=='unknown' or b=='unknown' or (a!='number' and b!='number'):return UNKNOWN
            # Widen unrelated counters; a widened value can never authorize an
            # address. Real lane/frame constants stay well inside this domain.
            if not -65536<=x+y<=65536:return UNKNOWN
            result.add((b if a=='number' else a,x+y))
    return frozenset(result) if len(result)<=8 else UNKNOWN


def address(text,state):
    m=re.fullmatch(r'(-?\d*)\(%(\w+)(?:,%(\w+)(?:,(\d+))?)?\)',text)
    if not m:return UNKNOWN
    result=add(operand('%'+m[2],state),one('number',int(m[1] or 0)))
    if m[3]:
        index=operand('%'+m[3],state)
        if any(k!='number' for k,_ in index):return UNKNOWN
        result=add(result,frozenset(('number',v*int(m[4] or 1)) for _,v in index))
    return result


def transfer(line,before,span=None):
    state=before.copy();op,args=o.instruction(line)
    if op=='callq':
        for r in o.VOLATILE:state[r]=UNKNOWN
        return state
    if op in ('divl','divq'):state['rax']=state['rdx']=UNKNOWN;return state
    if op not in o.WRITE or not args:return state
    dest=o.ALIASES.get(args[-1]);value=UNKNOWN
    if op in ('movq','movl'):value=operand(args[0],before)
    elif op=='leaq':value=address(args[0],before)
    elif op=='xorl' and args[0]==args[-1]:value=one('number',0)
    elif op in ('addq','incq') and dest:
        value=add(before[dest],one('number',1) if op=='incq' else operand(args[0],before))
    elif op=='imulq' and len(args)==3 and args[0].startswith('$'):
        source=operand(args[1],before)
        if all(k=='number' for k,_ in source):value=frozenset(('number',v*int(args[0][1:])) for _,v in source)
    if dest:
        if args[-1]!='%'+dest:
            value=frozenset(('number',v&0xffffffff) for k,v in value) if op in ('movl','xorl') and all(k=='number' for k,_ in value) else UNKNOWN
        state[dest]=merge(before[dest],value) if op.startswith('cmov') else value
    if span:
        lo,hi=span
        for slot in SLOTS:
            if lo<slot+8 and slot<hi:
                state[slot]=operand(args[0],before) if op=='movq' and (lo,hi)==(slot,slot+8) else UNKNOWN
    return state


def check_lane(code,edges,spans,lane,observer=None):
    s.require(type(lane) is int and 0<=lane<4,'one of four admitted loop lanes')
    initial={k:UNKNOWN for k in (*o.REGS,*SLOTS)}
    initial.update({k:one('workspace',v) for k,v in ROOTS.items()})
    initial.update(r8=one('number',112*lane),r9=one('number',lane),rdx=one('workspace',3624+156*lane))
    states={642:initial};todo=deque([642]);backedges=set();exits=set()
    while todo:
        at=todo.popleft();before=states[at]
        if observer is not None:observer(at,before)
        after=transfer(code[at],before,spans.get(at))
        if at in STORES:
            offset,stride,width=STORES[at];op,args=o.instruction(code[at])
            actual={'movq':8,'movb':1,'setne':1}.get(op)
            s.require(actual==width and address(args[-1],before)==one('workspace',offset+lane*stride),
                'all predecessors retain exact original per-lane store root and extent')
        destinations=edges[at]
        if at==641:
            s.require(before['r8']==one('number',112*(lane+1)) and before['r9']==one('number',lane+1) and
                before['rdx']==one('workspace',3624+156*(lane+1)),
                'input stride, lane and frame advance together on every loop predecessor')
            s.require(all(before[k]==one('workspace',v) for k,v in ROOTS.items()),
                'original pointer cells preserved for the next lane induction')
            destinations=[992 if lane==3 else 642]
        for dest in destinations:
            if dest==642:backedges.add(at);continue
            if dest not in NODES:exits.add((at,dest));continue
            joined=after if dest not in states else {k:merge(states[dest][k],after[k]) for k in initial}
            if states.get(dest)!=joined:states[dest]=joined;todo.append(dest)
    s.require(states.keys()==NODES and (backedges=={641} if lane<3 else not backedges),
        'complete loop population reached and exactly the bounded lane backedge')
    return dict(lane=lane,reachable_positions=len(states),backedges=sorted(backedges),exits=sorted(exits),
        writes=[dict(site=at,span=[offset+lane*stride,offset+lane*stride+width])
            for at,(offset,stride,width) in STORES.items()])
