"""Frame-alias stores and bounded framing runtime writes; other effects pending."""
from collections import deque
import re
import windows_enclave_sha3_simd_wipe_origins as origins
s,life=origins.s,origins.life
REGS,ALIASES=origins.REGS,origins.ALIASES
VECTOR_SITES=(206,207,208,209,211,213,215,217,283,284,285,286,288,290,292,294)
PROTECTED=((448,456),(456,464),(1104,1112),(1112,1120))


def definitions(code,edges):
    states={0:{r:frozenset({-1}) for r in REGS}};queue=deque([0])
    while queue:
        at=queue.popleft();state=states[at].copy();op,args=origins.instruction(code[at])
        if op=='callq':
            for r in origins.VOLATILE:state[r]=frozenset({at})
        elif op in ('divl','divq'):state['rax']=state['rdx']=frozenset({at})
        elif op in origins.WRITE|{'popq'} and args and args[-1] in ALIASES:
            reg=ALIASES[args[-1]]
            state[reg]=state[reg]|{at} if op.startswith('cmov') else frozenset({at})
        for dest in edges[at]:
            value=state if dest not in states else {r:states[dest][r]|state[r] for r in REGS}
            if states.get(dest)!=value:states[dest]=value;queue.append(dest)
    return states


def frame_origins(code,states,at,reg,trail=frozenset()):
    s.require((at,reg) not in trail,'unanchored frame-address cycle')
    trail=trail|{(at,reg)};result=set()
    for site in states[at][reg]:
        s.require(site>=0,'frame-address has an actual definition on every predecessor')
        line=code[site]
        match=re.fullmatch(r'leaq (-?\d*)\(%rbp\), %'+reg,line)
        if match:result.add(int(match[1] or 0));continue
        match=re.fullmatch(r'movq %(\w+), %'+reg,line)
        s.require(match is not None and match[1] in REGS,'full-width anchored frame-address transfer')
        result.update(frame_origins(code,states,site,match[1],trail))
    s.require(result,'nonvacuous frame-address origins')
    return result


def encoding_skips(code,states,at):
    """Actual reaching R8 definitions produce 8..13 or 0 + 14 + carry."""
    values=set()
    for site in states[at]['r8']:
        s.require(site>=0,'no unknown encoding skip')
        match=re.fullmatch(r'movl \$(\d+), %r8d',code[site])
        if match:
            value=int(match[1]);s.require(8<=value<=13,'bounded literal encoding skip');values.add(value)
        else:
            s.require(code[site]=='adcq $14, %r8' and states[site]['r8']=={site-1} and
                code[site-1]=='movl $0, %r8d','zero-based final carry encoding skip')
            values.update((14,15))
    s.require(values==set(range(8,16)),'complete nonvacuous encoding skip domain')
    return sorted(values)


def encoding_effects(code,skip):
    """Execute the whole straight-line helper slice for every possible skip.

    Only public frame offsets/lengths are modeled. The helper write contract is
    conditional on the separately bound runtime implementation and Win64 ABI.
    """
    s.require(type(skip) is int and 8<=skip<=15,'bounded public encoding skip')
    base=1<<20;regs={'rbp':base,'r8':skip};effects=[]
    def operand(v):
        if v.startswith('$'):return int(v[1:])
        s.require(v in ALIASES or v=='%rbp','assigned framing operand')
        key='rbp' if v=='%rbp' else ALIASES[v]
        s.require(key in regs,'known framing operand');return regs[key]
    for line in code:
        op,args=origins.instruction(line)
        if op=='callq':
            name=args[0];s.require(name in ('memset','memcpy'),'assigned framing runtime helper')
            dest,length=regs['rcx'],regs['r8'];source=regs['rdx']
            s.require(0<=length<=255,'bounded framing runtime extent')
            if name=='memset':s.require(source==0,'zero framing fill')
            effects.append(dict(helper=name,write=[dest-base,dest-base+length],
                read=None if name=='memset' else [source-base,source-base+length]))
            for reg in origins.VOLATILE:regs.pop(reg,None)
            continue
        s.require(op in ('movl','movq','leaq','addq','subq','xorl') and len(args)==2,
            'closed straight-line framing effect instruction')
        src,dst=args;s.require(dst in ALIASES,'assigned framing result register');reg=ALIASES[dst]
        if op=='leaq':
            match=re.fullmatch(r'(-?\d*)\(%(\w+)(?:,%(\w+))?\)',src)
            s.require(match is not None,'bounded frame address expression')
            value=int(match[1] or 0)+operand('%'+match[2])+(operand('%'+match[3]) if match[3] else 0)
        elif op=='xorl':s.require(src==dst,'zero framing idiom');value=0
        else:
            value=operand(src)
            if op in ('addq','subq'):value=operand(dst)+(value if op=='addq' else -value)
        s.require(0<=value<(1<<64),'nonwrapping framing address/length')
        regs[reg]=value&0xffffffff if op=='movl' else value
    n=16-skip
    expected=[dict(helper='memset',write=[-80+n,175],read=None),
        dict(helper='memcpy',write=[-80,-80+n],read=[784+skip,800])]
    s.require(effects==expected,'exact framing buffer partition and original source extent')
    return effects


def disjoint(spans,protected=PROTECTED):
    s.require(spans and protected,'nonvacuous physical separation check')
    for lo,hi in spans:
        s.require(-128<=lo<hi<=1000,'write stays inside allocated executor frame')
        s.require(all(hi<=a or b<=lo for a,b in protected),'frame write excludes every live pointer cell')


def inspect(bodies,assembly,caller,wipe,framing):
    n=origins.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(wipe['function']==framing['function']==caller['functions']['executor']==n['executor'] and
        wipe['all_normal_predecessor_direct_pointer_origins_checked'] and
        framing['public_framing_fields_and_output_offsets_checked'], 'replayed frame/receiver prerequisites')
    edges,_=origins.reconcile.graph(code,assembly);origins.frame_writes(code,edges)
    states=definitions(code,edges);stores=[]
    for at,offset in zip(VECTOR_SITES,(0,32,64,96,128,160,192,223)*2,strict=True):
        match=re.fullmatch(r'vmovups %ymm[0-3], (\d*)\(%rax\)',code[at])
        s.require(match is not None and int(match[1] or 0)==offset and frame_origins(code,states,at,'rax')=={177},
            'original 255-byte temporary vector-store base')
        start=177+int(match[1] or 0);stores.append(dict(site=at,write=[start,start+32]))
    s.require(code[1033]=='movq %r9, (%r8)' and frame_origins(code,states,1033,'r8')=={-80,784},
        'both actual conditional compaction frame aliases')
    stores.extend(dict(site=1033,write=[base,base+8]) for base in (-80,784))
    runtime=[]
    for begin,end in ((187,200),(264,277)):
        for skip in encoding_skips(code,states,begin):
            runtime.append(dict(region=[begin,end],skip=skip,effects=encoding_effects(code[begin:end],skip)))
    spans=[r['write'] for r in stores]+[e['write'] for r in runtime for e in r['effects']]
    disjoint(spans)
    # Physical caller/child relation: CALL return address + eight pushes +1128
    # local bytes, then both functions use RBP=RSP+128.
    parent=life.code(bodies[n['digest']]);geometry=origins.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry and parent[:12]==[
        *['pushq %'+r for r in ('rbp','r15','r14','r13','r12','rsi','rdi','rbx')],
        'movl $9112, %eax','callq __chkstk','subq %rax, %rsp','leaq 128(%rsp), %rbp'],
        'reviewed parent stack frame allocation')
    s.require(code[:10]==[*['pushq %'+r for r in ('rbp','r15','r14','r13','r12','rsi','rdi','rbx')],
        'subq $1128, %rsp','leaq 128(%rsp), %rbp'],'reviewed executor child frame allocation')
    child_origin=-8-64-1128
    physical=[(child_origin+a,child_origin+b) for a,b in spans]
    objects=geometry['executor_entry_objects']
    s.require(all(hi<=a or b<=lo for lo,hi in physical for a,b in objects.values()),
        'frame-local writes exclude all simultaneous caller objects')
    pending_stores=set(wipe['non_frame_store_sites_pending'])-set(VECTOR_SITES)-{1033}
    pending_calls=set(wipe['call_sites_pending_memory_effects'])-{195,199,272,276}
    s.require(len(pending_stores)==57 and len(pending_calls)==53,'exact remaining effect populations')
    return dict(function=n['executor'],frame_alias_store_sites=sorted(set(VECTOR_SITES)|{1033}),
        store_effects=stores,runtime_frame_call_sites=[195,199,272,276],runtime_effect_cases=runtime,
        protected_pointer_cells=[list(v) for v in PROTECTED],child_frame_origin_in_parent=child_origin,
        bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects=True,
        pending_non_frame_store_sites=sorted(pending_stores),pending_callee_effect_sites=sorted(pending_calls),
        runtime_implementation_and_nonvolatile_abi_required=True,
        other_indirect_effects_and_original_allocation_lifetimes_qualified=False,
        private_frame_and_exception_cleanup_qualified=False)
