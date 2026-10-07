"""Direct CFG definitions for saved SIMD512 scalar-helper pointer arguments.

Actual register/slot definitions, partial writes, loops and ABI clobbers are
tracked. Indirect physical aliases and callee memory preservation remain parent
composition obligations, not facts inferred from a symbolic workspace name.
"""
from collections import deque
import re
import windows_enclave_sha2_source_lifetime as source
s=source.s
SLOTS={760:4580,1016:5604,1024:5348,968:4708,928:5476,984:512}
ABI_SLOTS={1040:'inputs',1048:'executor'}
ROOTS={'workspace':('stack',1168),'control':('stack',1176),'inputs':('register','r8'),'executor':('register','rdx')}
REGS=('rax','rcx','rdx','rbx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
VOLATILE={'rax','rcx','rdx','r8','r9','r10','r11'}
ALIASES={}
for reg in REGS:
    names=(reg,reg+'d',reg+'w',reg+'b') if reg.startswith('r') and reg[1:].isdigit() else {
        'rax':('rax','eax','ax','al','ah'),'rcx':('rcx','ecx','cx','cl','ch'),
        'rdx':('rdx','edx','dx','dl','dh'),'rbx':('rbx','ebx','bx','bl','bh'),
        'rsi':('rsi','esi','si','sil'),'rdi':('rdi','edi','di','dil')}[reg]
    ALIASES.update(('%'+v,reg) for v in names)
BASES={'rbp':(0,0),'rsp':(-128,-128)}


def definitions(lines,start,tables,slots=(),indexed=None):
    slots=tuple(dict.fromkeys((*slots,1168,1176)))
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    s.require(start in labels and len(labels)==sum(v.endswith(':') for v in lines),'unique slot-CFG labels')
    keys=(*REGS,*slots);positions={key:i for i,key in enumerate(keys)}
    states={labels[start]:tuple(frozenset({-1}) for _ in keys)};queue=deque(states)
    while queue:
        at=queue.popleft();state=list(states[at]);op,args=source.instruction(lines[at])
        if op=='callq':
            for reg in VOLATILE:state[positions[reg]]=frozenset({at})
        elif args:
            reg=ALIASES.get(args[-1])
            if reg and op!='pushq':
                old=state[positions[reg]]
                state[positions[reg]]=old|{at} if op.startswith('cmov') else frozenset({at})
            span=source.store_span(op,args,BASES)
            if span==source.INDEXED_FRAME and indexed is not None:
                s.require(at in indexed,'every computed frame write has a reviewed extent')
                span=indexed[at]
            if span:
                for slot in slots:
                    if source.cells.overlaps(span,(slot,slot+8)):state[positions[slot]]=frozenset({at})
        if op in ('retq','ud2'):continue
        nexts=[]
        if op.startswith('j'):
            target=lines[at].split(maxsplit=1)[1]
            if target.startswith('*'):
                s.require(op=='jmpq' and at in tables,'assigned slot-CFG jump table');targets=tables[at]
            else:targets=[target]
            s.require(targets and all(t in labels for t in targets),'slot-CFG destinations stay local')
            nexts.extend(labels[t] for t in targets)
        if op not in ('jmp','jmpq'):nexts.append(at+1)
        for dest in nexts:
            s.require(0<=dest<len(lines),'no escaped slot-CFG path')
            new=tuple(state)
            if dest in states:new=tuple(a|b for a,b in zip(states[dest],new,strict=True))
            if states.get(dest)!=new:states[dest]=new;queue.append(dest)
    return {at:dict(zip(keys,state,strict=True)) for at,state in states.items()}


def unique(lines,line):
    s.require(lines.count(line)==1,'unique slot contract: '+line)
    return lines.index(line)


def indexed_effects(lines,states,tables):
    """Bound both computed RBP stores rather than assuming they miss saved slots."""
    pad=unique(lines,'movb $-128, 544(%rbp,%rdx)')
    sub=pad-1;const=pad-2
    s.require(lines[const:pad]==['movl $11, %edx','subq %rcx, %rdx'] and states[pad]['rdx']=={sub}
              and states[sub]['rdx']=={const},'padding index is exactly 11 minus bounded skip')
    adc=unique(lines,'adcq $1, %rcx');cmov=unique(lines,'cmovaeq %rdx, %rcx')
    s.require(lines[adc-1]=='movl $0, %ecx' and states[adc]['rcx']=={adc-1},'ADC starts from zero')
    s.require(states[cmov]['rcx']=={adc} and lines[cmov-1]=='movl $0, %edx'
              and states[cmov]['rdx']=={cmov-1},'conditional skip selects zero or ADC value')
    s.require(states[sub]['rcx']=={adc,cmov},'padding skip stays in zero through two on every path')
    # Carry is a single bit regardless of parameter: skip is 0, 1 or 2.
    spans={pad:(553,556)}
    store=unique(lines,'movq %rcx, 32(%rbp,%rax,8)')
    begin=unique(lines,'.B118:');step=store+1;initial=begin-1
    s.require(lines[initial]=='xorl %eax, %eax' and lines[step:step+3]==[
        'incq %rax','cmpq $64, %rax','jne .B118'],'bounded public schedule induction')
    s.require(states[store]['rax']=={initial,step} and states[step]['rax']=={initial,step},
              'no other schedule-index definitions enter the loop')
    # Exact 0..63 induction requires a single external entry and the compared
    # backedge, not merely the expected definition population.
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    for at,line in enumerate(lines):
        if not line.startswith('j'):continue
        target=line.split(maxsplit=1)[1]
        if target in labels and begin<=labels[target]<=step+2:
            s.require(at==step+2 and target=='.B118','no alternate entry into public schedule loop')
    s.require(not any(v.endswith(':') for v in lines[begin+1:step+3]),'no internal schedule entry labels')
    s.require(not any(v.startswith('j') for v in lines[begin+1:step]),'straight-line public schedule iteration')
    s.require(all(not begin<=labels[target]<=step+2 for targets in tables.values() for target in targets),
              'no indirect entry into public schedule loop')
    spans[store]=(32,544)
    actual={i for i,line in enumerate(lines) if not line.startswith('callq ') and
            source.store_span(*source.instruction(line),BASES)==source.INDEXED_FRAME}
    s.require(actual==set(spans),'complete indexed-frame write population')
    return spans


def require_origin(lines,states,at,location,root,offset,slots):
    """Check every reaching definition, including reload cycles, against an ABI root.

An SCC is not itself an origin: unknown entry values reject, and an actual ABI
anchor must be reached. This allows the executor pointer's loop save/reloads
without treating a cycle or a successful predecessor as a proof on its own.
"""
    todo=[(at,location,root,offset)];seen=set();anchors=set()
    while todo:
        key=todo.pop()
        if key in seen:continue
        seen.add(key);at,location,root,offset=key
        s.require(root in ROOTS,'assigned original argument identity')
        defs=states[at][location];s.require(defs,'nonempty pointer definition population')
        for site in defs:
            if site==-1:
                s.require(ROOTS[root]==('register',location) and offset==0,'no uninitialized or wrong ABI pointer origin')
                anchors.add(('register',location));continue
            line=lines[site]
            if isinstance(location,int):
                match=re.fullmatch(r'movq %(\w+), '+str(location)+r'\(%rbp\)',line)
                s.require(match is not None,'no partial, overlapping or computed pointer-slot overwrite')
                todo.append((site,match[1],root,offset));continue
            kind,source_slot=ROOTS[root]
            if kind=='stack' and offset==0 and line==f'movq {source_slot}(%rbp), %{location}':
                s.require(states[site][source_slot]=={-1},'original incoming stack argument not overwritten')
                anchors.add(('stack',source_slot));continue
            match=re.fullmatch(r'movq %(\w+), %'+location,line)
            if match:todo.append((site,match[1],root,offset));continue
            match=re.fullmatch(r'leaq (\d+)\(%(\w+)\), %'+location,line)
            if match:
                s.require(int(match[1])==offset,'exact workspace-relative field offset')
                todo.append((site,match[2],root,0));continue
            match=re.fullmatch(r'movq (\d+)\(%rbp\), %'+location,line)
            if match:
                slot=int(match[1]);s.require(slots.get(slot)==(root,offset),'assigned full-width pointer reload')
                todo.append((site,slot,root,offset));continue
            raise ValueError('unassigned pointer definition: '+line)
    s.require(anchors,'a pointer cycle alone cannot establish an origin')
    return sorted(anchors)


def require_workspace(lines,states,at,reg,offset,slots):
    return require_origin(lines,states,at,reg,'workspace',offset,{k:('workspace',v) for k,v in slots.items()})


def require_slot(lines,states,at,slot,offset,slots):
    return require_workspace(lines,states,at,slot,offset,slots)


def compose(placement,stack):
    layout=placement['placements'];origin=layout['frame']['offset']
    s.require(origin==-1136 and layout['frame']['root']=='resident-frame','same reviewed child frame')
    s.require(placement['conditional_returning_calls']==18 and placement['conditional_indirect_stores']==5,
              'complete wide tracked effect population')
    s.require(stack['normal_callee_count']==11 and stack['tracked_returning_call_sites']==18,
              'same tracked normal callee closure')
    protected={slot:(origin+slot,origin+slot+8) for slot in (*SLOTS,*ABI_SLOTS,976,1168,1176)}
    effects=[(kind,root,(low,high)) for kind,root,low,high in placement['distinct_effects']]
    effects.append(('writes','resident-frame',tuple(origin+v for v in stack['caller_frame_relative_stack_span'])))
    effects.append(('writes',placement['outgoing_home_space']['root'],placement['outgoing_home_space']['span']))
    for kind,root,span in effects:
        s.require(root in ('resident-frame','resident-page','worker-input'),'assigned physical effect root')
        s.require(kind in ('reads','writes') and len(span)==2 and all(type(v) is int for v in span)
                  and span[0]<=span[1],'assigned memory direction and bounded interval')
    for kind,root,span in effects:
        if kind=='writes' and root=='resident-frame':
            s.require(all(not source.cells.overlaps(span,cell) for cell in protected.values()),
                      'conditional indirect/helper/stack effects exclude every live saved slot')
    return dict(protected_parent_relative_slots={str(k):list(v) for k,v in protected.items()},
        normal_tracked_effects_disjoint=True,external_root_separation_required=True,
        earlier_vector_phase_effects_for_slot984_pending=True)


def inspect(bodies,assembly,frame,placement,stack):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name])
    tables=source.paths.jump_tables(assembly,lines)
    initial=definitions(lines,name,tables)
    indexed=indexed_effects(lines,initial,tables)
    states=definitions(lines,name,tables,(*SLOTS,*ABI_SLOTS,1168,1176),indexed)
    begin=unique(lines,'.B182:');end=unique(lines,'.B227:')
    rows=[]
    for slot,offset in SLOTS.items():
        reads=[]
        for at in range(begin,end):
            op,args=source.instruction(lines[at])
            if args and any(re.search(r'(?<!\d)'+str(slot)+r'\(%rbp\)',v) for v in args[:-1]):
                s.require(op=='movq','full-width pointer-slot use')
                require_slot(lines,states,at,slot,offset,SLOTS);reads.append(at)
        s.require(reads,'nonvacuous scalar-helper slot consumers')
        rows.append(dict(slot=slot,workspace_offset=offset,reads=reads,
                         reaching_stores=sorted({n for at in reads for n in states[at][slot]})))
    # The first wipe uses the register itself; the loop backedge restores it
    # from slot760. Check both paths without seeding RBX from its expected value.
    wipe=s.one(bodies,r'HardenedSha2Owner4wipe$')
    uses=[i for i in range(begin,end) if lines[i]=='callq '+wipe]
    s.require(len(uses)==2,'both scalar-owner wipe sites')
    for at in uses:require_workspace(lines,states,at,'rcx',4580,SLOTS)
    abi=[];mapping={slot:('workspace',off) for slot,off in SLOTS.items()}|{slot:(root,0) for slot,root in ABI_SLOTS.items()}
    for slot,root in ABI_SLOTS.items():
        reads=[]
        for at,line in enumerate(lines):
            op,args=source.instruction(line)
            if at in states and args and any(re.search(r'(?<!\d)'+str(slot)+r'\(%rbp\)',v) for v in args[:-1]):
                s.require(op=='movq','full-width original argument reload')
                require_origin(lines,states,at,slot,root,0,mapping);reads.append(at)
        s.require(reads,'nonvacuous original argument consumers')
        abi.append(dict(slot=slot,root=root,reads=reads))
    for slot in (1168,1176):
        s.require(all(state[slot]=={-1} for state in states.values()),'incoming workspace/control slots are never directly overwritten')
    s.require(frame['function']==name,'same saved frame as argument-effect contracts')
    return dict(pointer_slots=rows,original_abi_slots=abi,owner_wipe_sites=uses,indexed_frame_writes={str(k):list(v) for k,v in indexed.items()},
        conditional_memory_composition=compose(placement,stack),
        reachable_instructions=len(states),direct_cfg_origins_and_preservation_checked=True,
        later_slot_reuse_is_outside_last_helper_consumption=True,
        indirect_effects_and_original_allocation_lifetimes_required=True,
        nonvolatile_and_fixed_frame_abi_required=True,whole_frame_qualified=False)
