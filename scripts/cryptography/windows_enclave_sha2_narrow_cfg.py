"""Normal-path narrow frame definitions, with bounded indexed frame writes.

The fixed frame and Win64 __chkstk/nonvolatile ABI are explicit prerequisites.
Indirect alias effects and external allocation validity are composed separately.
"""
import re
import windows_enclave_sha2_slot_origins as o
import windows_enclave_sha2_early_writes as g
s=o.s
BASES={'rbx':(0,0),'rsp':(0,0),'rbp':(128,159)}
INPUTS=tuple(544+40*i for i in range(8))
SLOTS=(88,112,152,80,*INPUTS)


def predecessors(edges,at):return {a for a,targets in edges.items() if at in targets}


def straight(edges,first,last):
    for at in range(first+1,last+1):
        s.require(predecessors(edges,at)=={at-1},'no bypass into pointer construction/check')


def indexed_bounds(lines,states,edges):
    spans={};head=o.unique(lines,'.B21:');step=head+9;initial=head-2
    s.require(lines[initial:head]==['movl $224, %eax','.p2align 4'] and
        lines[step:step+3]==['addq $256, %rax','cmpq $2272, %rax','jne .B21'],
        'bounded eight-iteration frame-zeroing induction')
    s.require(predecessors(edges,head)=={head-1,step+2},'only initial and guarded clear-loop entries')
    straight(edges,head,step+2)
    s.require(states[head]['rax']=={initial,step} and states[step]['rax']=={initial,step},
              'clear-loop counter has no other definitions')
    for n in range(8):
        at=head+1+n;off=640+32*n
        s.require(lines[at]==f'vmovups %ymm0, {off}(%rbx,%rax)', 'exact indexed clearing store')
        spans[at]=(off+224,off+2016+32)
    at=o.unique(lines,'movb %r8b, 10784(%rbx,%rcx)')
    s.require(lines[at-4:at]==['cmpq $7, 80(%rbx)','ja .B79',
        'movq 80(%rbx), %rcx','movq 56(%rbx), %r8'],'compact-store index checked immediately')
    straight(edges,at-4,at)
    s.require(states[at]['rcx']=={at-2},'compact store uses its checked index')
    spans[at]=(10784,10792)
    at=o.unique(lines,'movq %r12, 7968(%rbx,%r15,8)')
    load=o.unique(lines,'movzbl (%rax,%r13), %r15d')
    s.require(lines[load+1:load+3]==['cmpq $7, %r15','ja .B176'] and
              states[at]['r15']=={load},'vector-offset store retains checked lane index')
    straight(edges,load,load+2);g.success_edge(edges,load,load+2,at)
    spans[at]=(7968,8032)
    actual={i for i,line in enumerate(lines) if not line.startswith('callq ') and
            o.source.store_span(*o.source.instruction(line),BASES)==o.source.INDEXED_FRAME}
    s.require(actual==set(spans),'all narrow computed frame writes bounded')
    return spans


def prepare(lines,assembly,name):
    tables=o.source.paths.jump_tables(assembly,lines);edges=g.graph(lines,tables)
    # __chkstk is an ABI-specific stack probe, not an arbitrary Rust callback.
    # Its argument-preserving contract belongs to shared runtime qualification.
    probe=o.unique(lines,'callq __chkstk')
    s.require(lines[probe-1:probe+8]==['movl $11992, %eax','callq __chkstk',
        'subq %rax, %rsp','.seh_stackalloc 11992','leaq 128(%rsp), %rbp',
        '.seh_setframe %rbp, 128','.seh_endprologue','andq $-32, %rsp','movq %rsp, %rbx'],
        'fixed narrow frame and unique stack-probe placement')
    active=probe+8;exit_at=o.unique(lines,'.seh_startepilogue')
    # Reject changes to the aligned bases before the single epilogue. Register
    # aliases include partial writes; taking frame aliases needs separate effects.
    for at,line in enumerate(lines):
        if at<=active or exit_at<=at<=o.unique(lines,'retq'):continue
        op,args=o.source.instruction(line)
        aliases={v for names in o.source.cells.BASE_ALIASES.values() for v in names}
        s.require(not args or args[-1] not in {'%'+v for v in aliases} or op=='pushq',
                  'fixed frame bases throughout all normal paths')
    kwargs=dict(bases=BASES,call_clobbers={probe:{'rax'}})
    raw=o.definitions(lines,name,tables,SLOTS,**kwargs)
    spans=indexed_bounds(lines,raw,edges)
    states=o.definitions(lines,name,tables,SLOTS,spans,**kwargs)
    return states,edges,spans


def reads(lines,slot):
    """Include comparisons, RMW uses and LEA exposure, not just MOV reloads."""
    found=[];token=re.compile(r'(?<!\d)'+str(slot)+r'\(%(?:rbx|rsp)\)')
    for at,line in enumerate(lines):
        op,_,rest=line.partition(' ');args=rest.split(', ') if rest else []
        sources=args if op in o.source.READ or op.startswith(('cmp','test','lea')) else args[:-1]
        if any(token.search(arg) for arg in sources):found.append(at)
        if args and token.search(args[-1]) and op.startswith(('add','sub','inc','dec','and','or','xor')):
            found.append(at)
    return sorted(set(found))


def trace(lines,states,at,location,anchor,slots=(),*,base='rbx'):
    """All reaching full-width moves must end at the supplied checked anchor.

Loop cycles are visited once but do not manufacture an anchor. The caller's
anchor callback verifies the load/field identity and any required CFG guards.
"""
    todo=[(at,location)];seen=set();anchors=set()
    while todo:
        at,location=todo.pop()
        if (at,location) in seen:continue
        seen.add((at,location))
        s.require(at in states and location in states[at],'reachable traced pointer use')
        for site in states[at][location]:
            if anchor(site,location):anchors.add(site);continue
            s.require(site>=0,'no uninitialized pointer path')
            line=lines[site]
            if isinstance(location,int):
                match=re.fullmatch(r'movq %(\w+), '+str(location)+r'\(%'+base+r'\)',line)
                s.require(match is not None,'no partial/overlapping pointer-slot definition')
                todo.append((site,match[1]));continue
            match=re.fullmatch(r'movq %(\w+), %'+location,line)
            if match:todo.append((site,match[1]));continue
            match=re.fullmatch(r'movq (-?\d+)\(%'+base+r'\), %'+location,line)
            if match:
                slot=int(match[1]);s.require(slot in slots,'assigned pointer reload lifetime')
                todo.append((site,slot));continue
            raise ValueError('unassigned narrow pointer definition: '+line)
    s.require(anchors,'pointer cycles need a real anchor')
    return sorted(anchors)
