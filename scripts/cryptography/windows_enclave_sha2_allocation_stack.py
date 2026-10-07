"""Normal-CFG stack geometry for the saved SIMD allocation callers.

These offsets prove separation, not erasure or OS stack residency. __chkstk and
Win64 call/nonvolatile preservation remain explicit shared-runtime contracts.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_cleanup_paths as paths
from windows_enclave_sha2_slot_origins import ALIASES, VOLATILE

SAVED={'rbp','rbx','rsi','rdi','r12','r13','r14','r15'}
POINTER_OPS={'addq','callq','cmpb','cmpq','cmpw','incq','ja','jae','jb','je','jmp','jne',
             'leaq','movabsq','movb','movl','movq','movw','movzbl','movzwl','orb','orl','orq',
             'popq','pushq','retq','setb','sete','setne','shll','shrl','shrq','subq',
             'testb','testl','testq','vmovdqu','vmovups','vptest','vpxor','vzeroupper','xorl','nop'}


def edges(lines,assembly):
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    s.require(len(labels)==sum(v.endswith(':') for v in lines),'unique allocation CFG labels')
    tables=paths.jump_tables(assembly,lines);result={}
    for at,line in enumerate(lines):
        op,_,arg=line.partition(' ');dest=[]
        if op in ('retq','ud2'):result[at]=[];continue
        if op.startswith('j'):
            targets=tables.get(at,[]) if arg.startswith('*') else [arg]
            s.require(targets and all(v in labels for v in targets),'local allocation CFG destinations')
            dest.extend(labels[v] for v in targets)
        if op not in ('jmp','jmpq') and at+1<len(lines):dest.append(at+1)
        result[at]=dest
    return result


def reachable(graph,start,removed=()):
    todo=[start];seen=set();removed=set(removed)
    while todo:
        at=todo.pop()
        if at in seen:continue
        seen.add(at);todo.extend(n for n in graph[at] if (at,n) not in removed)
    return seen


def require_edge(graph,start,consumer,edge):
    s.require(edge[1] in graph[edge[0]] and consumer in reachable(graph,start),
              'real nonvacuous allocation/lifetime edge')
    s.require(consumer not in reachable(graph,start,[edge]),'allocation admission cannot be bypassed')


def pointer_origin(lines,graph,at,reg,root,offset=0):
    """All predecessor definitions must trace to one incoming pointer/offset.

    Caller effects still require the Win64 nonvolatile ABI contract. No stack
    reload, partial definition, unknown arithmetic or unanchored cycle is used
    as evidence of an original pointer.
    """
    live=reachable(graph,0);s.require(at in live,'reachable pointer consumer')
    s.require(all(lines[i].startswith('.') or lines[i].endswith(':') or
                  lines[i].split()[0] in POINTER_OPS for i in live),
              'closed pointer-CFG instruction effects; no implicit or multi-destination writes')
    predecessors={i:[] for i in graph}
    for i,targets in graph.items():
        if i in live:
            for target in targets:predecessors[target].append(i)
    todo=[(at,reg,offset)];seen=set();anchors=set()
    while todo:
        at,reg,offset=todo.pop()
        if (at,reg,offset) in seen:continue
        seen.add((at,reg,offset));s.require(len(seen)<100000,'bounded pointer-origin graph')
        if at==0:
            s.require(reg==root and offset==0,'same original ABI argument on every path')
            anchors.add((reg,offset));continue
        s.require(predecessors[at],'pointer use is reachable from a real predecessor')
        for before in predecessors[at]:
            line=lines[before];op,_,arg=line.partition(' ');args=arg.split(', ')
            writes=(op=='callq' and reg in VOLATILE or
                    op not in ('pushq',) and not op.startswith(('cmp','test','j')) and
                    not line.startswith('.') and not line.endswith(':') and ALIASES.get(args[-1])==reg)
            if not writes:todo.append((before,reg,offset));continue
            match=re.fullmatch(r'movq %(\w+), %'+reg,line)
            if match:todo.append((before,match[1],offset));continue
            match=re.fullmatch(r'leaq (\d+)\(%(\w+)\), %'+reg,line)
            s.require(match is not None and 0<=int(match[1])<=offset,'full-width bounded pointer origin')
            todo.append((before,match[2],offset-int(match[1])))
    s.require(anchors,'pointer cycles alone do not prove an origin')
    return len(seen)


def inspect(body,assembly,entry_mod32):
    s.require(entry_mod32 in (8,24),'Win64 entry return-slot alignment')
    lines=s.lines(body);graph=edges(lines,assembly)
    # (RSP relative to entry, saved-register stack, frame RBP, aligned RBX).
    todo=[(0,0,(),None,None)];states={};calls={};returns=[];minimum=0
    while todo:
        at,sp,saves,bp,bx=todo.pop();value=(sp,saves,bp,bx)
        if at in states:
            s.require(states[at]==value,'one stack geometry on every incoming path');continue
        states[at]=value;line=lines[at];op,_,arg=line.partition(' ')
        if op=='pushq':
            reg=arg.removeprefix('%');s.require(reg in SAVED,'assigned nonvolatile push')
            sp-=8;saves=(*saves,(reg,sp))
        elif op=='popq':
            reg=arg.removeprefix('%')
            s.require(saves and saves[-1]==(reg,sp),'matched saved register at its actual address')
            saves=saves[:-1];sp+=8
            if reg=='rbp':bp=None
            if reg=='rbx':bx=None
        elif op in ('subq','addq') and arg.endswith(', %rsp'):
            amount=arg.split(', ')[0]
            if amount=='%rax':
                s.require(op=='subq' and at>=2 and lines[at-1]=='callq __chkstk',
                          'only the bound __chkstk result supplies a dynamic stack adjustment')
                match=re.fullmatch(r'movl \$(\d+), %eax',lines[at-2])
                s.require(match is not None,'literal probed stack allocation')
                require_edge(graph,0,at,(at-2,at-1));require_edge(graph,0,at,(at-1,at))
                amount='$'+match[1]
            s.require(re.fullmatch(r'\$[1-9]\d*',amount) is not None,'positive fixed stack allocation')
            count=int(amount[1:]);s.require(count<=65536,'bounded private frame')
            sp+=count if op=='addq' else -count
        elif line=='leaq 128(%rsp), %rbp':
            s.require(bp is None and any(r=='rbp' for r,_ in saves),'saved incoming frame pointer')
            bp=sp+128
        elif line=='andq $-32, %rsp':
            s.require(bp is not None and bx is None,'one aligned resident allocation')
            sp-=(entry_mod32+sp)%32
        elif line=='movq %rsp, %rbx':
            s.require(bp is not None and bx is None,'one resident local frame anchor');bx=sp
        elif op=='leaq' and arg.endswith(', %rsp'):
            match=re.fullmatch(r'(\d+)\(%rbp\), %rsp',arg)
            s.require(match is not None and bp is not None,'restore stack from live frame anchor')
            sp=bp+int(match[1])
        elif op=='callq':
            if arg=='__chkstk':
                s.require(at>0 and re.fullmatch(r'movl \$\d+, %eax',lines[at-1]) is not None and
                          at+1<len(lines) and lines[at+1]=='subq %rax, %rsp','only the prologue probe contract')
            else:
                s.require((entry_mod32+sp)%16==0 and saves and sp+32<=saves[-1][1],
                          'aligned call and allocated home area below saves')
            calls[at]=dict(target=arg,rsp=sp,rbp=bp,rbx=bx)
        elif op=='retq':
            s.require(not arg and sp==0 and not saves and bp is None and bx is None,'balanced caller return')
            returns.append(at)
        elif not line.startswith('.') and not line.endswith(':'):
            # RBP/RBX may be ordinary nonvolatile values before establishing a
            # frame anchor. Once established, even a partial overwrite rejects.
            dest=arg.split(', ')[-1]
            readonly=op.startswith(('cmp','test'))
            s.require(not op.startswith(('enter','leave','push','pop','ret','call','loop','xchg','xadd','cmpxchg')),
                      'no unassigned stack/control operation')
            if not readonly:
                s.require(dest not in ('%rsp','%esp','%sp','%spl'),'no unassigned stack-pointer write')
                s.require(bp is None or dest not in ('%rbp','%ebp','%bp','%bpl'),'live frame anchor preserved')
                s.require(bx is None or dest not in ('%rbx','%ebx','%bx','%bl','%bh'),'live aligned anchor preserved')
        minimum=min(minimum,sp)
        s.require(sp<=0,'caller cannot release its return slot')
        s.require(graph[at] or op in ('retq','ud2'),'no unassigned fallthrough outside the caller')
        todo.extend((n,sp,saves,bp,bx) for n in graph[at])
    s.require(returns,'nonvacuous normal caller return')
    return dict(calls=calls,low=minimum,returns=returns,states=states)


def call(result,target):
    found=[(at,row) for at,row in result['calls'].items() if row['target']==target]
    s.require(len(found)==1,'one synchronous allocation consumer: '+target)
    return found[0]
