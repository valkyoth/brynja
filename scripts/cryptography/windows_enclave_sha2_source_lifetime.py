"""Direct emitted CFG origin/preservation of the first prepared source pointer.

Reaching definitions include all normal branches and loop backedges. This closes
the direct-transfer obligation only: indirect memory effects, incoming argument
lifetimes, nonvolatile ABI preservation and physical separation remain required.
"""
from collections import deque
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_cleanup_paths as paths
import windows_enclave_sha2_frame_cell as cells

ALIASES={'rax':{'%rax','%eax','%ax','%al','%ah'},'rdi':{'%rdi','%edi','%di','%dil'}}
PLAIN={'nop','vzeroupper','retq','ud2'}
OPS={'movq','movl','movb','movw','movabsq','movzbl','movzwl','movslq','leaq','leal',
     'addq','addl','addb','adcq','subq','subl','subb','andq','andl','andb','orq','orl','orb',
     'xorq','xorl','xorb','incq','decq','decl','decb','bswapq','shll','shlq','shlb','shrl','shrq','shrb',
     'rolq','rorq','sbbw','imulq','imull','setne','sete','setae','cmovaeq','cmovbq','cmovel','cmovbl','cmovnel',
     'vmovaps','vmovups','vxorps','pushq','popq','bsfl'}
READ={'cmpb','cmpw','cmpl','cmpq','testb','testw','testl','testq'}
INDEXED_FRAME=(-(1<<64),1<<64)


def instruction(line):
    if line.startswith('rep '):line=line[4:]
    op,_,rest=line.partition(' ')
    if line.endswith(':') or line.startswith('.') or op in PLAIN|READ or op.startswith('j'):
        return op,[]
    if op=='callq':return op,[rest]
    s.require(op in OPS,'assigned reaching-definition instruction: '+op)
    return op,rest.split(', ')


def store_span(op,args,bases):
    if not args or '(' not in args[-1] or op in ('leaq','leal'):return None
    if op.startswith('vmov'):
        s.require(args[0].startswith(('%xmm','%ymm')),'assigned vector-store width')
        width=32 if args[0].startswith('%ymm') else 16
    else:
        s.require(op in OPS and op[-1] in 'bwlq','assigned direct-store width')
        width={'b':1,'w':2,'l':4,'q':8}[op[-1]]
    if set(re.findall(r'%(\w+)',args[-1])) & bases.keys() and ',' in args[-1]:
        return INDEXED_FRAME  # No inferred bound: kill the tracked cell fact.
    return cells.frame_span(args[-1],bases,width)


def analyse(lines,start,tables,cell,bases,initializer,absent):
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    s.require(start in labels and len(labels)==sum(v.endswith(':') for v in lines),'unique source-CFG labels')
    # Independent may-definition sets. Any uninitialized/unknown reaching value
    # invalidates a demanded fact; no successful path is selected preferentially.
    states={labels[start]:(frozenset({-1}),frozenset({-1}),frozenset({'unknown'}))}
    queue=deque(states)
    while queue:
        at=queue.popleft();a,d,p=states[at];line=lines[at];op,args=instruction(line)
        if op=='callq':a=frozenset({at})  # Win64 volatile RAX; RDI is nonvolatile.
        elif args:
            if args[-1] in ALIASES['rax'] and op!='pushq':
                a=(a|{at}) if op.startswith('cmov') else frozenset({at})
            if args[-1] in ALIASES['rdi'] and op!='pushq':
                d=(d|{at}) if op.startswith('cmov') else frozenset({at})
            span=store_span(op,args,bases)
            if span and cells.overlaps(span,cell):
                p=frozenset({'prepared' if at==initializer else 'absent' if at==absent else 'unknown'})
        if op in ('retq','ud2'):continue
        destinations=[]
        if op.startswith('j'):
            target=line.split(maxsplit=1)[1]
            if target.startswith('*'):
                s.require(op=='jmpq' and at in tables,'source-CFG assigned indirect branch')
                targets=tables[at]
            else:targets=[target]
            s.require(targets and all(t in labels for t in targets),'source-CFG local destinations')
            destinations.extend(labels[t] for t in targets)
        if op not in ('jmp','jmpq'):destinations.append(at+1)
        for dest in destinations:
            s.require(0<=dest<len(lines),'source-CFG cannot fall outside function')
            new=(a,d,p)
            if dest in states:new=tuple(old|value for old,value in zip(states[dest],new,strict=True))
            if states.get(dest)!=new:states[dest]=new;queue.append(dest)
    return states


def inspect(bodies,assembly,lane,frame):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned source route')
    name=frame['function'];body=bodies[name];lines=s.lines(body)
    base='rbx' if narrow else 'rbp';offset=frame['cell'][0]
    build='leaq 7712(%rbx), %rax' if narrow else 'leaq 1024(%rdi), %rax'
    assign=f'movq %rax, {offset}(%{base})';clear=f'movq $0, {offset}(%{base})'
    origins=[i for i,line in enumerate(lines[:-1]) if line==build and lines[i+1]==assign]
    s.require(len(origins)==lines.count(clear)==1,'unique prepared source and absent initializer')
    origin=origins[0];init=origin+1;absent=lines.index(clear)
    s.require(lines[init]==assign,'complete prepared source store immediately follows address calculation')
    tables=paths.jump_tables(assembly,lines)
    states=analyse(lines,name,tables,frame['cell'],frame['frame_alias_ranges'],init,absent)
    s.require(init in states and states[init][0]=={origin},'all source initializer paths use actual address calculation')
    loads=[]
    if not narrow:
        s.require(origin in states and states[origin][1] and -1 not in states[origin][1],
                  'workspace source has a reaching definition on every path')
        loads=sorted(states[origin][1])
        s.require(all(lines[i]=='movq 1168(%rbp), %rdi' for i in loads),
                  'every source-base definition reloads the original workspace argument')
        # Fixed-offset writes must not corrupt the incoming workspace pointer.
        # Indexed/indirect writes and calls need the separate memory contract.
        prologue=lines.index('.seh_endprologue')
        for line in lines[prologue+1:]:
            op,args=instruction(line)
            if op=='callq':continue
            span=store_span(op,args,frame['frame_alias_ranges'])
            s.require(not span or span==INDEXED_FRAME or not cells.overlaps(span,(1168,1176)),
                      'no fixed-offset write to the incoming workspace argument')
    checks=(f'cmpq $0, {offset}(%{base})',f'movq {offset}(%{base}), %r8')
    read_sites=[]
    for check in checks:
        s.require(lines.count(check)==1,'unique first source preflight/copy read')
        at=lines.index(check);read_sites.append(at)
        s.require(at in states and states[at][2] and states[at][2]<={'prepared','absent'},
                  'every first-source read has a valid reaching initializer')
    return dict(initializer=init,address_calculation=origin,absent_initializer=absent,
        source_reads=read_sites,workspace_argument_reload_sites=loads,reachable_instructions=len(states),
        all_normal_branch_and_loop_paths_checked=True,unknown_reaching_values_rejected=True,
        direct_cfg_source_origin_and_preservation_checked=True,
        indirect_effects_and_original_argument_lifetimes_required=True,
        nonvolatile_register_and_fixed_frame_abi_required=True,whole_frame_qualified=False)
