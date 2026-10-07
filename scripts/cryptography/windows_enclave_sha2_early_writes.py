"""Earlier wide digest indirect stores: actual origins and bounded writes.

Normal CFG/register definitions and the public four-lane induction are checked.
Physical object lifetime/separation and callee argument effects remain required;
these checks do not promote a symbolic root to a protected allocation proof.
"""
import re
import windows_enclave_sha2_slot_origins as o
import windows_enclave_sha2_effect_placement as placement
s=o.s


def graph(lines,tables):
    labels={line[:-1]:at for at,line in enumerate(lines) if line.endswith(':')}
    s.require(len(labels)==sum(line.endswith(':') for line in lines),'unique earlier-write CFG labels')
    edges={}
    for at,line in enumerate(lines):
        op,_=o.source.instruction(line);dest=[]
        if op in ('retq','ud2'):edges[at]=[];continue
        if op.startswith('j'):
            target=line.split(maxsplit=1)[1]
            if target.startswith('*'):
                s.require(op=='jmpq' and at in tables,'assigned earlier-write indirect branch')
                targets=tables[at]
            else:targets=[target]
            s.require(targets and all(v in labels for v in targets),'local earlier-write branch destinations')
            dest.extend(labels[v] for v in targets)
        if op not in ('jmp','jmpq'):
            # An unreachable trailing assembler directive is harmless. If this
            # edge is actually reached, reachable() rejects the missing node.
            dest.append(at+1)
        edges[at]=dest
    return edges


def reachable(edges,start,removed_node=None,removed_edge=None):
    pending=[start];seen=set()
    while pending:
        at=pending.pop()
        if at==removed_node or at in seen:continue
        s.require(at in edges,'closed earlier-write graph')
        seen.add(at)
        pending.extend(v for v in edges[at] if (at,v)!=removed_edge)
    return seen


def dominates(edges,start,guard,target):
    s.require(target in reachable(edges,start) and target not in reachable(edges,start,removed_node=guard),
              'required address/index definition dominates use')


def success_edge(edges,start,branch,target):
    s.require(branch+1 in edges[branch] and target in reachable(edges,start)
              and target not in reachable(edges,start,removed_edge=(branch,branch+1)),
              'successful bounds-check edge dominates memory access')


def state_index(lines,states,edges,start):
    """Induction at B104: initial zero, otherwise guarded increment of 0..3.

R12 also holds public IV words elsewhere. Only a checked save/reload of the
bounded index can feed the increment from that path; IV arithmetic is not
mistaken for an index definition. Unknown incoming definitions reject.
"""
    head=o.unique(lines,'.B104:');entry=o.unique(lines,'.B101:')-3
    step=o.unique(lines,'.B103:')+1;save=head+7
    load=o.unique(lines,'.B102:')+1;restore=load+11
    s.require(lines[head:save+1]==['.B104:','leaq (%r12,%r12,4), %rbx',
        'movq 1040(%rbp), %rax','movzwl 32(%rax,%rbx,8), %eax','cmpl $65535, %eax',
        'je .B103','cmpw $4, %ax','movq %r12, 1024(%rbp)'],'public lane-index save path')
    s.require(lines[entry:entry+3]==['xorl %r12d, %r12d','movq $0, 1016(%rbp)','jmp .B104']
              and lines[step:step+3]==['incq %r12','cmpq $4, %r12','je .B126'],
              'zero-origin four-lane induction and guarded backedge')
    s.require({at for at,targets in edges.items() if head in targets}=={entry+2,step+2},
              'no unguarded loop-head predecessor')
    s.require(lines[load]=='movq 1024(%rbp), %r8' and lines[restore]=='movq %r8, %r12',
              'index restores from its exact saved copy')
    s.require(states[head]['r12']=={entry,step} and states[save]['r12']=={entry,step}
              and states[step]['r12']=={entry,step,restore}
              and states[restore]['r8']=={load} and states[load][1024]=={save},
              'all index definitions belong to the anchored bounded induction')
    dominates(edges,start,head,save);dominates(edges,start,save,load)
    s.require(save not in reachable(edges,step,removed_edge=(step+2,head)),
              'every increment-to-save path crosses the non-exhausted loop edge')
    return dict(head=head,entry=entry,increment=step,save=save,load=load,restore=restore,range=[0,3])


def indirect_inventory(lines,begin,end):
    rows=[]
    for at in range(begin,end):
        op,args=o.source.instruction(lines[at])
        if op=='callq' or not args or '(' not in args[-1] or op in ('leaq','leal'):continue
        if o.source.store_span(op,args,o.BASES) is None:rows.append(at)
    return rows


def stores(lines,states,edges,start,begin,end):
    index=state_index(lines,states,edges,start);rows=[];assigned=set()
    def add(at,root,span):
        s.require(at not in assigned,'one effect per earlier indirect store')
        assigned.add(at);rows.append(dict(line=at,instruction=lines[at],object=root,span=list(span)))
    # Public IV temporary aliases RBP-88, including its loop restore. Trace
    # every incoming definition at each store, not a single textual match.
    aliases=[i for i in indirect_inventory(lines,begin,end) if '%r13' in lines[i].split(', ')[-1]]
    s.require(len(aliases)==21,'complete earlier local-alias write population')
    for at in aliases:
        defs=states[at]['r13']
        s.require(defs and -1 not in defs and all(lines[v]=='leaq -88(%rbp), %r13' for v in defs),
                  'all local scratch alias definitions refer to the actual frame')
        span=o.source.store_span(*o.source.instruction(lines[at]),{'r13':(-88,-88)})
        s.require(span is not None and -88<=span[0]<span[1]<=544,'local IV scratch write extent')
        add(at,'frame',span)
    # Eight words per state, at workspace+512+64*index, index in 0..3.
    load=index['load'];address=load+3
    s.require(lines[load:address+1]==['movq 1024(%rbp), %r8','movq %r8, %rcx',
              'shlq $6, %rcx','addq 984(%rbp), %rcx'],'state initialization address calculation')
    s.require(states[address]['rcx']=={address-1} and states[address-1]['rcx']=={address-2}
              and states[address-2]['r8']=={load},'unclobbered state index scaling')
    o.require_slot(lines,states,address,984,512,{984:512})
    sites=[address+i for i in (*range(1,8),9)]
    regs=('rax','r11','rdi','rbx','r14','rdx','r12','r15')
    for word,(at,reg) in enumerate(zip(sites,regs,strict=True)):
        operand=('' if word==0 else str(8*word))+'(%rcx)'
        s.require(lines[at]==f'movq %{reg}, {operand}' and states[at]['rcx']=={address},
                  'exact state initialization word address and width')
        dominates(edges,start,address,at)
        add(at,'workspace',(512+8*word,512+3*64+8*word+8))
    # Both pre-computation and vector-loop accounting update the original control.
    controls=[at for at in indirect_inventory(lines,begin,end) if lines[at] in
              ('movq %rax, 16(%rdx)','movq %rcx, 24(%rdx)')]
    s.require(len(controls)==4,'complete earlier control-counter writes')
    for at in controls:
        o.require_origin(lines,states,at,'rdx','control',0,{})
        off=16 if lines[at].endswith('16(%rdx)') else 24
        add(at,'control',(off,off+8))
    # Runtime checked compact index protects the stored vector block count.
    at=o.unique(lines,'movq %r12, 4544(%rax,%r15,8)')
    load=o.unique(lines,'movzbl (%rax,%r13), %r15d');guard=load+2
    s.require(lines[load+1:guard+1]==['cmpq $3, %r15','ja .B228']
              and states[at]['r15']=={load},'vector offset index retains its checked 0..3 value')
    # Start at the defining load, not function entry: a successful check in an
    # earlier iteration must not qualify a newly loaded compact index.
    success_edge(edges,load,guard,at)
    o.require_origin(lines,states,at,'rax','workspace',0,{})
    add(at,'workspace',(4544,4576))
    s.require(assigned==set(indirect_inventory(lines,begin,end)),'all earlier indirect stores assigned, no hidden writes')
    s.require(len(rows)==34,'complete earlier indirect-store population')
    return index,sorted(rows,key=lambda row:row['line'])


def compose(rows,layout):
    protected=(920,960,984,1040,1048,1168,1176);origin=layout['frame']['offset']
    s.require(origin==-1136,'same earlier wide child frame')
    mapped=[]
    for row in rows:
        effect=placement.place(dict(object=row['object'],span=row['span']),layout)
        s.require(effect['root']=='resident-frame','earlier direct stores have concrete caller/child placements')
        s.require(all(not o.source.cells.overlaps(effect['span'],(origin+slot,origin+slot+8)) for slot in protected),
                  'earlier indirect stores exclude all live callback and saved argument slots')
        mapped.append(dict(line=row['line'],**effect))
    return dict(stores=mapped,protected_slots=list(protected),conditional_effects_disjoint=True,
                actual_pointer_lifetimes_and_external_separation_required=True)


def inspect(bodies,assembly,early,layout):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);start=lines.index(name+':')
    tables=o.source.paths.jump_tables(assembly,lines);edges=graph(lines,tables)
    preliminary=o.definitions(lines,name,tables)
    indexed=o.indexed_effects(lines,preliminary,tables)
    states=o.definitions(lines,name,tables,(984,1024),indexed)
    begin=o.unique(lines,'leaq 512(%rdi), %rax')+2;end=o.unique(lines,'.B182:')
    s.require(early['begin']==begin and early['end']==end,'same earlier vector lifetime interval')
    index,rows=stores(lines,states,edges,start,begin,end)
    return dict(function=name,begin=begin,end=end,indirect_stores=rows,initialization_index=index,
        normal_cfg_origins_and_store_bounds_checked=True,placement=compose(rows,layout),
        callee_argument_effects_pending=True,original_allocation_lifetime_and_separation_pending=True,
        arbitrary_unwind_qualified=False,whole_frame_qualified=False)
