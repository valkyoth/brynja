"""Machine compact-base/cursor definitions within their vector-only lifetimes.

Cursor arithmetic bounds come from the complete emitted vector-loop review.
These reaching definitions reject stale values from earlier slot roles and
overwrites before consumption; indirect physical alias separation stays explicit.
"""
import re
import windows_enclave_sha2_narrow_cfg as n
import windows_enclave_sha2_simd_vector as vector
o,g,s=n.o,n.g,n.s


def slot_reads(lines,slot,base,begin,end):
    found=[];token=re.compile(r'(?<!\d)'+str(slot)+r'\(%'+base+r'\)')
    for at in range(begin,end):
        op,_,rest=lines[at].partition(' ');args=rest.split(', ') if rest else []
        operands=args if op in o.source.READ or op.startswith(('cmp','test','lea','add','sub','inc','dec')) else args[:-1]
        if any(token.search(arg) for arg in operands):found.append(at)
    return found


def cursor(lines,states,edges,slot,seed,step,reads):
    s.require(reads and step in reads,'cursor reload and increment population')
    for at in reads:
        s.require(states[at][slot] and states[at][slot]<={seed,step},
                  'cursor has only its current initializer or guarded advancement')
        g.dominates(edges,lines.index(next(line for line in lines if line.endswith(':'))),seed,at)
    # A closed cycle cannot qualify itself in lieu of an initialized pointer.
    s.require(seed in states[step][slot],'advancement is anchored to the original cursor')


def inspect(bodies,assembly,lane):
    vector.inspect(bodies,lane)
    narrow=lane=='simd256';name=s.one(bodies,r'Resident6digest$' if narrow else r'Executor13digest_secret$')
    lines=s.lines(bodies[name]);tables=o.source.paths.jump_tables(assembly,lines)
    if narrow:
        _,edges,spans=n.prepare(lines,assembly,name)
        probe=o.unique(lines,'callq __chkstk')
        states=o.definitions(lines,name,tables,(*n.SLOTS,104),spans,
            bases=n.BASES,call_clobbers={probe:{'rax'}})
        seed=o.unique(lines,'leaq 10784(%rbx), %rax')+1
        s.require(lines[seed]=='movq %rax, 104(%rbx)' and states[seed]['rax']=={seed-1},
                  'cursor initially points at the exact compact array')
        begin=o.unique(lines,'.B91:');end=o.unique(lines,'.B143:');step=o.unique(lines,'addq %rax, 104(%rbx)')
        reads=slot_reads(lines,104,'rbx',begin,end)
        s.require(len(reads)==5 and lines[step-1]=='movq 56(%rbx), %rax' and states[step]['rax']=={step-1},
                  'four cursor reloads and one reviewed width increment')
        cursor(lines,states,edges,104,seed,step,reads)
        base_reads=[]
    else:
        edges=g.graph(lines,tables);initial=o.definitions(lines,name,tables)
        spans=o.indexed_effects(lines,initial,tables)
        states=o.definitions(lines,name,tables,(944,1024,1168),spans)
        seed=o.unique(lines,'.B129:')-4
        s.require(lines[seed-1:seed+1]==['movq 944(%rbp), %rax','movq %rax, 1024(%rbp)'],
                  'wide compact cursor initialized after IV-index slot reuse')
        begin=o.unique(lines,'.B126:');end=o.unique(lines,'.B182:')
        base_reads=slot_reads(lines,944,'rbp',begin,end)
        s.require(len(base_reads)==3,'complete vector compact-base reload population')
        for at in base_reads:o.require_origin(lines,states,at,944,'workspace',4576,{944:('workspace',4576)})
        s.require(states[seed]['rax']=={seed-1},'wide initializer uses original compact base')
        step=o.unique(lines,'addq %r8, 1024(%rbp)')
        reads=slot_reads(lines,1024,'rbp',begin,end)
        s.require(len(reads)==4 and lines[step-5]=='movq 1032(%rbp), %r8' and states[step]['r8']=={step-5},
                  'three wide cursor reloads and one reviewed width increment')
        cursor(lines,states,edges,1024,seed,step,reads)
    return dict(function=name,initializer=seed,increment=step,cursor_reads=reads,base_reads=base_reads,
        vector_interval=[begin,end],current_phase_definitions_checked=True,
        earlier_and_later_slot_roles_do_not_establish_vector_cursor=True,
        complete_vector_geometry_and_indirect_memory_effect_reviews_required=True,
        physical_separation_and_runtime_abi_still_required=True,whole_frame_qualified=False)
