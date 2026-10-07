"""Descriptor requirements at saved, table-bound protected-call boundaries.

OS exception dispatch and effects of earlier cleanup handlers are prerequisites,
not simulated here. The main image checker independently binds complete bodies.
"""
import windows_enclave_sha2_simd_authority as authority
import windows_enclave_sha2_cleanup_regions as r
o,s,n=r.o,r.s,r.n


def inspect(bodies,assembly,lane,name,output):
    narrow=lane=='simd256';child=name.endswith('Executor13digest_secret')
    first,last=(46,68) if narrow else (36,56) if child else (66,76)
    # root, flag, pointer offset, frame base: every destructor caller is explicit.
    assigned=({272:('returned',71,2912,'rbx'),277:('original',None,864,'rbx')} if narrow else
              {304:('original',None,816,'rbp')} if child else {91:('original',55,352,'rbx')})
    lines=s.lines(bodies[name]);tables=authority.cleanup_tables(assembly,bodies,lane)
    chains=tables['parents'][name]['ordered_handlers_from_ip'];requirements={};handlers={}
    for number,(root,flag,offset,base) in assigned.items():
        handler=s.one(bodies,r'^\?dtor\$'+str(number)+r'@.*'+('Resident6digest' if not child else 'Executor13digest_secret')+r'@4HA$')
        code=s.lines(bodies[handler]);call=o.unique(code,'callq '+output)
        s.require(code[call-1]==f'leaq {offset}(%{base}), %rcx','cleanup drop receives assigned descriptor root')
        if flag is not None:
            s.require(code[call-3:call-1]==[f'cmpb $0, {flag}(%rbx)',
                'je .B274' if narrow else 'je .B93'],'exact destructor availability flag')
        requirements[handler]=(root,flag)
        handlers[handler]=dict(call=call,descriptor_offset=offset,flag_offset=flag)
    expected=[f'.Ltmp{i}:' for i in range(first,last)]
    s.require([v for v in lines if v.startswith('.Ltmp')]==expected,
              'complete emitted protected-region annotation population')
    calls={}
    for i in range(first,last,2):
        a=o.unique(lines,f'.Ltmp{i}:');b=o.unique(lines,f'.Ltmp{i+1}:')
        at=[j for j in range(a,b) if lines[j].startswith('callq ')]
        s.require(len(at)==1,'one emitted call per protected region');calls[at[0]]=i
    active=[];guarded={};rows=[]
    for at,line in enumerate(lines):
        if line.endswith(':') and line[:-1] in chains:active=chains[line[:-1]]
        if at not in calls:continue
        selected=[h for h in active if h in requirements]
        if selected:guarded[at]=[requirements[h] for h in selected]
        rows.append(dict(call=at,handlers=selected))
    s.require(set(h for row in rows for h in row['handlers'])==set(requirements),
              'every assigned destructor has a real activated callsite')
    return guarded,dict(handlers=handlers,calls=rows,OS_dispatch_and_prior_handler_noninterference_required=True)
