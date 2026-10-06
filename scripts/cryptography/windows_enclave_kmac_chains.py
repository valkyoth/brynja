"""Saved KMAC route reconciliation; author evidence, never a release gate."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha3_avx2_chain as previous
import windows_enclave_sha3_chain as scalar
import windows_enclave_kmac_shapes as shapes
import windows_enclave_kmac_reuse as reuse
import windows_enclave_kmac_lifecycle as lifecycle
import windows_enclave_kmac_readers as readers
import windows_enclave_kmac_assignment as assignment

w,shared,obj=previous.w,previous.shared,previous.obj
require,digest=previous.require,previous.digest
SPEC=shared.CATALOG.with_name('kmac-chains-20261006.json')
SPEC_HASH='2f6abdc0f65b7e11a772ef2acf19f2562378df0d1f5aa2a7f75b2b6da86be74c'
RUNTIME={'memcpy','memset','memcmp','__chkstk','__umodti3',
         'PublicKmacInput','PublicKmacOutput','PublicKmacSource','PublicKmacObserve'}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen two-route KMAC review')
    result=json.loads(raw)
    require(set(result)=={'scalar','avx2'},'both KMAC opening routes')
    require([len(result[k]['functions']) for k in ('scalar','avx2')]==[84,77],'complete emitted populations')
    return result


def load(base,root,lane,pin):
    row=next(r for r in shared.catalog(shared.CATALOG.read_bytes()) if r['route']==pin['route'])
    profile=next(r for r in w.specification(w.SPEC.read_bytes())['profiles'] if r['route']==pin['route'])
    directory=(base/row['object']).parent
    data=w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image=(base/row['image']).read_bytes()
    asm=(directory/'normal_rust.s').read_bytes();ir=(directory/'normal_rust.ll').read_bytes()
    build=(directory/'kmac-worker-build.json').read_bytes()
    for name,raw in [('object',data),('image',image),('assembly',asm),('ir',ir),('build',build)]:
        require(digest(raw)==pin[name+'_sha256'],'saved '+lane+' '+name)
    manifest=json.loads(build);sources={n.replace('\\','/'):h for n,h in manifest['source_sha256'].items()}
    require(manifest['target']=='x86_64-pc-windows-msvc' and len(sources)==pin['source_count'],
            'exact saved target and source population')
    for name,sha in sources.items():
        path=Path(name)
        require(not path.anchor and ':' not in name and '..' not in path.parts,'relative source path')
        require(digest((root/path).read_bytes())==sha,'unchanged saved build input '+name)
    return row,data,image,asm.decode(),ir.decode(),sources


def body_check(values,pin):
    code,refs,runtime=values
    require(len(code)==pin['bytes'] and digest(code)==pin['sha256'],'reviewed complete body')
    require(digest(json.dumps(refs,sort_keys=True).encode())==pin['references_sha256'] and
            runtime==pin['runtime'],'complete references and extent kind')


def data_bindings(data,image,records,functions):
    rows,symbols=obj.tables(data);constants={};tables={};runtime={}
    for name,r in records.items():
        for target,address in r['reference_targets'].items():
            if target in records: continue
            if target in RUNTIME:
                require(target not in runtime or runtime[target]['rva']==address,'same runtime boundary')
                entry=runtime.setdefault(target,dict(rva=address,callers=[],assigned_completion_package=8))
                entry['callers'].append(name);continue
            if target=='.rdata':
                _,syms,_,_,refs=obj.select(data,name)
                refs=[r for r in refs if r['symbol']=='.rdata']
                ids={r['symbol_index'] for r in refs};require(len(ids)==1,'one dispatch section per body')
                symbol=syms[ids.pop()];row=rows[symbol['section']-1]
                starts=sorted({r['addend'] for r in refs})
                require(starts[0]==0 and starts[-1]<len(row['code']),'complete bounded dispatch subtables')
                sizes=[end-start for start,end in zip(starts,starts[1:]+[len(row['code'])])]
                pin=dict(operands=[[r['offset'],r['addend']] for r in refs],
                         object_hex=row['code'].hex(),subtable_bytes=sizes)
                raw,table=previous.s.scalar.ops.table(data,image,r,pin)
                require(all(0<=v<r['size'] for v in table['destinations']),'all dispatch targets inside caller')
                tables[name]=table|pin|dict(linked_hex=raw.hex());continue
            matches=[v for v in symbols.values() if v['name']==target and v['section']>0]
            require(len(matches)==1 and matches[0]['value']==0,'unique data section '+target)
            row=rows[matches[0]['section']-1]
            if row['name']==b'.bss':
                require(target.endswith(('4LIVE','4LIVE.0','9LIVE_PAGE.0')) and
                        len(row['code']) in (8,24),'only resident pointer identity')
                linked,_=shared.caller.pe.linked(image)
                require(any(v['flags'] & 0xe0000000==0xc0000000 and v['rva']<=address and
                            address+len(row['code'])<=v['rva']+v['virtual_size'] for v in linked),
                        'bounded writable live metadata')
                constants[target]=dict(rva=address,bytes=len(row['code']),kind='resident pointer identity');continue
            require(not row['nrelocs'] and row['flags'] & 0xe0000000==0x40000000,'immutable object constant')
            require(previous.readonly(image,address,len(row['code']))==row['code'],'actual linked constant')
            constants[target]=dict(rva=address,bytes=len(row['code']),sha256=digest(row['code']))
    for item in runtime.values(): item['callers'].sort()
    return constants,tables,runtime


def frames(records,assembly):
    sizes={};edges={};vectors={};indirect={}
    for name,r in records.items():
        body=assembly[name]
        alignment=re.findall(r'andq\s+\$-(\d+), %rsp',body)
        require(not alignment or alignment==['32'],'bounded 32-byte alignment')
        # A constant stack probe may use RAX; reject unknown dynamic subtraction.
        normalized=previous.s.normalized(body)
        dynamic=[i for i,l in enumerate(normalized) if re.match(r'subq %[^,]+, %rsp',l)]
        for at in dynamic:
            require(normalized[at]=='subq %rax, %rsp' and at>=2 and normalized[at-1]=='callq __chkstk'
                    and re.fullmatch(r'movl \$\d+, %eax',normalized[at-2]),'bounded stack probe only')
        require(not re.search(r'andq\s+%[^,]+, %rsp',body),'no unbounded alignment')
        sizes[name]=sum(map(int,re.findall(r'\.seh_stackalloc (\d+)',body)))
        sizes[name]+=8*len(re.findall(r'\.seh_pushreg ',body))+(31 if alignment else 0)
        vectors[name]=[list(map(int,p)) for p in re.findall(r'\.seh_savexmm %xmm(\d+), (\d+)',body)]
        edges[name]=sorted(t for t in r['reference_targets'] if t in records)
        targets=re.findall(r'^\s*(?:callq|jmpq)\s+\*([^\n]+)',body,re.M)
        if targets: indirect[name]=targets
    return sizes,edges,vectors,indirect,scalar.contributions(edges,sizes)


def inspect_route(base,root,lane,pin,mutate):
    row,data,image,asm,ir,sources=load(base,root,lane,pin)
    functions=previous.inventory(data)
    require(set(functions)==set(pin['functions']),'complete frozen KMAC inventory')
    for name,values in functions.items(): body_check(values,pin['functions'][name])
    assembly=previous.s.bodies(asm,functions)
    semantics=shapes.inspect(assembly,lane)
    semantics['private_abi']=shapes.preconditions(ir,assembly,lane)
    semantics['public_integer_encoder']=reuse.encoder(assembly,lane)
    semantics['lifecycle']=lifecycle.inspect(assembly,lane)
    if lane=='avx2': semantics['checked_xor_range']=reuse.widened_xor(assembly)
    else:
        semantics['distinct_construction']=reuse.scalar_construction(assembly,ir)
        semantics['readers']=readers.inspect(assembly)
    prior_helpers=reuse.inspect(base,root,lane,functions,ir,assembly)
    records=previous.bind_all(data,image,functions)
    constants,tables,runtime=data_bindings(data,image,records,functions)
    kernel=permutation(data,image,asm,assembly,records,lane)
    transport=transport_binding(base,row,data,image,records,runtime)
    sizes,edges,vectors,indirect,geometry=frames(records,assembly)
    assignments=assignment.functions(records,prior_helpers)
    storage=assignment.storage(records,sizes,vectors,runtime,lane)
    require(set(indirect)==set(tables),'every indirect transfer assigned to bound tables')
    require(all(len(indirect[n])==len(t['operands']) for n,t in tables.items()),'every dispatch operand accounted')
    reached=set()
    def visit(name):
        if name in reached: return
        reached.add(name)
        for child in edges[name]: visit(child)
    visit('RetainedWork');normal=len(reached)
    for name in list(reached):
        for m in records[name].get('metadata',[]):
            if m['symbol'] in records: visit(m['symbol'])
    require(reached==set(records),'no unreachable or unassigned inner body')
    mutations=0;table_mutations=0
    if mutate:
        for name,(code,refs,kind) in functions.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try: body_check((bad,refs,kind),pin['functions'][name])
                except ValueError: mutations+=1
                else: raise AssertionError('accepted body mutant')
        for name,p in tables.items():
            raw=bytes.fromhex(p['linked_hex'])
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                try: previous.s.scalar.ops.table_destinations(bad,p['rva'],records[name]['rva'],p)
                except ValueError: table_mutations+=1
                else: raise AssertionError('accepted dispatch mutant')
    return dict(route=row['route'],source_sha256=sources,image_sha256=digest(image),
        object_sha256=digest(data),body_byte_mutations_rejected=mutations,
        table_byte_mutations_rejected=table_mutations,kernel=kernel,transport=transport,
        normal_reachable_functions=normal,total_functions=len(records),
        cleanup_funclets=sum(n.startswith('?') for n in records),constants=constants,dispatch_tables=tables,
        functions={n:dict(rva=r['rva'],bytes=r['size'],frame_bytes=sizes[n],saved_vectors=vectors[n],
            inner_calls=edges[n],references=r['reference_targets']) for n,r in sorted(records.items())},
        geometry=geometry,semantics=semantics,prior_helpers=prior_helpers,
        author_review_assignments=assignments,storage_lifetimes=storage,
        runtime_boundaries_pending=runtime,whole_image_qualified=False,
        arbitrary_exception_cleanup_qualified=False,independent_retest=False)


def permutation(data,image,asm,assembly,records,lane):
    s=previous.s
    if lane=='scalar':
        # Use the real full assembly extent, including its emitted end label.
        name=s.scalar.PERMUTE;start=asm.index('\n'+name+':\n')
        s.scalar.permutation_assembly(asm[start:asm.index('.seh_endproc',start)])
        result=dict(rounds=24,state_bytes=200,opaque_stack_accesses=0,
                    working_gprs=['rax','rcx','rdx','r10','r11'])
        result['constants']=s.scalar.constants(data,image,records[name])
    else:
        result=s.kernel(assembly[s.KERNEL])
        rows,symbols=obj.tables(data)
        found=[v for v in symbols.values() if v['name']==s.CONSTANT]
        require(len(found)==1,'one accelerated round table')
        expected=s.scalar.round_constants();row=rows[found[0]['section']-1]
        require(found[0]['value']==0 and row['code']==expected,'independently generated round constants')
        address=records[s.KERNEL]['reference_targets'][s.CONSTANT]
        require(previous.readonly(image,address,192)==expected,'actual linked accelerated round table')
        result['constants']=dict(rva=address,bytes=192,sha256=digest(expected))
    return result


def transport_binding(base,row,data,image,records,runtime):
    t=w.transport;spec=t.specification(t.SPEC.read_bytes())
    profile=next(p for p in spec['profiles'] if p['route']==row['route'])
    native=(base/row['object']).read_bytes()
    wrapper=(base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    tr=t.inspect(native,image,wrapper,(base/'sdk-system32-review/vertdll.dll').read_bytes(),
                 profile,spec['templates'])
    parent=shared.inspect(native,image,wrapper)
    require(parent['retained_worker_rva']==records['RetainedWork']['rva'],'exact wrapper enters KMAC worker')
    for suffix in ('Input','Output','Source','Observe'):
        require(runtime['PublicKmac'+suffix]['rva']==tr['records'][suffix]['rva'],
                'actual bound KMAC transport '+suffix)
    return dict(wrapper_worker_rva=parent['retained_worker_rva'],
                transport_rvas={k:tr['records'][k]['rva'] for k in ('Input','Output','Source','Observe')},
                shared_runtime_completion_package=8)


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    result={lane:inspect_route(base,root,lane,pin,mutate) for lane,pin in spec.items()}
    return dict(schema=1,status='AUTHOR_KMAC_PRIVATE_CHAIN_REVIEW_COMPLETE',routes=result,
        completion_package=3,completion_package_closed=True,remaining_family_review=[],
        shared_completion_package=8,
        shared_obligations=['Actual runtime callees and SDK boundary composition',
            'Complete stack-window erasure, including moved copies and incoming register saves',
            'Final compiler/platform and whole-image stack-depth reconciliation'],
        whole_image_qualified=False,release_gate_changed=False,native_run_added=False,
        spec_sha256=SPEC_HASH,source_sha256={p.name:digest(p.read_bytes()) for p in
            sorted({Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} |
                   {Path(__file__),Path(__file__).with_name('test-windows-enclave-kmac-chains.py')})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
