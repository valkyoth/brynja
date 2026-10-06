"""Saved accelerated SHA-3 inner-chain review; excludes shared runtime qualification."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha3_avx2_shapes as s
import windows_enclave_worker_boundaries as w
import windows_enclave_caller_handlers as handlers
import windows_enclave_leaf_binding as leaf
import windows_enclave_construction_review as construction

shared,obj,require,digest=w.shared,w.obj,s.require,s.digest
SPEC=shared.CATALOG.with_name('sha3-avx2-chain-20261006.json')
SPEC_HASH='ce9a558035c95fd520f85aa76029b39a80c8ca66ab7e8e65046b0b21d2317b3d'
RUNTIME={'memcpy','memset','memcmp','__umodti3','PublicSha3Input','PublicSha3Output','PublicSha3Source','PublicSha3Observe'}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen author review specification')
    value=json.loads(raw)
    require(len(value['functions'])==61 and sum(n.startswith('?') for n in value['functions'])==8,
            '53 main functions and eight cleanup funclets')
    return value


def inputs(base,root,spec):
    row=shared.catalog(shared.CATALOG.read_bytes())[4]
    profile=w.specification(w.SPEC.read_bytes())['profiles'][3]
    directory=(base/row['object']).parent
    data=w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image=(base/row['image']).read_bytes();asm=(directory/'normal_rust.s').read_bytes()
    ir=(directory/'normal_rust.ll').read_bytes();build=(directory/'sha3-worker-build.json').read_bytes()
    for key,raw in [('object',data),('image',image),('assembly',asm),('ir',ir),('build',build)]:
        require(digest(raw)==spec[key+'_sha256'],'saved '+key+' identity')
    manifest=json.loads(build);require(manifest['target']=='x86_64-pc-windows-msvc','MSVC build target')
    sources={n.replace('\\','/'):h for n,h in manifest['source_sha256'].items()}
    require(len(sources)==254,'complete saved build input population')
    for name,sha in sources.items():
        path=Path(name)
        require(not path.anchor and ':' not in name and '..' not in path.parts,'relative source path')
        require(digest((root/path).read_bytes())==sha,'unchanged build input: '+name)
    return row,directory,data,image,asm.decode(),ir.decode(),sources


def inventory(data):
    rows,symbols=obj.tables(data);ranges=obj.ranges(data,rows,symbols);result={}
    for sym in symbols.values():
        if sym['kind']!=32 or sym['section']<=0: continue
        runtime=any(r['section']==sym['section'] and r['start']==sym['value'] for r in ranges)
        if runtime:
            _,_,_,code,refs=obj.select(data,sym['name'])
            refs=[{k:v for k,v in r.items() if k!='symbol_index'} for r in refs]
        else: code,refs=shared.caller.function(data,sym['name'])
        require(sym['name'] not in result,'unique function inventory')
        result[sym['name']]=(code,refs,runtime)
    # Whole-object identity additionally binds alignment bytes and unnamed sections.
    require(all(any(v['section']==i and v['kind']==32 for v in symbols.values())
                for i,row in enumerate(rows,1) if row['flags'] & 0x20000000 and row['code']),
            'no unnamed executable section')
    return result


def body_check(code,refs,runtime,pin):
    require(len(code)==pin['bytes'] and digest(code)==pin['sha256'],'complete reviewed function bytes')
    require(refs==pin['references'] and runtime==pin['runtime'],'complete function references and extent kind')


def bind_all(data,image,functions):
    records={};pending=set(functions)
    while pending:
        previous=len(pending);errors=[]
        for name in sorted(pending):
            anchors=list(records.values())
            for parent in records.values():
                targets={v['symbol']:v['symbol_rva'] for v in parent.get('metadata',[]) if v['symbol'].startswith('?dtor')}
                if targets:
                    anchors.append(dict(entry=parent['entry']+':bound-xdata',image_sha256=digest(image),
                                        reference_targets=targets))
            try:
                record=(handlers.bind(data,image,name,anchors) if functions[name][2]
                        else leaf.bind(data,image,name,anchors))
            except ValueError as error:
                errors.append(str(error));continue
            records[name]=record;pending.remove(name)
        require(len(pending)<previous,'all functions bind to exact image: '+repr(sorted(pending))+' '+repr(errors))
    for name,r in records.items():
        for target,rva in r['reference_targets'].items():
            if target in records: require(records[target]['rva']==rva,'exact inner call/tail destination')
        for metadata in r.get('metadata',[]):
            if metadata['symbol'] in records:
                require(records[metadata['symbol']]['rva']==metadata['symbol_rva'],'actual cleanup funclet target')
    return records


def reused(functions):
    """Re-execute semantic opcode/branch checks, not just compare body hashes."""
    result={}
    for module in (s.engine,s.engine.cleanup,s.engine.adapters,construction):
        matched={role:pin for role,pin in module.BODIES.items()
                 if pin[0] in functions and digest(functions[pin[0]][0])==pin[2]}
        for role,(name,size,sha) in matched.items():
            code,refs,_=functions[name]
            require(len(code)==size,'reused helper extent')
            if hasattr(module,'CALLS'):
                require({r['offset']:r['symbol'] for r in refs}==module.CALLS[role],
                        'reused helper actual call/data names')
            for key,offset,hexcode in module.ANCHORS:
                if key==role:
                    expected=bytes.fromhex(hexcode)
                    require(code[offset:offset+len(expected)]==expected,'reproduced semantic helper landmark')
            for key,offset,opcode,target in getattr(module,'BRANCHES',()):
                if key!=role: continue
                width=4 if len(opcode)==2 or opcode==b'\xe9' else 1
                end=offset+len(opcode)+width
                require(code[offset:offset+len(opcode)]==opcode and
                        end+int.from_bytes(code[end-width:end],'little',signed=True)==target,
                        'reproduced semantic helper branch')
            result[name]=module.__name__+':'+role
    require(len(result)==20,'exact reusable engine, state, clearing and prefix population')
    return result


def readonly(image,address,length):
    return s.scalar.ops.readonly(image,address,length)


def data_bindings(data,image,records,functions):
    rows,symbols=obj.tables(data);out={};tables={}
    for name,r in records.items():
        for ref in functions[name][1]:
            target=ref['symbol']
            if target in records or target in RUNTIME: continue
            if target=='.rdata': continue
            matches=[v for v in symbols.values() if v['name']==target and v['section']>0]
            require(len(matches)==1 and matches[0]['value']==0,'unique complete data object: '+target)
            row=rows[matches[0]['section']-1];address=r['reference_targets'][target]
            if target in (s.WORKER+'4LIVE',s.WORKER+'9LIVE_PAGE.0'):
                linked,_=shared.caller.pe.linked(image)
                require(any(v['flags'] & 0xe0000000==0xc0000000 and v['rva']<=address and
                            address+(24 if target.endswith('LIVE') else 8)<=v['rva']+v['virtual_size'] for v in linked),
                        'bounded writable pointer-only live metadata')
                out[target]=dict(rva=address,kind='pointer-only resident identity');continue
            require(not row['nrelocs'] and row['flags'] & 0xe0000000==0x40000000,'immutable relocation-free constant')
            require(readonly(image,address,len(row['code']))==row['code'],'exact linked constant')
            out[target]=dict(rva=address,bytes=len(row['code']),sha256=digest(row['code']))
    # Three bounded intra-function dispatches, represented by two COFF sections.
    for name,sizes in ((s.WORKER+'7receive',[44,32]),(s.OWNER+'6finish',[16])):
        _,syms,selected,_,refs=obj.select(data,name)
        refs=[r for r in refs if r['symbol']=='.rdata']
        require(len(refs)==len(sizes),'all dispatch table operands')
        ids={r['symbol_index'] for r in refs};require(len(ids)==1,'single combined table section')
        row=rows[syms[ids.pop()]['section']-1]
        pin=dict(operands=[[r['offset'],r['addend']] for r in refs],object_hex=row['code'].hex(),subtable_bytes=sizes)
        raw,bound=s.scalar.ops.table(data,image,records[name],pin)
        require(all(0<=n<records[name]['size'] for n in bound['destinations']),'dispatch remains inside reviewed caller')
        tables[name]=bound|dict(object_hex=pin['object_hex'],subtable_bytes=sizes,linked_hex=raw.hex())
    constants={v['name']:rows[v['section']-1]['code'] for v in symbols.values() if v['section']>0}
    require(constants[s.CONSTANT]==s.scalar.round_constants(),'independent round-constant LFSR')
    kat=s.zero_permutation()
    require(constants['anon.886b1edfcdffe7c13102d1d0ad2ffa3f.0']==kat,'independent public zero-state KAT')
    for name in records[s.STATE+'7initial']['reference_targets']:
        if name.startswith('__ymm@'):
            expected=int(name.removeprefix('__ymm@'),16).to_bytes(32,'little')
            require(constants[name]==expected and expected in [kat[i:i+32] for i in range(0,192,32)],
                    'vectorized KAT comparison constants')
    for name,values in [(s.OWNER+'6rehash',[28,32,48,64]),(s.OWNER+'6rehash.215',[28,32,48,64]),
                        (s.STATE+'7initial',[144,136,104,72,168,136,168,136]),
                        (s.STATE+'7initial.216',[28,32,48,64])]:
        require(constants['switch.table.'+name]==b''.join(n.to_bytes(8,'little') for n in values),
                'all algorithm rates and output widths')
    for index,value in enumerate((b'\1\2',b'\0',b'\0\5\6',bytes(range(1,7)),b'\3',b'\5\6',b'\4')):
        require(constants['anon.c28106df60482f47ece1441b2addaaaa.'+str(index)]==value,'exact allowed phases')
    return out,tables


def frames_and_edges(records,assembly):
    frames={};edges={};external={};vectors={}
    for name,r in records.items():
        body=assembly[name];fixed=sum(map(int,re.findall(r'\.seh_stackalloc (\d+)',body)))
        fixed += 8*len(re.findall(r'\.seh_pushreg ',body))
        alignment=re.findall(r'andq\s+\$-(\d+), %rsp',body)
        require(not alignment or alignment==['32'],'only reviewed bounded dynamic alignment')
        frames[name]=fixed+(31 if alignment else 0)
        vectors[name]=[list(map(int,pair)) for pair in re.findall(r'\.seh_savexmm %xmm(\d+), (\d+)',body)]
        require(not re.search(r'(?:subq|andq)\s+%[^,]+, %rsp',body),'no dynamic unbounded frame')
        edges[name]=sorted(t for t in r['reference_targets'] if t in records)
        for target,address in r['reference_targets'].items():
            if target not in RUNTIME: continue
            require(target not in external or external[target]['rva']==address,'consistent shared runtime address')
            item=external.setdefault(target,dict(rva=address,assigned_completion_package=8,callers=[]))
            item['callers'].append(name)
    require(set(external)==RUNTIME,'all shared runtime boundaries named')
    require({n for n,v in vectors.items() if v}=={s.KERNEL,
        '_RNvNtNtCshYLbG8W7MpL_17brynja_crypto_cpu16static_execution10operations12known_answer'},
        'all nonvolatile vector save owners')
    for entry in external.values(): entry['callers'].sort()
    from windows_enclave_sha3_chain import contributions
    geometry=contributions(edges,frames)
    return frames,edges,external,vectors,geometry


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    row,directory,data,image,asm,ir,sources=inputs(base,root,spec)
    functions=inventory(data);require(set(functions)==set(spec['functions']),'complete emitted function population')
    for name,values in functions.items(): body_check(*values,spec['functions'][name])
    assembly=s.bodies(asm,functions);kernel=s.semantics(assembly);exits=s.buffer_exits(assembly['RetainedWork'])
    preconditions=s.preconditions(ir)
    reused_functions=reused(functions)
    records=bind_all(data,image,functions)
    constants,tables=data_bindings(data,image,records,functions)
    frames,edges,external,vectors,geometry=frames_and_edges(records,assembly)
    reached=set()
    def visit(name):
        if name in reached: return
        reached.add(name)
        for child in edges[name]: visit(child)
    visit('RetainedWork')
    require(len(reached)==52,'exact normal-path population')
    for name in list(reached):
        for metadata in records[name].get('metadata',[]):
            if metadata['symbol'] in records: visit(metadata['symbol'])
    require(reached==set(functions),'all functions reachable through normal code or bound cleanup metadata')
    # Reproduce C-wrapper/transport boundaries in this exact image.
    transport=w.transport;spec_t=transport.specification(transport.SPEC.read_bytes())
    tp=spec_t['profiles'][3];native=(base/row['object']).read_bytes()
    wrapper=(base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    tr=transport.inspect(native,image,wrapper,(base/'sdk-system32-review/vertdll.dll').read_bytes(),tp,spec_t['templates'])
    parent=shared.inspect(native,image,wrapper)
    require(parent['retained_worker_rva']==records['RetainedWork']['rva'],'actual wrapper enters this worker')
    for target in ('PublicSha3Input','PublicSha3Output','PublicSha3Source','PublicSha3Observe'):
        require(external[target]['rva']==tr['records'][target.removeprefix(tp['prefix'])]['rva'],
                'actual reviewed transport target')
    mutations=0;table_mutations=0
    if mutate:
        for name,(code,refs,runtime) in functions.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try: body_check(bad,refs,runtime,spec['functions'][name])
                except ValueError: mutations+=1
                else: raise AssertionError('accepted body mutant')
        for name,pin in tables.items():
            raw=bytes.fromhex(pin['linked_hex'])
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                try: s.scalar.ops.table_destinations(bad,pin['rva'],records[name]['rva'],pin)
                except ValueError: table_mutations+=1
                else: raise AssertionError('accepted dispatch table mutant')
    return dict(schema=1,status='AUTHOR_SAVED_AVX2_SHA3_INNER_CHAIN_REVIEW',route=row['route'],
        image_sha256=digest(image),object_sha256=digest(data),build_inputs_sha256=sources,
        function_inventory={n:dict(rva=r['rva'],bytes=r['size'],conservative_frame_bytes=frames[n],
            saved_vectors=vectors[n],references=r['reference_targets'],inner_callees=edges[n],
            review=reused_functions.get(n,'scoped source/assembly review; see sha3-avx2-chain documentation')) for n,r in sorted(records.items())},
        kernel=kernel,buffer_exits=exits,constants=constants,dispatch_tables=tables,geometry=geometry,
        compiler_preconditions=preconditions,
        runtime_boundaries_pending=external,inner_function_population=53,cleanup_funclets_bound=8,
        unassigned_inner_functions=[],actual_body_byte_mutations_rejected=mutations,
        actual_table_byte_mutations_rejected=table_mutations,
        outer_window_reclamation_required=True,individual_caller_spills_erased=False,
        arbitrary_exception_cleanup_qualified=False,whole_image_qualified=False,
        independently_verified=False,native_run_added=False,release_gate_changed=False,
        spec_sha256=SPEC_HASH,source_sha256={p.name:digest(p.read_bytes()) for p in
            sorted({Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} |
                   {Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-avx2-chain.py')})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
