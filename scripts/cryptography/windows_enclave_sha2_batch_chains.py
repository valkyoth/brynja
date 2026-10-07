"""Saved SHA-2 batch inventories and admission review; not a release gate."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_kmac_chains as c
import windows_enclave_sha2_batch_shapes as shapes
import windows_enclave_sha2_batch_reuse as reuse
import windows_enclave_sha2_simd_reuse as simd_reuse
import windows_enclave_sha2_simd_indices as simd_indices
import windows_enclave_sha2_descriptor_bounds as descriptor_bounds
import windows_enclave_sha2_frame_cell as frame_cell
import windows_enclave_sha2_call_effects as call_effects
import windows_enclave_sha2_transfer_effects as transfer_effects
import windows_enclave_sha2_control_effects as control_effects
import windows_enclave_sha2_effect_placement as effect_placement
import windows_enclave_sha2_cleanup_paths as cleanup_paths
import windows_enclave_sha2_callee_stack as callee_stack
import windows_enclave_sha2_source_lifetime as source_lifetime
import windows_enclave_sha2_slot_origins as slot_origins

SPEC=c.shared.CATALOG.with_name('sha2-batch-chains-20261006.json')
SPEC_HASH='44369ff240a60f6d33d8aafb017aeb26d5b29e628d782d2ca6a47babc6ad709f'
COUNTS={'scalar':32,'sha_ni':42,'simd256':52,'simd512':52}
PREFIX={'scalar':'PublicSha2Batch','sha_ni':'PublicSha2Batch',
        'simd256':'PublicSha256Simd','simd512':'PublicSha512Simd'}
require,digest=c.require,c.digest


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen four-route batch inventory')
    value=json.loads(raw)
    require(set(value)==set(COUNTS),'four distinct batch routes')
    for lane,n in COUNTS.items(): require(len(value[lane]['functions'])==n,'complete batch population')
    return value


def source_closure(root,manifests,count):
    sources={}
    for manifest in manifests:
        for name,sha in manifest['source_sha256'].items():
            name=name.replace('\\','/');path=Path(name)
            require(not path.anchor and ':' not in name and '..' not in path.parts,'relative build source')
            require(name not in sources or sources[name]==sha,'consistent manifest overlap')
            require(digest((root/path).read_bytes())==sha,'unchanged native build source '+name)
            sources[name]=sha
    require(len(sources)==count,'complete merged build input population')
    return sources


def load(base,root,pin):
    row=next(r for r in c.shared.catalog(c.shared.CATALOG.read_bytes()) if r['route']==pin['route'])
    profile=next(r for r in c.w.specification(c.w.SPEC.read_bytes())['profiles'] if r['route']==pin['route'])
    directory=(base/row['object']).parent
    data=c.w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image=(base/row['image']).read_bytes();asm=(directory/'normal_rust.s').read_bytes()
    ir=(directory/'normal_rust.ll').read_bytes();build=(directory/pin['build_name']).read_bytes()
    for key,raw in [('object',data),('image',image),('assembly',asm),('ir',ir),('build',build)]:
        require(digest(raw)==pin[key+'_sha256'],'saved batch '+key)
    manifests=[json.loads(build)]
    for name,sha in pin['extra_manifests'].items():
        raw=(directory/name).read_bytes()
        require(digest(raw)==sha==manifests[0]['worker_record_sha256'],'image-to-worker build binding')
        manifests.append(json.loads(raw))
    require(manifests[-1]['target']=='x86_64-pc-windows-msvc','actual MSVC worker target')
    return row,data,image,asm.decode(),ir.decode(),source_closure(root,manifests,pin['source_count'])


def vtable_check(raw,relocations,symbols,image,address,records):
    require(len(raw)==40 and raw[:24]==bytes(16)+(1).to_bytes(8,'little') and raw[24:]==bytes(16),
            'exact stateless callback vtable layout')
    require(set(relocations)=={24,32},'two exact callable vtable slots')
    linked=c.previous.readonly(image,address,40)
    require(linked[:24]==raw[:24],'linked stateless callback metadata')
    # Linked absolute pointers include ImageBase, unlike the function RVAs.
    pe=int.from_bytes(image[0x3c:0x40],'little');image_base=int.from_bytes(image[pe+48:pe+56],'little')
    targets={}
    for at,ref in relocations.items():
        name=symbols[ref['symbol']]['name']
        require(ref['kind']==1 and name in records,'exact local ADDR64 callback target')
        require(int.from_bytes(linked[at:at+8],'little')==image_base+records[name]['rva'],
                'actual linked callback destination')
        targets[str(at)]=name
    return dict(bytes=40,slots=targets,metadata=[0,0,1],callsite_provenance_review_pending=True)


def bind_all(data,image,functions):
    records={};pending=set(functions);rows,symbols=c.obj.tables(data)
    while pending:
        before=len(pending);errors=[]
        for name in sorted(pending):
            anchors=list(records.values())
            for parent in records.values():
                targets={v['symbol']:v['symbol_rva'] for v in parent.get('metadata',[]) if v['symbol'].startswith('?dtor')}
                if targets: anchors.append(dict(entry=parent['entry']+':bound-xdata',image_sha256=digest(image),reference_targets=targets))
                for target,address in parent['reference_targets'].items():
                    if not target.startswith('anon.'): continue
                    found=[v for v in symbols.values() if v['name']==target and v['section']>0]
                    require(len(found)==1,'one incoming data anchor')
                    sym=found[0];row=rows[sym['section']-1];raw=row['code']
                    if len(raw)!=40 or not row['nrelocs']: continue
                    require(sym['value']==0 and row['flags'] & 0xe0000000==0x40000000,'read-only callback anchor')
                    refs=c.obj.relocations(data,row,symbols)
                    require(raw==bytes(16)+(1).to_bytes(8,'little')+bytes(16) and set(refs)=={24,32},
                            'exact stateless callback anchor layout')
                    linked=c.previous.readonly(image,address,40)
                    require(linked[:24]==raw[:24],'actual callback metadata')
                    pe=int.from_bytes(image[0x3c:0x40],'little');base=int.from_bytes(image[pe+48:pe+56],'little')
                    values={}
                    for at,ref in refs.items():
                        callee=symbols[ref['symbol']]['name']
                        require(ref['kind']==1 and callee in functions,'local ADDR64 callback anchor')
                        values[callee]=int.from_bytes(linked[at:at+8],'little')-base
                    anchors.append(dict(entry=parent['entry']+':'+target,image_sha256=digest(image),reference_targets=values))
            try:
                record=(c.previous.handlers.bind(data,image,name,anchors) if functions[name][2]
                        else c.previous.leaf.bind(data,image,name,anchors))
            except ValueError as error: errors.append(str(error));continue
            records[name]=record;pending.remove(name)
        require(len(pending)<before,'complete anchored batch population: '+repr(sorted(pending))+' '+repr(errors))
    for r in records.values():
        for target,address in r['reference_targets'].items():
            if target in records: require(address==records[target]['rva'],'exact local batch callee')
        for ref in r.get('metadata',[]):
            if ref['symbol'] in records: require(ref['symbol_rva']==records[ref['symbol']]['rva'],'exact batch cleanup target')
    return records


def location_check(raw,relocations,symbols,rows,image,address):
    require(len(raw)==24 and raw[:8]==bytes(8) and set(relocations)=={0},'bounded panic location')
    ref=relocations[0];sym=symbols[ref['symbol']]
    require(ref['kind']==1 and sym['section']>0 and sym['value']==0,'exact diagnostic filename pointer')
    row=rows[sym['section']-1]
    require(not row['nrelocs'] and row['flags'] & 0xe0000000==0x40000000 and
            len(row['code'])==int.from_bytes(raw[8:16],'little')+1 and row['code'][-1:]==b'\0',
            'immutable diagnostic filename plus terminator')
    linked=c.previous.readonly(image,address,24)
    require(linked[8:]==raw[8:],'actual diagnostic length/line/column')
    pe=int.from_bytes(image[0x3c:0x40],'little');base=int.from_bytes(image[pe+48:pe+56],'little')
    target=int.from_bytes(linked[:8],'little')-base
    require(c.previous.readonly(image,target,len(row['code']))==row['code'],'actual diagnostic filename')
    return dict(bytes=24,filename_sha256=digest(row['code']),line=int.from_bytes(raw[16:20],'little'),
                column=int.from_bytes(raw[20:24],'little'),failstop_preconditions_review_pending=True)


def data_bindings(data,image,records,functions,runtime_names,lane):
    rows,symbols=c.obj.tables(data);vtables={};locations={};filtered={}
    for name,r in records.items():
        ordinary=dict(r['reference_targets'])
        for target,address in r['reference_targets'].items():
            if not target.startswith('anon.'): continue
            found=[v for v in symbols.values() if v['name']==target and v['section']>0]
            require(len(found)==1,'unique anonymous data object')
            sym=found[0];row=rows[sym['section']-1]
            if not row['nrelocs']: continue
            if lane=='sha_ni':
                require(target in ('anon.4e9befcfadcea9e573802173d9a06cb2.8',
                    'anon.4e9befcfadcea9e573802173d9a06cb2.9') and sym['value']==0 and
                    row['flags'] & 0xe0000000==0x40000000,'two frozen SHA-NI panic locations')
                locations[target]=location_check(row['code'],c.obj.relocations(data,row,symbols),symbols,rows,image,address)
                del ordinary[target];continue
            require(lane.startswith('simd') and sym['value']==0 and
                    row['flags'] & 0xe0000000==0x40000000,'read-only SIMD callback table only')
            vtables[target]=vtable_check(row['code'],c.obj.relocations(data,row,symbols),symbols,image,address,records)
            del ordinary[target]
        filtered[name]=r|{'reference_targets':ordinary}
    require(len(vtables)==(1 if lane.startswith('simd') else 0),'exact callback-table population')
    require(len(locations)==(2 if lane=='sha_ni' else 0),'exact panic-location population')
    constants,tables,runtime=c.data_bindings(data,image,filtered,functions,runtime_names)
    return constants,tables,runtime,vtables,locations


def public_constructor_constants(constants,lane):
    if lane=='scalar':
        expected={shapes.iv.ROUND:(640,'125cf2084d7eec18dc9795be4baa221655c0eabab89e90a74fb0370378a60293')}
    elif lane=='sha_ni':
        kat=shapes.placement.kat
        expected={kat.TABLE:(256,'74ef7306e7452d6859b6463ce496b8df30925f69e1b2969e1f3f34bbc9c6af04')}
        for name in (kat.INITIAL,kat.EXPECTED):
            expected[name]=(32,digest(int(name[6:],16).to_bytes(32,'little')))
    else:
        kernel=shapes.simd_kernel
        raw=kernel.round_constants(lane)
        expected={kernel.CONSTANTS[lane]:(len(raw),digest(raw))}
        initial,answer=shapes.simd_constructor.constants(lane)
        expected.update({name:(len(raw),digest(raw)) for name,raw in initial+answer})
    for name,(size,sha) in expected.items():
        require(name in constants and constants[name]['bytes']==size and constants[name]['sha256']==sha,
                'reviewed linked public constructor constant '+name)
    return expected


def inspect_route(base,root,lane,pin,mutate):
    row,data,image,asm,ir,sources=load(base,root,pin)
    functions=c.previous.inventory(data)
    require(set(functions)==set(pin['functions']),'complete frozen batch bodies')
    for n,v in functions.items(): c.body_check(v,pin['functions'][n])
    bodies=c.previous.s.bodies(asm,functions);records=bind_all(data,image,functions)
    runtime_names={'memcpy','memset','memcmp','__chkstk','PublicProbeAbort'} | {
        PREFIX[lane]+suffix for suffix in ('Input','Output','Source','Observe')}
    constants,tables,runtime,vtables,locations=data_bindings(data,image,records,functions,runtime_names,lane)
    sizes,edges,vectors,indirect,geometry=c.frames(records,bodies)
    pending_calls={n:[l for l in c.shapes.lines(bodies[n]) if l.startswith('callq *')]
                   for n in indirect if any(l.startswith('callq *') for l in c.shapes.lines(bodies[n]))}
    # Indirect calls do not become a depth proof just because direct references
    # and jump tables bind. Their actual authority/cancellation provenance is
    # retained as explicit family work, not reassigned to shared runtime review.
    transport=c.transport_binding(base,row,data,image,records,runtime,PREFIX[lane])
    semantics=shapes.inspect(bodies,ir,lane)
    if lane.startswith('simd'):
        semantics['simd_authority']['cleanup_tables']=shapes.simd_authority.cleanup_tables(asm,bodies,lane)
        semantics['simd_authority']['callback_unwind']['cleanup_state_order_review_pending']=False
        semantics['simd_authority']['callback_unwind']['enclosing_storage_lifetimes_pending']=True
        if lane=='simd512':
            shapes.simd_digest.wide_widths(bodies,asm)
            semantics['simd_scalar_finish']['variant_tables']=shapes.simd_finish.tables(asm)
    semantics['public_constructor_constants']=public_constructor_constants(constants,lane)
    if lane.startswith('simd'):
        semantics['simd_primitive_contracts']=simd_reuse.inspect(base,lane,functions,ir,bodies,constants)
        semantics['simd_compact_indices']=simd_indices.inspect(bodies,lane)
        semantics['simd_descriptor_bounds']=descriptor_bounds.inspect(bodies,lane)
        semantics['simd_first_output_frame_cell']=frame_cell.inspect(bodies,lane)
        semantics['simd_scalar_call_effects']=call_effects.inspect(bodies,lane,
            semantics['simd_first_output_frame_cell'])
        semantics['simd_transfer_call_effects']=transfer_effects.inspect(bodies,lane,
            semantics['simd_first_output_frame_cell'],semantics['simd_scalar_call_effects'])
        semantics['simd_control_call_effects']=control_effects.inspect(bodies,lane,
            semantics['simd_first_output_frame_cell'],semantics['simd_transfer_call_effects'],vtables)
        semantics['simd_conditional_effect_placement']=effect_placement.inspect(bodies,lane,
            semantics['simd_first_output_frame_cell'],semantics['simd_scalar_call_effects'],
            semantics['simd_transfer_call_effects'],semantics['simd_control_call_effects'])
        semantics['simd_whole_function_cleanup_order']=cleanup_paths.inspect(bodies,asm,lane)
        semantics['simd_tracked_callee_stack']=callee_stack.inspect(bodies,lane,
            semantics['simd_first_output_frame_cell'],semantics['simd_scalar_call_effects'],
            semantics['simd_transfer_call_effects'],semantics['simd_control_call_effects'])
        semantics['simd_first_source_cfg_origin']=source_lifetime.inspect(bodies,asm,lane,
            semantics['simd_first_output_frame_cell'])
        if lane=='simd512':
            semantics['simd_helper_slot_origins']=slot_origins.inspect(bodies,asm,
                semantics['simd_first_output_frame_cell'],semantics['simd_conditional_effect_placement'],
                semantics['simd_tracked_callee_stack'])
    if lane=='scalar': semantics['variant_dispatch_order']=shapes.batch_state.scalar_tables(bodies,asm)
    reused=reuse.inspect(base,lane,data,functions,ir,bodies) if lane in ('scalar','sha_ni') else None
    mutations=table_mutations=0
    if mutate:
        for name,(code,refs,kind) in functions.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try: c.body_check((bad,refs,kind),pin['functions'][name])
                except ValueError: mutations+=1
                else: raise AssertionError('accepted complete-body mutant')
        for name,p in tables.items():
            raw=bytes.fromhex(p['linked_hex'])
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                try: c.previous.s.scalar.ops.table_destinations(bad,p['rva'],records[name]['rva'],p)
                except ValueError: table_mutations+=1
                else: raise AssertionError('accepted table mutant')
    return dict(route=row['route'],source_sha256=sources,image_sha256=digest(image),
        object_sha256=digest(data),functions={n:dict(rva=r['rva'],bytes=r['size'],frame_bytes=sizes[n],
            saved_vectors=vectors[n],inner_references=edges[n],references=r['reference_targets'])
            for n,r in sorted(records.items())},cleanup_funclets=sum(n.startswith('?') for n in functions),
        constants=constants,dispatch_tables=tables,callback_tables=vtables,panic_locations=locations,
        indirect_transfers=indirect,
        callback_callsite_review_pending=pending_calls,transport=transport,semantics=semantics,
        reproduced_primitive_contracts=reused,
        direct_graph_geometry_only=geometry,transitive_depth_qualified=False,
        runtime_boundaries_pending=runtime,body_byte_mutations_rejected=mutations,
        table_byte_mutations_rejected=table_mutations)


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    return dict(schema=1,status='AUTHOR_PARTIAL_SHA2_BATCH_CHAIN_REVIEW',completion_package=5,
        completion_package_closed=False,whole_image_qualified=False,independent_retest=False,
        release_gate_changed=False,native_run_added=False,
        routes={lane:inspect_route(base,root,lane,pin,mutate) for lane,pin in spec.items()},
        remaining_private_review=['batch-specific caller preconditions for reproduced primitive contracts',
            'enclosing constructor frame cleanup and batch-specific storage composition',
            'SIMD surrounding pointer/storage lifetimes, lane engines, kernels and normal error paths',
            'complete reachable frame and storage assignments; fail-stop preconditions'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();value=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(value,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
