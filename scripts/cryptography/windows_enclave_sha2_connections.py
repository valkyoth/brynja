"""Close saved scalar SHA-2 memory/transport edges; no loaded-image attestation."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_primitives as primitives
import windows_enclave_route_memory as memory
import windows_enclave_route_transport as transport

shared,ops,entry = primitives.shared,primitives.ops,primitives.entry
require,digest = shared.require,shared.digest
MEMORY_POPULATION = '3992d9e52a919f3fe534526f2a264055fa33483d0f2bf4d1c041aad22b636680'
CALLBACKS = sorted((('RetainedWork',704,'PublicSha2Observe'),(ops.EXPORT,244,'PublicSha2Output'),
                    (entry.RECEIVE,25,'PublicSha2Source'),(entry.RECEIVE,51,'PublicSha2Input'),
                    (entry.RECEIVE,259,'PublicSha2Input')))


def callback_population(data):
    rows,symbols = entry.obj.tables(data);result=[]
    for index,row in enumerate(rows,1):
        if not row['flags'] & 0x20000000: continue
        for offset,ref in entry.obj.relocations(data,row,symbols).items():
            name=symbols[ref['symbol']]['name']
            if not name.startswith('PublicSha2'): continue
            owners=[s for s in symbols.values() if s['section']==index and s['kind']==0x20]
            require(len(owners)==1 and owners[0]['value']==0,'one complete transport caller')
            require(ref['kind']==4 and offset>0 and row['code'][offset-1]==0xe8 and
                    row['code'][offset:offset+4]==bytes(4),'direct transport call')
            result.append((owners[0]['name'],offset,name))
    return sorted(result)


def population(memory_calls,callbacks):
    require(len(memory_calls)==40 and digest(shared.encoded(memory_calls))==MEMORY_POPULATION,
            'complete forty-call scalar memory population')
    require(callbacks==CALLBACKS,'complete scalar transport call population')


def reconcile(calls,bindings,targets):
    require(set(bindings)=={name for name,_,_ in calls},'every incoming caller bound')
    for name,at,symbol in calls:
        record=bindings[name]
        refs=[r for r in record['references'] if r['offset']==at]
        require(len(refs)==1 and refs[0]['symbol']==symbol and refs[0]['addend']==refs[0]['trailing']==0,
                'actual call relocation identity')
        require(record['reference_targets'][symbol]==targets[symbol],'actual memory/transport destination')


def geometry(window):
    # These caller locations come from the already checked entry/lifecycle,
    # operation and state frame models. REP helpers tail-reuse the call frame.
    primitive=primitives.geometry(window)
    state_finish=window.high+primitive['deepest_selected_caller_rsp_from_high']
    finalize=window.high+primitive['finalize_rsp_from_high']
    spans=[window.span('state copy REP saves and return',state_finish-24,56),
           window.span('finalize fill REP save and return',finalize-16,48)]
    owner_export=window.high+ops.geometry(window)['operations'][ops.EXPORT]['rsp_from_high']
    output=primitives.bounded.Frame.enter(window,owner_export,40)
    sdk=primitives.bounded.Frame.enter(window,output.current,40)
    spans.extend((output.slot('output adapter frame/home',-40,80,'entry'),
                  sdk.slot('SDK outbound-copy frame/home',-40,80,'entry')))
    return dict(spans=spans,output_adapter_rsp_from_high=output.current-window.high,
                sdk_copy_rsp_from_high=sdk.current-window.high,primitive_depth=primitive['deepest_selected_leaf_rsp_from_high'],
                payload_registers_erased_by_runtime=False,outer_window_and_register_clear_required=True,
                sdk_status_tail_uses_reviewed_return_chain=True,maximum_whole_image_depth_qualified=False)


def inspect(data,native,image,wrapper,ir,sdk,spec):
    parent=primitives.inspect(data,native,image,wrapper,ir)
    profile=spec['profiles'][0];require(profile['route']=='sha2/mod.rs::open','scalar transport profile')
    exported=transport.inspect(native,image,wrapper,sdk,profile,spec['templates'])
    runtime=memory.inspect(image,30064)
    memory_calls=memory.bounded.call_population(data);callbacks=callback_population(data)
    population(memory_calls,callbacks)
    calls=sorted(memory_calls+callbacks)
    bindings={name:shared.caller.bind(data,image,name) for name,_,_ in calls}
    targets={'memcpy':runtime['frames']['copy']['rva'],'memset':runtime['frames']['fill']['rva']}
    targets.update({'PublicSha2'+role:v['rva'] for role,v in exported['records'].items()})
    reconcile(calls,bindings,targets)
    require(not memory.bounded.call_population(native),'no additional C memory calls')
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_RUNTIME_EXPORT_CONNECTIONS',
                image_sha256=parent['image_sha256'],object_sha256=digest(data),sdk_sha256=digest(sdk),
                incoming=[dict(caller=n,offset=at,callee=c,target_rva=targets[c]) for n,at,c in calls],
                runtime=runtime,transport=exported,geometry=geometry(primitives.bounded.Window(0,65536)),
                scalar_normal_return_connections_reviewed=True,loaded_application_iat_proven=False,
                live_runtime_selector_initialization_qualified=False,public_output_transactional=False,
                maximum_whole_image_depth_qualified=False,arbitrary_exception_cleanup_qualified=False,
                whole_image_qualified=False,independently_verified=False,native_run_added=False,release_gate_changed=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG);p.add_argument('--templates',type=Path,default=transport.SPEC)
    p.add_argument('--output',type=Path);args=p.parse_args();base=args.saved_directory
    row=shared.catalog(args.catalog.read_bytes())[1]
    native,image=(base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native)==row['object_sha256'] and digest(image)==row['sha256'],'saved scalar identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes())==entry.ARCHIVE,'saved scalar archive')
    sdk=(base/'sdk-system32-review/vertdll.dll').read_bytes();shared.sdk.sdk_review.inspect(sdk)
    result=inspect(args.object.read_bytes(),native,image,
                   (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                   (base/'sha2-scalar-cleanup-image/normal_rust.ll').read_bytes(),sdk,
                   transport.specification(args.templates.read_bytes()))
    paths={Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-connections.py')))
    result['source_sha256']={p.name:digest(p.read_bytes()) for p in sorted(paths)}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
