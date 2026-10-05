"""Saved sequential C helper normal paths; no SDK or arbitrary-unwind claim."""
import argparse
import json
from pathlib import Path

import windows_enclave_sequential_c as shared
import windows_enclave_caller_handlers as handlers
from windows_enclave_frame_geometry import Frame, Window

require, digest = shared.require, shared.digest
SPECS = {
    'BaseLockedBody': (80,6,'5374bb1b493ace233bd16acf04f3db269c84487e6d84b99c58ff2f533e1502d9',
                        '6b3140eab12e4631dd5f40d6ca7daf540d1c9bde87a05728521a0d9c81b75b06'),
    'page_info': (137,3,'45f45756772e9ad5d8bb3c9c61561c3860c14728d44fa0aa53011201836b775d',
                   '3e705a12d17fde27c88923a6b4f87bd46756e48fa8941611a50edd055fb98bbd'),
    'notify_host': (78,3,'f5604b66a26282fd8ea72574ec48f6f7d514097e73d66505b1632bd639209ec4',
                     'f933e7a9794df458d997d535852f46f0b265b1ec64000d178b3bcea62cf7305c'),
    'retained_guards': (98,6,'e5e4f941ff56f28be51a038f7f234225520a64dfc861c035aa95ea4b5248d322',
                         'f8edcf3bb069ad7c454f64bb60338760c8ab27224b6587cc9c88fe24983fd75d'),
    'retained_page': (122,1,'168e3abd6d96a56a919d02a1b9b47d0189076e2a09414ca529cfbc95c9706294',
                       'da2b3bba259fce8d20b0abd8f6ffcb68dd245d1ea02d634e8b994e3a695d42ed'),
    'retained_notify': (93,3,'56a6e5a56a1ab1ff8b0592f0490a828adc246a14713a9d93b0476c63b418b1b4',
                         'af94071fc0a9f8a8eb75da931411200288f1856d97d40b265c4e53947c8aeaf7'),
    'retained_free': (83,6,'71500bf47467433609110b480a16e1c73e37399951c1c0496125a00c6fddd6c2',
                       '2d5d553efe05c0c0e503cb819149f5c65ec0a1eccb2d2ee7e0c1084464584f1c'),
    'locked_work': (337,14,'074c6b81d9acd2464a40b5849e227a09f8edd20d978d6ebe973173c262826395',
                     '61c149091ae54f817b8d901894b7198ed2ffb5e3ccaaef1a4e34b422ccf8fd5b'),
}
HANDLERS = {'BaseLockedBody':'__C_specific_handler','locked_work':'__GSHandlerCheck_SEH'}
LANDMARKS = (
    ('BaseLockedBody',0x26,'e800000000eb17'),
    ('page_info',0x20,'4883f830'),('page_info',0x42,'817c244000100000'),
    ('page_info',0x4c,'397c2444'),('page_info',0x57,'483bc3'),
    ('page_info',0x61,'4881f900100000'),('page_info',0x6a,'482bd8488d8100f0ffff483bd8'),
    ('retained_page',0x20,'4883f830'),('retained_page',0x26,'817c244000100000'),
    ('retained_page',0x30,'397c2444'),('retained_page',0x3b,'483bc3'),
    ('retained_page',0x45,'4881f900100000'),('retained_page',0x4e,'482bd8488d8100f0ffff483bd8'),
    ('notify_host',7,'48c744243800000000'),('notify_host',0x35,'48837c243801'),
    ('retained_notify',7,'48c744243800000000'),('retained_notify',0x28,'4881c200100000'),
    ('retained_notify',0x34,'480bd04533c0'),('retained_notify',0x44,'48837c243801'),
    ('retained_guards',0xb,'ba01000000'),('retained_guards',0x20,'ba040000004881c100100000'),
    ('retained_guards',0x3c,'ba010000004881c100200000'),
    ('retained_free',0xb,'33d241b800800000'),
    ('retained_free',0x33,'48c7050000000000000000b801000000'),
    ('locked_work',0x59,'c6440430a5'),('locked_work',0x9d,'4885d2'),
    ('locked_work',0xd9,'488bc7'),('locked_work',0xe0,'40887c043048ffc0483d00010000'),
    ('locked_work',0x100,'0fb64414308bcf84c00f44cb8bd948ffc24881fa00010000'),
    ('locked_work',0x130,'488b8c24300100004833cce800000000'),
)
BRANCHES = (
    ('BaseLockedBody',0x13,0x75,0x1a),('BaseLockedBody',0x2b,0xeb,0x44),
    ('page_info',0x24,0x74,0x42),('page_info',0x4a,0x75,0x35),
    ('page_info',0x50,0x75,0x35),('page_info',0x5a,0x77,0x35),
    ('page_info',0x68,0x72,0x35),('page_info',0x77,0x77,0x35),
    ('retained_page',0x24,0x75,0x6d),('retained_page',0x2e,0x75,0x6d),
    ('retained_page',0x34,0x75,0x6d),('retained_page',0x3e,0x77,0x6d),
    ('retained_page',0x4c,0x72,0x6d),('retained_page',0x5b,0x77,0x6d),
    ('notify_host',0x1a,0x74,0x47),('notify_host',0x33,0x74,0x47),('notify_host',0x3b,0x75,0x47),
    ('retained_notify',0x1a,0x74,0x56),('retained_notify',0x26,0x74,0x56),
    ('retained_notify',0x42,0x74,0x56),('retained_notify',0x4a,0x75,0x56),
    ('retained_guards',0x17,0x74,0x5b),('retained_guards',0x33,0x74,0x5b),
    ('retained_guards',0x4f,0x74,0x5b),('retained_free',0x1b,0x75,0x33),
    ('locked_work',0xa0,0x74,0xb5),('locked_work',0xee,0x72,0xe0),('locked_work',0x118,0x72,0x100),
)


def check_template(name,code,refs):
    size,count,code_hash,refs_hash = SPECS[name]
    require(len(code) == size and digest(code) == code_hash,'complete sequential helper body')
    require(len(refs) == count and digest(shared.encoded(refs)) == refs_hash,'complete helper relocations')


def instructions(bodies):
    require(set(bodies) == set(SPECS),'helper instruction population')
    for name,offset,hexcode in LANDMARKS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code,'helper instruction landmark')
    for name,offset,opcode,target in BRANCHES:
        code = bodies[name][offset:offset+2]
        require(len(code) == 2 and code[0] == opcode and
                offset+2+int.from_bytes(code[1:],'little',signed=True) == target,'helper branch target')


def reconcile(parent,records,imports):
    require(set(records) == set(SPECS),'complete helper population')
    identities = dict(parent['reference_targets'])
    # Seed all helper entry addresses before resolving their inter-helper calls.
    for name,record in records.items():
        require(record['image_sha256'] == parent['image_sha256'],'same helper image')
        require(record['size'] == SPECS[name][0],'complete helper runtime extent')
        require(name not in identities or identities[name] == record['rva'],'parent helper entry')
        identities[name] = record['rva']
        if name in HANDLERS:
            require(record['handler'] is not None and record['handler']['symbol'] == HANDLERS[name],
                    'known bound handler identity, not handler qualification')
    for record in records.values():
        for symbol,target in record['reference_targets'].items():
            require(symbol not in identities or identities[symbol] == target,'helper target/global agreement')
            identities[symbol] = target
            if symbol.startswith('__imp_'):
                require(imports.get(symbol[6:]) == target,'named helper SDK import')
    return identities


def geometry(window):
    """Only these inspected calls; OS frames and Rust workers stop at entry."""
    body = Frame.enter(window,window.high-32,56)
    base = Frame.enter(window,body.current,40)
    marker = Frame.enter(window,base.current,328)
    notify = Frame.enter(window,body.current,40)
    guards = Frame.enter(window,body.current,40)
    page = Frame.enter(window,guards.current,88)
    free = Frame.enter(window,body.current,40)
    frames = dict(body=body,base=base,public_marker=marker,retained_notify=notify,
                  retained_guards=guards,retained_page=page,retained_free=free)
    spans = [body.slot('saved RBP',-8,8,'entry'),
             body.slot('saved RBX',64,8),body.slot('saved RSI',80,8),body.slot('saved RDI',88,8),
             base.slot('public exception marker',56,1),marker.slot('public sentinel',48,256),
             marker.slot('cookie',304,8),marker.slot('saved RBX',336,8),
             notify.slot('public acknowledgement',56,8),page.slot('page-query metadata',32,48),
             page.slot('saved RBX',96,8)]
    return dict(frames={n:dict(rsp_from_high=f.current-window.high,entry_from_high=f.entry-window.high)
                        for n,f in frames.items()},spans=spans,
                unknown_callees=[body.unknown_callee('RetainedWork entry/home'),
                                 notify.unknown_callee('CallEnclave entry/home'),
                                 page.unknown_callee('VirtualQuery entry/home'),
                                 free.unknown_callee('VirtualFree entry/home')],
                pre_post_window_callback_frames_included=False,
                maximum_transitive_depth_qualified=False,runtime_placement_measured=False)


def inspect(data,image,wrapper):
    parent = shared.inspect(data,image,wrapper)
    selected = {name:shared.caller.function(data,name) for name in SPECS}
    for name,(code,refs) in selected.items(): check_template(name,code,refs)
    instructions({name:v[0] for name,v in selected.items()})
    records = {}
    for name in SPECS:
        if name in HANDLERS:
            # Do not mistake an entry-only runtime fragment for this full body.
            *_,code,refs = handlers.obj.select(data,name)
            normalized = [{k:v for k,v in r.items() if k != 'symbol_index'} for r in refs]
            require((code,normalized) == selected[name],'handler extent covers complete helper section')
            records[name] = handlers.bind(data,image,name)
        else:
            records[name] = shared.caller.bind(data,image,name)
    identities = reconcile(parent,records,shared.sdk.imports(image)['vertdll.dll'])
    entries = {name:dict(rva=r['rva'],bytes=r['size'],
                        handler=r.get('handler'),normal_local_frame_only=True) for name,r in records.items()}
    return dict(image_sha256=parent['image_sha256'],object_sha256=parent['object_sha256'],
                entries=entries,reference_targets=identities,whole_image_qualified=False,
                sdk_semantics_qualified=False,exception_handler_semantics_qualified=False)


def collect(base,mutate=False):
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    records,count = [],0
    for row in shared.catalog(shared.CATALOG.read_bytes()):
        data,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
        require(digest(data) == row['object_sha256'] and digest(image) == row['sha256'],'saved helper inputs')
        records.append(dict(route=row['route'],**inspect(data,image,wrapper)))
        if mutate and len(records) == 1:
            for name in SPECS:
                code,refs = shared.caller.function(data,name)
                for index in range(len(code)):
                    changed = bytearray(code); changed[index] ^= 1
                    try: check_template(name,changed,refs)
                    except ValueError: count += 1
                    else: raise AssertionError('accepted helper byte mutation')
    return dict(schema=1,date='2026-10-05',status='SAVED_SEQUENTIAL_HELPER_NORMAL_PATH_REVIEW',
                catalog_sha256=shared.CATALOG_SHA256,images=len(records),
                complete_helper_bindings=len(records)*len(SPECS),unique_template_bytes=sum(s[0] for s in SPECS.values()),
                actual_template_byte_mutations_rejected=count,records=records,geometry=geometry(Window(0,65536)),
                worker_review_transferred=False,sdk_semantics_qualified=False,whole_image_qualified=False,
                exception_cleanup_qualified=False,native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--catalog',type=Path,default=shared.CATALOG)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    shared.CATALOG = args.catalog
    result = collect(args.saved_directory,args.mutate)
    sources = ('windows_enclave_sequential_helpers.py','test-windows-enclave-sequential-helpers.py',
               'windows_enclave_sequential_c.py','windows_enclave_caller_handlers.py',
               'windows_enclave_caller_object.py','windows_enclave_caller_binding.py',
               'windows_enclave_caller_unwind.py','windows_enclave_wrapper_binding.py','windows_enclave_sdk_return.py',
               'windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
