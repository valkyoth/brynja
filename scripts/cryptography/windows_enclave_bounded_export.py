"""Saved bounded token cross-copy and explicit output export, not a gate."""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_callbacks as callbacks

sha,shared,dispatch = callbacks.sha,callbacks.shared,callbacks.dispatch
require,digest = callbacks.require,callbacks.digest
TOKEN = '_RNvCs7RQXX2qQXJA_22retained_rehash_worker5TOKEN'
SPECS = {
    'PublicCrossCopy':(14176,194,'d99d599a911b83d38fbc50ab0bafbcdded61223d7fe2b6cc67c06ba48d2607ed',
                       '3df9cb731c6076dc01bafbb1b704ba898aa037323164387a81bf53f80a9da152'),
    'PublicCrossControl':(14096,75,'54f74f74e8240748c92b7e067ea62246d902c7082c8c1e087a63f5ff1032eb61',
                          '634ffc129c49e11bf6f4fc92d5ca8d145ba64aa32299364afda4bc4c4035add8'),
    'PublicRetainedCopy':(16592,52,'36d9c3e8a3d9fc12aaf01aef53b590efeaf9ca94a1cb9755563b4934cdd7e8e0',
                          '8d7d41468a0a788092f0aaac786e014a95f21401834f072a11c0a683dbb4dcf1'),
    'PublicRetainedOutput':(16864,34,'172249932155ea79e03302bc0a8244c14fc10e8c87a4a14985262253dbb14050',
                            '15fa788ed857e9a00439b060703dc07c68c416504be4de4712822ccee62b2dfd'),
    'PublicRetainedControl':(16544,44,'f801fe98bd582e355886f09609f19902b1755e3596c6c29efa5cc3c378e42806',
                             '7144d48d3a2f9056f57c065a404bda1203e82b9d22022a179186fd8a9875d1f8'),
    'RetainedTokenWord':(4096,21,'a32deef7d61d5daed5ce65575c7ebdd78edbe02577c0664a8d46effb439c0281',
                         '5c5c510b29deac713641ca3c3bca81b3195252ec002de92ad8a9a8783f6f6202'),
}
# Exact destinations in this one saved image, NOT a portable linker layout.
TARGETS = {'active':41128,'retained_call':41292,'retained_operation':41304,
           'PublicLockedLow':43448,'PublicLockedHigh':43440,'cross_report':41416,
           'input_source':41464,'EnclaveCopyIntoEnclave':23922,'EnclaveCopyOutOfEnclave':23928,
           'retained_live':41320,'RetainedTokenWord':4096,'public_copy_calls':41408,
           'retained_output':41312,'retained_report':41328,TOKEN:43408}
DATA = {'active':4,'retained_call':4,'retained_operation':8,'PublicLockedLow':8,'PublicLockedHigh':8,
        'cross_report':48,'input_source':8,'retained_live':4,'public_copy_calls':8,
        'retained_output':8,'retained_report':80,TOKEN:32}
LANDMARKS = {
    'PublicCrossCopy':((0,'40534883ec20'),(0x24,'48833d000000000a'),
                       (0x42,'483bc8'),(0x47,'482bc14883f820'),(0x50,'48833d0000000000'),
                       (0x61,'41b82000000048c7050000000001000000e80000000085c0'),
                       (0x7b,'48c7050800000001000000'),(0xb1,'4883c4205bc3b8054000804883c4205bc3')),
    'PublicCrossControl':((0,'8b050000000085c0753e3905000000007536488d41f04883f8037712'
                            '833d000000000074234883c1f0e900000000488d41e04883f8057710'
                            '488d0500000000488b84c800ffffffc333c0c3'),),
    'PublicRetainedCopy':((0,'8b050000000085c07424833d0000000000741b833d00000000007412'
                            '4983f820750c48ff0500000000e900000000b805400080c3'),),
    'PublicRetainedOutput':((0,'8b050000000085c07515390500000000750d48890d00000000b801000000c333c0c3'),),
    'PublicRetainedControl':((0,'8b050000000085c0751f3905000000007517488d41f04883f809770d'
                               '488d0500000000488b44c880c333c0c3'),),
    'RetainedTokenWord':((0,'4883f903760331c0c3488d0500000000488b04c8c3'),),
}
BRANCHES = ((0x11,'0f84',0xb7),(0x1e,'0f84',0xb7),(0x2c,'0f85',0xb7),
            (0x39,'72',0xb7),(0x45,'77',0xb7),(0x4e,'72',0xb7),(0x58,'75',0xb7),(0x79,'75',0xbc))


def check_body(name,code,refs):
    _,size,body_hash,refs_hash = SPECS[name]
    require(len(code) == size and digest(code) == body_hash,'complete export body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete export references')


def instructions(name,code):
    for at,text in LANDMARKS[name]:
        raw = bytes.fromhex(text);require(code[at:at+len(raw)] == raw,'cross/export instruction')
    if name != 'PublicCrossCopy': return
    for at,text,target in BRANCHES:
        op = bytes.fromhex(text);width = 4 if len(op) == 2 else 1
        value = code[at+len(op):at+len(op)+width]
        require(code[at:at+len(op)] == op and len(value) == width and
                at+len(op)+width+int.from_bytes(value,'little',signed=True) == target,'cross-copy branch')
    at = 0x86
    for i in range(4):
        load = bytes.fromhex('488b0b') if i == 0 else bytes.fromhex('488b4b')+bytes([i*8])
        raw = load+bytes.fromhex('48890d')+(16+8*i).to_bytes(4,'little')
        require(code[at:at+len(raw)] == raw,'four public token words only');at += len(raw)


def linked_bytes(code,refs,start,targets):
    """Relocate the pinned object against independently reconciled identities."""
    result = bytearray(code)
    for ref in refs:
        require(ref['symbol'] in targets,'known export reference')
        at = ref['offset'];value = targets[ref['symbol']]+ref['addend']-start-at-4-ref['trailing']
        require(0 <= at <= len(code)-4 and -(1<<31) <= value < 1<<31,'bounded REL32 export operand')
        result[at:at+4] = value.to_bytes(4,'little',signed=True)
    return bytes(result)


def mapped_code(rows,functions,start,expected,leaf):
    owners = [r for r in rows if r['rva'] < start+len(expected) and start < r['rva']+r['virtual_size']]
    require(len(owners) == 1,'unique complete export code mapping')
    row = owners[0];offset = start-row['rva']
    require(row['flags'] & 0xa0000020 == 0x20000020 and 0 <= offset and
            offset+len(expected) <= min(len(row['code']),row['virtual_size']),'nonwritable complete export code')
    require(row['code'][offset:offset+len(expected)] == expected,'exact fully relocated export bytes')
    if leaf: require(not any(a < start+len(expected) and start < b for a,b,_ in functions),'no leaf/tail unwind overlap')


def reconcile(parent,common,worker):
    require(worker['image_sha256'] == common['image_sha256'],'same Rust/C image')
    require(worker['reference_targets'].get('PublicCrossCopy') == SPECS['PublicCrossCopy'][0] and
            worker['reference_targets'].get('PublicRetainedCopy') == SPECS['PublicRetainedCopy'][0] and
            worker['reference_targets'].get(TOKEN) == TARGETS[TOKEN],'dispatcher uses these copy/token entries')
    for name,target in TARGETS.items():
        if name in common['reference_targets']:
            require(common['reference_targets'][name] == target,'same existing retained global/callee')
        for record in parent['records'].values():
            require(record['image_sha256'] == common['image_sha256'],'same callback image')
            if name in record['reference_targets']:
                require(record['reference_targets'][name] == target,'same input/control global/callee')


def metadata(rows):
    spans = []
    for name,size in DATA.items():
        address = TARGETS[name]
        owners = [r for r in rows if r['rva'] < address+size and address < r['rva']+r['virtual_size']]
        require(len(owners) == 1 and owners[0]['flags'] & 0xe0000000 == 0xc0000000 and
                owners[0]['rva'] <= address and address+size <= owners[0]['rva']+owners[0]['virtual_size'],
                'bounded writable nonexecutable export metadata')
        spans.append(dict(name=name,rva=address,bytes=size))
    ordered = sorted(spans,key=lambda s:s['rva'])
    require(all(a['rva']+a['bytes'] <= b['rva'] for a,b in zip(ordered,ordered[1:])),'separate export metadata spans')
    return spans


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    cross = dispatch.Frame.enter(window,worker.current,40)
    inbound = dispatch.Frame.enter(window,cross.current,40)
    # PublicRetainedCopy tail-jumps without adding a frame/return address.
    outbound = dispatch.Frame.enter(window,worker.current,40)
    return dict(cross_rsp_from_high=cross.current-window.high,inbound_rsp_from_high=inbound.current-window.high,
                outbound_rsp_from_high=outbound.current-window.high,
                spans=[worker.slot('cross-copy input staging',128,32),worker.slot('copied public token',96,32),
                       cross.slot('saved RBX',-8,8,'entry'),window.span('inbound syscall return',inbound.current-8,8),
                       window.span('outbound syscall return',outbound.current-8,8)],
                exported_host_controls_inside_window_claimed=False,maximum_transitive_depth_qualified=False,
                output_adapter_is_tail_transfer=True,kernel_storage_qualified=False)


def inspect(data,native,image,wrapper,sdk_data,mutate=False):
    parent = callbacks.inspect(data,native,image,wrapper,sdk_data)
    common = shared.inspect(native,image,wrapper)
    worker = shared.caller.bind(data,image,'RetainedWork')
    reconcile(parent,common,worker)
    rows,functions = shared.caller.pe.linked(image)
    records,count = {},0
    for name,(rva,size,_,_) in SPECS.items():
        obj = data if name == 'RetainedTokenWord' else native
        code,refs = shared.caller.function(obj,name);check_body(name,code,refs);instructions(name,code)
        expected = linked_bytes(code,refs,rva,TARGETS)
        mapped_code(rows,functions,rva,expected,name != 'PublicCrossCopy')
        if name == 'PublicCrossCopy':
            bound = shared.caller.bind(obj,image,name);frames = bound['unwind']
            require(bound['rva'] == rva and len(frames) == 1 and frames[0]['stack_bytes'] == 40 and
                    frames[0]['chain'] is None and not frames[0]['saved_registers'],'complete cross-copy fixed frame')
        if name in ('PublicCrossControl','PublicRetainedControl','PublicRetainedOutput'):
            require(callbacks.exported(image,name) == rva,'same named export entry')
        records[name] = dict(rva=rva,bytes=size,linked_sha256=digest(expected),references=refs,
                             reference_targets={r['symbol']:TARGETS[r['symbol']] for r in refs})
        if mutate:
            for i in range(size):
                changed = bytearray(code);changed[i] ^= 1
                try: check_body(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual export byte mutation')
    imports = shared.sdk.imports(image)['vertdll.dll'];sdk_edges = {}
    for name in ('EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave'):
        raw = shared.sdk.thunk(rows,functions,TARGETS[name],imports[name])
        export = shared.sdk.export(sdk_data,name)
        require(export == shared.sdk.status.sdk.BODIES[name][0],'same saved SDK export')
        sdk_edges[name] = dict(thunk_rva=TARGETS[name],bytes=raw,import_rva=imports[name],sdk_export_rva=export)
    shared.sdk.copy_edges()  # Complete outbound direction/syscall/status body.
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_CROSS_AND_EXPORT_REVIEW',records=records,
                metadata_regions=metadata(rows),geometry=geometry(dispatch.Window(0,65536)),sdk_edges=sdk_edges,
                image_sha256=digest(image),sdk_sha256=digest(sdk_data),actual_body_byte_mutations_rejected=count,
                public_token_protocol_required=True,loaded_sdk_identity_proven=False,
                whole_image_qualified=False,native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[0];require(row['route'] == 'mod.rs::open','bounded image')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == dispatch.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sdk-system32-review/vertdll.dll').read_bytes(),args.mutate)
    sources = ('windows_enclave_bounded_export.py','test-windows-enclave-bounded-export.py',
               'windows_enclave_bounded_callbacks.py','windows_enclave_bounded_sha256.py','windows_enclave_bounded_owner.py',
               'windows_enclave_bounded_rehash.py','windows_enclave_bounded_input.py','windows_enclave_bounded_dispatch.py',
               'windows_enclave_sequential_c.py','windows_enclave_sdk_return.py','windows_enclave_sdk_status.py',
               'windows_enclave_sdk_frames.py','windows_enclave_caller_binding.py','windows_enclave_caller_unwind.py',
               'windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
