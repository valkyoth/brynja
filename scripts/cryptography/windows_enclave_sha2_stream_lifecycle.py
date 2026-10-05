"""Saved scalar streaming owner admission/cancellation/destruction review."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_stream_entry as entry
import windows_enclave_bounded_owner as wiping

shared,bounded = entry.shared,entry.bounded
require,digest = entry.require,entry.digest
PREFIX = '_RNvMs0_Csad7P77nok56_11sha2_streamNtB5_5Owner'
QUARANTINE,OPERATION,CANCEL = (PREFIX+s for s in ('10quarantine','9operation','6cancel'))
DROP = '_RNvXs2_Csad7P77nok56_11sha2_streamNtB5_5OwnerNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
IR_HASH = 'ae7bda220403911c8d4f4db6d5871d443b49ce5f2c2c203658efc856beaa2159'
PINS = {
    QUARANTINE:(106,'0028b1f4d2b30cf1cc9b6c37979aa59ba669c266910fa505aab5c2340345193a',
                'eae7d6b8887f9a0d2a9c45a51f72f09b67b69833514775d2d07510a264156a52'),
    OPERATION:(257,'180c5e5ab3c7ef24a36378f827074bbc9c952e5d1f5926f8102f506d8e47ee57',
               'c30df69e54e1ccb01d866bdbf24c88a40d2b3f0f036d70d9e61edc3a63a9eb3c'),
    CANCEL:(252,'a7763b9c5aeafc3d9d7f6bbfdb7a4a48d4221f124c38c3d99a8e57a4a1346a90',
            '87644c892a7bd7993dbd98af68e8aa4d3234941770f50688673e04c1c12b0d90'),
    DROP:(99,'abbfda01b5c4998d226b0051de29242663a686506c54df26246fbf63594e59a6',
          'eae7d6b8887f9a0d2a9c45a51f72f09b67b69833514775d2d07510a264156a52'),
}
# Start, stack-copy offset, owner register, and normal continuation phase.
COPY_SITES = {QUARANTINE:((0xb,42,'rsi',3),),DROP:((0xb,42,'rsi',None),),
              OPERATION:((0x25,34,'rdi',3),(0x8e,34,'rdi',3)),
              CANCEL:((0x3c,40,'rsi',3),(0x9b,40,'rsi',0))}
LANDMARKS = {
    QUARANTINE:((0,'564881ecc00400004889ce'),(0x61,'4881c4c00400005ec3')),
    DROP:((0,'564881ecc00400004889ce'),(0x5a,'4881c4c00400005ec3')),
    OPERATION:((0,'56574881ecb80400004889d74889ce'),
               (0xf,'0fb682e20400004438c80f94c13c030f95c084c1'),
               (0x7b,'c60602b002eb72'),(0x82,'488b474048ffc04c39c0'),
               (0xe4,'c60601b002eb09'),(0xeb,'4c89474048893e31c08846084881c4b80400005f5ec3')),
    CANCEL:((0,'564881ecc00400004889ce440fb689e2040000418d41ff3c02'),
            (0x1b,'4989d0488d4c24284889f2e800000000807c243002'),
            (0x32,'0fb6442428e9b7000000'),(0x92,'b002eb5d'),
            (0x96,'488b742428'),(0xf1,'b0ff4881c4c00400005ec3')),
}
BRANCHES = {OPERATION:((0x23,'75',0x82),(0x8c,'74',0xeb)),
            CANCEL:((0x19,'73',0x3c),(0x30,'75',0x96))}


def copy_shape(stack,register,phase):
    require(register in ('rsi','rdi') and stack in (34,40,42) and phase in (None,0,3),'reviewed copy shape')
    # Complete copy/tag/wipe/output-clear/metadata sequence, not just a hash.
    reg = '56' if register == 'rsi' else '57'
    raw = bytes.fromhex('488d'+reg+'48488d4c24')+bytes([stack])
    raw += bytes.fromhex('41b896040000e800000000c6')+bytes.fromhex('46' if register == 'rsi' else '47')
    raw += bytes.fromhex('48ff0fb64424')+bytes([stack])+bytes.fromhex('3cff741831c93c060f93c1488d0449488d0c044883c1')
    raw += bytes([stack+1])+bytes.fromhex('e800000000ba400000004889')
    raw += bytes.fromhex('f1' if register == 'rsi' else 'f9')+bytes.fromhex('e80000000066c7')
    raw += bytes.fromhex('86' if register == 'rsi' else '87')+bytes.fromhex('de040000ffff')
    if phase is not None:
        raw += bytes.fromhex('c6')+bytes.fromhex('86' if register == 'rsi' else '87')+bytes.fromhex('e2040000')+bytes([phase])
    return raw


def body_check(name,code,refs):
    size,ch,rh = PINS[name]
    require(len(code) == size and digest(code) == ch,'complete streaming lifecycle body')
    require(digest(shared.encoded(refs)) == rh,'complete streaming lifecycle references')


def instructions(name,code):
    for at,h in LANDMARKS[name]:
        raw = bytes.fromhex(h);require(code[at:at+len(raw)] == raw,'lifecycle admission/result instruction')
    for at,stack,register,phase in COPY_SITES[name]:
        raw = copy_shape(stack,register,phase)
        # Quarantine/drop source address is RCX before the owner is kept in RSI.
        if name in (QUARANTINE,DROP): raw = bytes.fromhex('488d5148')+raw[4:]
        require(code[at:at+len(raw)] == raw,'complete take/copy/wipe/clear path')
    for at,h,target in BRANCHES.get(name,()):
        op = bytes.fromhex(h)
        require(code[at:at+1] == op and at+2+int.from_bytes(code[at+1:at+2],'little',signed=True) == target,
                'lifecycle branch target')


def sequence_model(stored,requested):
    """Machine comparison plus ingress precondition; not independent execution."""
    require(type(stored) is int and type(requested) is int and 0 <= stored < 1<<64 and
            0 <= requested < 1<<64,'u64 sequence domain')
    return requested != 0 and ((stored+1) & ((1<<64)-1)) == requested


def ir_precondition(raw):
    require(digest(raw) == IR_HASH,'saved compiler IR identity')
    lines = raw.decode('utf-8').splitlines()
    found = [line for line in lines if line.startswith('define ') and '@'+OPERATION+'(' in line]
    require(len(found) == 1 and 'define internal fastcc void ' in found[0] and
            'i64 noundef range(i64 1, 0) %2' in found[0],'emitted internal nonzero-sequence precondition')
    return dict(sha256=digest(raw),nonzero_sequence_precondition=True,
                precondition_enforced_at_reviewed_receiver=True,standalone_operation_zero_check_claimed=False)


def reconcile(parent,records,wipe):
    worker = parent['records']['RetainedWork'];receiver = parent['records'][entry.RECEIVE]
    for symbol in (QUARANTINE,DROP):
        require(worker['reference_targets'][symbol] == records[symbol]['rva'],'entry reaches this lifecycle body')
    require(receiver['reference_targets'][CANCEL] == records[CANCEL]['rva'] and
            records[CANCEL]['reference_targets'][OPERATION] == records[OPERATION]['rva'],'actual cancel/admission call chain')
    for name,record in records.items():
        require(record['image_sha256'] == parent['image_sha256'] == wipe['image_sha256'],'same lifecycle image')
        frames = record['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == 1224 and frames[0]['chain'] is None and
                not frames[0]['saved_registers'],'complete lifecycle fixed frame')
        require(record['reference_targets'][wiping.WIPE] == wipe['rva'] and
                record['reference_targets'][bounded.CLEAR] == parent['clearing_leaf_rva'] and
                record['reference_targets']['memcpy'] == 28336,'exact shared wipe, clearer and copy targets')
    require(worker['reference_targets'][wiping.WIPE] == wipe['rva'],'entry and lifecycle share workspace wipe')
    require(wipe['reference_targets'][bounded.CLEAR] == parent['clearing_leaf_rva'],'wipe reaches same clearer')


def geometry(window):
    body = bounded.Frame.enter(window,window.high-32,56)
    worker = bounded.Frame.enter(window,body.current,1160)
    receive = bounded.Frame.enter(window,worker.current,104)
    cancel = bounded.Frame.enter(window,receive.current,1224)
    operation = bounded.Frame.enter(window,cancel.current,1224)
    quarantine = bounded.Frame.enter(window,worker.current,1224)
    records = {}
    for name,frame,offset in (('direct quarantine/drop',quarantine,42),('cancel',cancel,40),('cancel operation',operation,34)):
        wipe = bounded.Frame.enter(window,frame.current,40)
        spans = [frame.slot('moved enum copy',offset,1174),
                 frame.slot('ordinary variant workspace',offset+1,1170),
                 frame.slot('general-t variant workspace',offset+4,1170)]
        records[name] = dict(rsp_from_high=frame.current-window.high,spans=spans,
                             clearer_entry=wipe.unknown_callee('volatile clearer entry/home'),
                             memory_runtime_entry=frame.unknown_callee('memcpy entry/home'))
    return dict(paths=records,original_inactive_owner_storage_erased=False,
                complete_moved_enum_individually_erased=False,outer_window_and_page_teardown_required=True,
                other_operation_callers_qualified=False,maximum_transitive_depth_qualified=False)


def inspect(data,native,image,wrapper,ir,mutate=False):
    parent = entry.inspect(data,native,image,wrapper);precondition = ir_precondition(ir)
    records = {};count = 0
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted lifecycle body mutation')
    code,refs = shared.caller.function(data,wiping.WIPE)
    wiping.body_check(wiping.WIPE,code,refs);plan = wiping.wipe_plan(code,refs)
    wipe = shared.caller.bind(data,image,wiping.WIPE)
    require(len(wipe['unwind']) == 1 and wipe['unwind'][0]['stack_bytes'] == 40 and
            wipe['unwind'][0]['chain'] is None,'same complete wipe frame')
    reconcile(parent,records,wipe)
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_STREAM_LIFECYCLE_REVIEW',
                image_sha256=digest(image),object_sha256=digest(data),compiler_precondition=precondition,
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                workspace_wipe=dict(rva=wipe['rva'],bytes=wipe['size'],regions=plan),
                geometry=geometry(bounded.Window(0,65536)),actual_body_byte_mutations_rejected=count,
                whole_image_qualified=False,native_run_added=False,release_gate_changed=False,
                independently_verified=False,arbitrary_exception_cleanup_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[1];require(row['route'] == 'sha2/mod.rs::open','scalar stream route')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes()) == entry.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sha2-scalar-cleanup-image/normal_rust.ll').read_bytes(),args.mutate)
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-stream-lifecycle.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
