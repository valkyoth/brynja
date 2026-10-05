"""Saved bounded rehash caller/commit review; no transitive crypto qualification."""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_input as borrowed

dispatch,shared = borrowed.dispatch,borrowed.shared
require,digest = shared.require,shared.digest
REHASH = '_RNvNtCs7RQXX2qQXJA_22retained_rehash_worker22retained_rehash_worker6rehash'
COMPUTE = '_RNvNtCs7RQXX2qQXJA_22retained_rehash_worker22retained_rehash_worker7compute'
PINS = {
    REHASH:(906,'ce67db242c18f7153660ecf992abe6032f9a4ba274fb64e697435e21a956d13b',
            'c97ff76f4be9197a169d6314e52f5d0c3939f9dbc12d7f1aeb17662b795141a5'),
    COMPUTE:(1378,'33cf26c6b126256ae6a2a5282d540be9cff5ac5694085864291f8b77b3adfc7a',
             'bfe8c3a53120cf1bda2b3695452599929876b075eff52b0ef5614b7ac7e2bcb3'),
}
LANDMARKS = {
    REHASH:(
        (0,'41574156415541545657534881ec90090000'),
        (0x1c7,'4829da410f93c04881fa000001000f94c24420c280fa01'),
        (0x21d,'48c706be00000048c7460800000000'),
        (0x22c,'488d8c24ee040000e800000000'),
        (0x241,'4881c4900900005b5f5e415c415d415e415fc3'),
        (0x2b0,'4889442420488d4c24304c8d8424ee0400004c8d8c24900000004889fae800000000'),
        (0x2f5,'4981ffbf0000000f95c0'),
        (0x321,'488d8c24e8000000e80000000083f801'),
        (0x333,'48b800000000010000004909c7'),
        (0x37a,'c647200348c706bf000000'),
    ),
    COMPUTE:(
        (0,'4157415641554154565755534883ec78'),
        (0x6b,'ba200000004889f9e800000000ba200000004889d9e800000000'),
        (0x85,'410fb6452040b50183f802'),(0xb6,'41c6452001'),
        (0xdf,'f30f6f442420f3410f6f0f660f74c8f3410f6f4710f30f6f542430660f74d0660fdbd1660fd7c2'),
        (0x106,'41bf670000003dffff0000'),(0x140,'49ffc4'),
        (0x165,'41b8200000004c89f14c89fae80000000084c0'),
        (0x18c,'488d4c24204c89f241b0014989f9e800000000807c242001'),
        (0x1c0,'41c645200341bf68000000'),
        (0x1cb,'ba200000004889d9e800000000ba200000004889f9e800000000'),
        (0x208,'483d93040000'),(0x46e,'41bfbf000000807f2004'),
        (0x491,'4883c4785b5d5f5e415c415d415e415fc3'),
        (0x4ac,'4885c94889d0480f44c14883f820'),
        (0x4c8,'0f10000f1048100f114b100f1103'),
        (0x4e5,'498b4500f30f6f03f30f6f4b10f30f7f4810f30f7f004d89651841c6452002'),
        (0x511,'41bf6a000000'),(0x51c,'b9200000004889c2e8000000000f0b'),
        (0x54a,'48c7462801000000b80100000041bf08000000'),
    ),
}
BRANCHES = {
    REHASH:((0x1de,'75',0x1ff),(0x26e,'75',0x1ff),(0x28d,'0f85',0x1ff),
            (0x2aa,'0f85',0x1ff),(0x331,'75',0x360),(0x35b,'e9',0x22c),(0x385,'e9',0x224)),
    COMPUTE:((0x90,'74',0xb6),(0x95,'74',0xab),(0x9a,'0f85',0x12b),
             (0x111,'74',0x136),(0x143,'0f84',0x511),(0x178,'74',0x18c),
             (0x1a4,'0f85',0x4a2),(0x225,'74',0x1f0),(0x454,'0f84',0x52b),
             (0x4ba,'75',0x51c),(0x50c,'e9',0x1cb),(0x517,'e9',0x113),
             (0x52e,'0f85',0x47e),(0x55d,'e9',0x480)),
}


def body_check(name,code,refs):
    size,body_hash,refs_hash = PINS[name]
    require(len(code) == size and digest(code) == body_hash,'complete rehash body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete rehash relocations')


def instructions(name,code):
    for offset,hexcode in LANDMARKS[name]:
        raw = bytes.fromhex(hexcode)
        require(code[offset:offset+len(raw)] == raw,'rehash instruction landmark')
    for offset,hexcode,target in BRANCHES[name]:
        opcode = bytes.fromhex(hexcode)
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,
                'rehash branch destination')


def reconcile(parent,records,hashed):
    worker = parent['dispatcher']
    rehash,compute = records[REHASH],records[COMPUTE]
    require(worker['reference_targets'].get(REHASH) == rehash['rva'],'dispatcher calls this rehash')
    require(rehash['reference_targets'].get(COMPUTE) == compute['rva'],'rehash calls this compute')
    require(hashed['image_sha256'] == worker['image_sha256'],'borrowed hash in same image')
    require(borrowed.WIPE in hashed['reference_targets'],'known borrowed workspace wipe')
    for name,size in ((REHASH,2504),(COMPUTE,184)):
        record = records[name]
        require(record['image_sha256'] == worker['image_sha256'],'same saved image')
        for symbol in (borrowed.LIVE,dispatch.CLEAR):
            require(record['reference_targets'].get(symbol) == worker['reference_targets'][symbol],
                    'same owner and volatile clearer')
        require(record['reference_targets'].get(borrowed.WIPE) == hashed['reference_targets'][borrowed.WIPE],
                'same wipe as borrowed input (semantics separately reviewed)')
        frames = record['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == size and frames[0]['chain'] is None,
                'complete reviewed fixed frame')


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    rehash = dispatch.Frame.enter(window,worker.current,2504)
    compute = dispatch.Frame.enter(window,rehash.current,184)
    spans = [rehash.slot('rehash saved GPRs',-56,56,'entry'),rehash.slot('rehash saved XMM6',2432,16),
             rehash.slot('compute result',48,48),rehash.slot('candidate digest',144,32),
             rehash.slot('compiler token copy',176,16),rehash.slot('staging digest',192,32),
             rehash.slot('observation report',232,64),rehash.slot('workspace',1262,1170),
             rehash.slot('upper window argument',2544,8),
             compute.slot('compute saved GPRs',-64,64,'entry'),compute.slot('compute saved XMM6/7',80,32),
             compute.slot('token comparison/finalize return',32,32),compute.slot('identity copy',64,16),
             compute.slot('staging pointer argument',224,8)]
    return dict(rehash_rsp_from_high=rehash.current-window.high,compute_rsp_from_high=compute.current-window.high,
                spans=spans,unknown_callees=[rehash.unknown_callee('rehash helper entry/home'),
                                           compute.unknown_callee('compute helper entry/home')],
                maximum_transitive_depth_qualified=False,individual_stack_copies_erased=False)


def inspect(data,native,image,wrapper,mutate=False):
    parent = dispatch.inspect(data,native,image,wrapper)
    # Reuse the previous input body's identity check, not an unverified address.
    code,refs = shared.caller.function(data,borrowed.HASH)
    borrowed.body_check(borrowed.HASH,code,refs)
    hashed = shared.caller.bind(data,image,borrowed.HASH)
    records,count = {},0
    for name in PINS:
        code,refs = shared.caller.function(data,name)
        body_check(name,code,refs);instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for index in range(len(code)):
                changed = bytearray(code);changed[index] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted rehash byte mutation')
    reconcile(parent,records,hashed)
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_REHASH_CALLER_REVIEW',records=records,
                geometry=geometry(dispatch.Window(0,65536)),object_sha256=dispatch.OBJECT,
                archive_sha256=dispatch.ARCHIVE,archive_member=dispatch.MEMBER,
                actual_body_byte_mutations_rejected=count,
                update_finalize_wipe_callees_qualified=False,observer_callee_qualified=False,
                length_mismatch_abort_covered_by_normal_cleanup=False,whole_image_qualified=False,
                native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('object',type=Path)
    parser.add_argument('--catalog',type=Path,default=shared.CATALOG)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    row = shared.catalog(args.catalog.read_bytes())[0]
    require(row['route'] == 'mod.rs::open','bounded route')
    base = args.saved_directory
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image')
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == dispatch.ARCHIVE,'saved archive')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    result = inspect(args.object.read_bytes(),native,image,wrapper,args.mutate)
    sources = ('windows_enclave_bounded_rehash.py','test-windows-enclave-bounded-rehash.py',
               'windows_enclave_bounded_input.py','windows_enclave_bounded_dispatch.py',
               'windows_enclave_sequential_c.py','windows_enclave_caller_binding.py',
               'windows_enclave_caller_object.py','windows_enclave_caller_handlers.py',
               'windows_enclave_leaf_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
