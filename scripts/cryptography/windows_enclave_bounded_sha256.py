"""Offline saved bounded SHA-256 operations, transfer and scalar cleanup review."""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_owner as owner

rehash,dispatch,shared = owner.rehash,owner.dispatch,owner.shared
require,digest = shared.require,shared.digest
UPDATE = '_RNvMNtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened7state32NtNtB4_5owner17HardenedSha2Owner8update32'
FINAL = '_RNvMs5_NtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened8in_placeNtB5_6Sha25615finalize_secret'
SCALAR = '_RNvNtNtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened10compress326native6scalar'
COPY = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory18copy_secret_region'
BYTES = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_transfer10copy_bytes'
TABLE = 'anon.a99b5b83196533d8746ce7cb64084aff.7'
TABLE_HASH = '74ef7306e7452d6859b6463ce496b8df30925f69e1b2969e1f3f34bbc9c6af04'
PINS = {
    UPDATE:(525,'7149d88a8fda17aef3ee6cd3e30d989fd2529c6458667b900c7bc07ad65b26f6',
            '6bc08a228e2bd4d5f041b8e42624f30a6622ddfdcf84734c9d45bd0df1461ace'),
    FINAL:(691,'28bcd7ab5fa47aa35b65c3d89c3f2b971a9cdd0d199cfa9d3be6f92f0d5863ff',
           '159374a72143319b9c11e01d135e10098586f8d20f95440e0b090c9f41045e98'),
    SCALAR:(482,'e2061a0517a45fa59dcef9be254468bb469fa1af42aa92f55b1ba7e33f346f45',
            '1ca3798bb322b9d7be66d46e08618db268c4d84a6afe796727339034f41ef5eb'),
    COPY:(32,'ee504003eb72cad384615984c9faaa1519dbdf48366caa6cfe97e77f04cd3af4',
          'beba63d9636b36f7b326a895e4ec820dd8f9602cf751cb8afd9eac90eafc8e3f'),
    BYTES:(68,'820c2a4fdf11073053919c00ab6524a905846dd6347f14a23b9371c1b0fda7e4',
           '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
}
LANDMARKS = {
    UPDATE:((0,'4157415641554154565755534883ec38'),
            (0x16,'488b8180040000480fc84a8d2c004839c50f92c14889e848c1e83d0f95c2b00108ca'),
            (0x4d,'4531f6ba400000004829ca4c0f43f24c39f34c0f42f3498d3c0e4881ff80000000'),
            (0x99,'48b8c0ffffffffffff7f4821d84889442430'),
            (0xad,'4c8db6000300004c8dbe800000004c8da600040000'),
            (0xe0,'ba4000000041b9400000004c89f14d89e8e8000000003cff'),
            (0x10c,'ba800200004c89f9e800000000ba800000004c89f1e8000000004883c740'),
            (0x12c,'83e33f4c8b4424284c034424304889f14889da4989d9e8000000003cffb001'),
            (0x1b2,'ba800200004c89f1e800000000ba800000004c89f9e800000000ba800000004889f1e800000000c6869104000000'),
            (0x1e5,'48c7868804000000000000480fcd4889ae8004000031c04883c4385b5d5f5e415c415d415e415fc3')),
    FINAL:((0,'4157415641554154565755534883ec28'),
           (0x1c,'ba200000004c89c9e8000000004084ed'),
           (0x32,'4c8bae80040000490fcd4c89e848c1e83d'),
           (0x49,'49c1e503440fb6be910400004c8db680030000490fcdc68690040000014981ff80000000'),
           (0x85,'43c6043e804180ff38'),
           (0xc6,'ba800200004c89e1e800000000ba800000004c89f9e800000000'),
           (0xe0,'0f57c0410f114620410f114610410f110649c74630000000004c89aeb8030000'),
           (0x139,'ba800200004c89f1e800000000ba800000004c89f9e800000000'),
           (0x242,'0f57c00f1186600400000f118670040000ba800000004889f1e800000000'),
           (0x260,'41b8200000004889f94c89f2e80000000048897b0848c7431020000000c60300'),
           (0x282,'31c0884301c60301ba200000004889f9e800000000'),
           (0x297,'4889f14883c4285b5d5f5e415c415d415e415fe900000000'),(0x2af,'b001')),
    COPY:((0,'4883ec28b0024c39ca75104989d24c89c24d89d0e800000000b0ff4883c428c3'),),
    BYTES:((0,'4989d14989ca31c94c89c24883fa087216498b04094989040a4883c1084883ea084883fa0873ea'
              '4885d27411410fb604094188040a48ffc148ffca75ef31c031c931d2c3'),),
    SCALAR:((0,'56574d89c14989d34889ce488d3d00000000'),
            (446,'43c70411000000004183c2044181fa8002000075eb31c031c931d24531c04531d25f5ec3')),
}
BRANCHES = {
    UPDATE:((0x38,'0f85',0x1fc),(0x4b,'74',0x94),(0x6e,'0f87',0x1fc),
            (0x87,'0f84',0x15c),(0x8f,'e9',0x1fc),(0xab,'74',0x12c),
            (0xf8,'75',0x8d),(0x12a,'75',0xe0),(0x14b,'0f85',0x1fc),
            (0x157,'e9',0x1e5),(0x167,'75',0x1e5),(0x188,'0f85',0x8d),(0x1e0,'e9',0x99)),
    FINAL:((0x2c,'0f84',0x282),(0x43,'0f85',0x2af),(0x6d,'77',0x90),
           (0x83,'78',0x90),(0x8e,'72',0xf9),(0x280,'eb',0x297),(0x2b1,'eb',0x284)),
}
EDGES = {UPDATE:{COPY,SCALAR,dispatch.CLEAR},FINAL:{COPY,BYTES,SCALAR,dispatch.CLEAR,owner.WIPE},
         COPY:{BYTES},BYTES:set(),SCALAR:{TABLE}}


def body_check(name,code,refs):
    size,body_hash,refs_hash = PINS[name]
    require(len(code) == size and digest(code) == body_hash,'complete SHA-256 operation body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete SHA-256 operation references')


def instructions(name,code):
    for offset,hexcode in LANDMARKS[name]:
        raw = bytes.fromhex(hexcode)
        require(code[offset:offset+len(raw)] == raw,'operation instruction landmark')
    for offset,hexcode,target in BRANCHES.get(name,()):
        opcode = bytes.fromhex(hexcode)
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,
                'operation branch destination')
    if name == FINAL: render_plan(code)


def render_plan(code):
    def word(n): return n.to_bytes(4,'little')
    first = bytes.fromhex('4c8db640040000ba0400000041b9040000004c89f14d89e0e800000000')
    require(code[0x153:0x170] == first,'first four-byte rendered word')
    for index in range(1,8):
        offset = 0x170+(index-1)*30
        expected = (bytes.fromhex('4c8d86')+word(1024+index*4)+bytes.fromhex('488d8e')+
                    word(1088+index*4)+bytes.fromhex('ba0400000041b904000000e800000000'))
        require(code[offset:offset+30] == expected,'remaining seven rendered words')
    return [dict(source=1024+4*i,destination=1088+4*i,bytes=4) for i in range(8)]


def table_bytes(raw):
    require(len(raw) == 256 and digest(raw) == TABLE_HASH,'complete scalar round constants')


def constants(data,image,record):
    rows,symbols = dispatch.obj.tables(data)
    found = [s for s in symbols.values() if s['name'] == TABLE]
    require(len(found) == 1 and found[0]['value'] == 0 and 1 <= found[0]['section'] <= len(rows),
            'unique round table at section start')
    row = rows[found[0]['section']-1]
    require(row['flags'] & 0xe0000000 == 0x40000000 and row['nrelocs'] == 0,'readonly relocation-free constants')
    table_bytes(row['code'])
    linked,_ = shared.caller.pe.linked(image)
    address = record['reference_targets'][TABLE]
    candidates = [r for r in linked if r['rva'] <= address and
                  address+256 <= r['rva']+min(r['virtual_size'],len(r['code']))]
    require(len(candidates) == 1 and candidates[0]['flags'] & 0xe0000000 == 0x40000000,'readonly mapped constants')
    raw = dispatch.mapping.mapped(linked,address,256)
    table_bytes(raw)
    require(raw == row['code'],'linked constants equal object constants')
    return dict(rva=address,bytes=256,sha256=TABLE_HASH)


def reconcile(records,anchors,wipe,clear,table):
    require(set(records) == set(PINS) and set(anchors) == {owner.PLACED,rehash.COMPUTE},'exact local call inventory')
    targets = {n:r['rva'] for n,r in records.items()} | {owner.WIPE:wipe['rva'],dispatch.CLEAR:clear['rva'],TABLE:table['rva']}
    for record in (*records.values(),*anchors.values(),wipe):
        require(record['image_sha256'] == clear['image_sha256'],'same saved image')
    for name,record in records.items():
        require(set(record['reference_targets']) == EDGES[name],'no unreviewed operation callee or data reference')
        for edge in EDGES[name]:
            require(record['reference_targets'][edge] == targets[edge],'exact operation destination')
    for record in anchors.values():
        for edge in (UPDATE,FINAL,owner.WIPE,dispatch.CLEAR):
            require(record['reference_targets'].get(edge) == targets[edge],'placement/rehash operation identity')
    for name,size in ((UPDATE,120),(FINAL,104),(COPY,40),(SCALAR,16)):
        frames = records[name]['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == size and frames[0]['chain'] is None,
                'whole operation fixed frame')


def geometry(window):
    # Placement is deeper than the previously bound rehash compute (H-3168).
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    hashed = dispatch.Frame.enter(window,worker.current,2584)
    receive = dispatch.Frame.enter(window,hashed.current,296)
    placed = dispatch.Frame.enter(window,receive.current,120)
    update = dispatch.Frame.enter(window,placed.current,120)
    final = dispatch.Frame.enter(window,placed.current,104)
    copy = dispatch.Frame.enter(window,update.current,40)
    # Copy/scalar are call-free. Do not invent aligned allocations for leafs.
    spans = [update.slot('update saved GPRs',-64,64,'entry'),update.slot('input pointer and complete-byte count',40,16),
             final.slot('finalize saved GPRs',-64,64,'entry'),
             window.span('scalar saved pointers, return and caller home',update.current-24,56),
             window.span('copy leaf return and caller home',copy.current-8,40)]
    return dict(update_rsp_from_high=update.current-window.high,finalize_rsp_from_high=final.current-window.high,
                copy_rsp_from_high=copy.current-window.high,scalar_rsp_from_high=update.current-24-window.high,
                deepest_operation_rsp_from_high=copy.current-8-window.high,spans=spans,
                finalize_wipe_tail_reuses_entry=True,operation_chain_depth_reviewed=True,
                maximum_whole_image_depth_qualified=False,individual_caller_stack_copies_erased=False)


def inspect(data,native,image,wrapper,mutate=False):
    parent = owner.inspect(data,native,image,wrapper)
    records,anchors,count = {},{},0
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);instructions(name,code)
        if name != BYTES: records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for index in range(len(code)):
                changed = bytearray(code);changed[index] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual operation body mutation')
    records[BYTES] = dispatch.leaf.bind(data,image,BYTES,list(records.values()))
    anchors[owner.PLACED] = parent['records'][owner.PLACED]
    code,refs = shared.caller.function(data,rehash.COMPUTE);rehash.body_check(rehash.COMPUTE,code,refs)
    anchors[rehash.COMPUTE] = shared.caller.bind(data,image,rehash.COMPUTE)
    wipe = parent['records'][owner.WIPE]
    clear = dispatch.leaf.bind(data,image,dispatch.CLEAR,[wipe,*records.values()])
    table = constants(data,image,records[SCALAR])
    reconcile(records,anchors,wipe,clear,table)
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_SHA256_OPERATION_REVIEW',records=records,
                scalar_constants=table,geometry=geometry(dispatch.Window(0,65536)),
                object_sha256=dispatch.OBJECT,archive_sha256=dispatch.ARCHIVE,archive_member=dispatch.MEMBER,
                actual_body_byte_mutations_rejected=count,valid_initialized_owner_required=True,
                normal_operation_chain_reviewed=True,whole_image_qualified=False,
                independent_cryptographic_review=False,native_run_added=False,release_gate_changed=False)


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
    sources = ('windows_enclave_bounded_sha256.py','test-windows-enclave-bounded-sha256.py',
               'windows_enclave_bounded_owner.py','windows_enclave_bounded_rehash.py','windows_enclave_bounded_input.py',
               'windows_enclave_bounded_dispatch.py','windows_enclave_sequential_c.py',
               'windows_enclave_caller_binding.py','windows_enclave_caller_object.py',
               'windows_enclave_caller_handlers.py','windows_enclave_leaf_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
