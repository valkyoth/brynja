"""Saved SHA-NI state construction/consumption and copy helpers, not all engines."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha_ni_lifecycle as life
import windows_enclave_sha_ni_receiver as receiver
import windows_enclave_sha_ni_state_shapes as shapes
import windows_enclave_session_runtime as runtime

shared,obj = life.shared,life.workers.obj
require,digest = life.require,life.digest
NEW,FINISH = shapes.NEW,shapes.FINISH
BEGIN,REHASH,OWNER_FINISH = (life.PREFIX+s for s in ('5begin','6rehash','6finish'))
COPY = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory18copy_secret_region'
BYTES = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_transfer10copy_bytes'
ENGINE = '_RNvMNtNtCskNJ9UBpP4M4_16brynja_hash_sha218hardened_execution6engineNtB2_6Engine6finish'
KAT = '_RNvMs_NtCshYLbG8W7MpL_17brynja_crypto_cpu18hardened_executionNtB4_7Session12known_answer'
IVS = ('__ymm@19cde05babd9831f8c68059b7f520e513af54fa572f36e3c85ae67bb67e6096a',
       '__ymm@a44ffabea78ff96411155868310bc0ff39590ef717dd703007d57c36d89e05c1')
PINS = shapes.PINS | {
    COPY:(32,'ee504003eb72cad384615984c9faaa1519dbdf48366caa6cfe97e77f04cd3af4',
          'beba63d9636b36f7b326a895e4ec820dd8f9602cf751cb8afd9eac90eafc8e3f'),
    BYTES:(68,'820c2a4fdf11073053919c00ab6524a905846dd6347f14a23b9371c1b0fda7e4',
           '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945')}
# Main runtime extents, not whole sections containing additional funclets.
ANCHORS = {
    BEGIN:(517,'97714c921f4c30dc94dbefe3eb69510fdeb928f059952707f2922b733b11988b',
           'd139f8d333ac16a6d355cf15426c742c93a5e704300587b0254e412613f69e86',4056,
           '415741565657534881ecb00f0000'),
    REHASH:(1019,'e1e696ffb77dfc7e17f9111243dbc7014cd5310fc7a8cf7143d1d0b5a59ffbff',
            'e25dfff0742f02b0fdae508bc1d13f6456e7e8ae1655d23ab5f97a8dd59b554d',4200,
            '554157415641554154565753b828100000e8000000004829c4488dac2480000000'),
    OWNER_FINISH:(704,'59a4d4e46e2ba6737d26326b92210a3838e435fc202428bed5bf73dd68c84eca',
                  '311fa22468a3c1ecb45c5b34e410a73d6d1875ea48bcff0679cd29ef027b1dd2',2152,
                  '554157415641545657534881ec30080000488dac2480000000')}


def body_check(name,code,refs):
    size,ch,rh = PINS[name]
    require(len(code) == size and digest(code) == ch,'complete SHA-NI state/helper body')
    require(digest(shared.encoded(refs)) == rh,'complete SHA-NI state/helper references')


def instructions(name,code):
    if name in shapes.LANDMARKS:
        for at,h in shapes.LANDMARKS[name]:
            raw = bytes.fromhex(h);require(code[at:at+len(raw)] == raw,'state admission/copy/wipe instruction')
        if name == NEW:
            for a,b,n in shapes.REPEATS:
                require(len(code[a:a+n]) == n and code[a:a+n] == code[b:b+n],'both variants initialize/publish identically')
    elif name == COPY:
        require(code == bytes.fromhex('4883ec28b0024c39ca75104989d24c89c24d89d0e800000000b0ff4883c428c3'),
                'equal-length copy adapter')
    elif name == BYTES:
        # The complete no-stack copy loop and its RAX/RCX/RDX erase are pinned.
        require(len(code) == 68 and code[-7:] == bytes.fromhex('31c031c931d2c3'), 'copy payload registers erased')


def preconditions(raw):
    require(digest(raw) == receiver.IR_HASH,'same saved compiler IR')
    checks = {NEW:('define internal fastcc void ','range(i16 0, 7)','dereferenceable(2000)'),
              FINISH:('define internal fastcc ','range(i64 0, 33)','dereferenceable(2000)')}
    for name,tokens in checks.items():
        lines = [s for s in raw.decode().splitlines() if s.startswith('define ') and '@'+name+'(' in s]
        require(len(lines) == 1 and all(t in lines[0] for t in tokens),'private state parameter preconditions')
    return dict(sha256=digest(raw),constructor_tag_range=[0,7],output_length_range=[0,33],
                half_open=True,standalone_unbounded_call_claimed=False)


def constants(data,image,record):
    rows,symbols = obj.tables(data);linked,_ = shared.caller.pe.linked(image);out = {}
    for name in IVS:
        found = [s for s in symbols.values() if s['name'] == name]
        require(len(found) == 1 and found[0]['value'] == 0 and 1 <= found[0]['section'] <= len(rows),'unique IV storage')
        row = rows[found[0]['section']-1];raw = int(name[6:],16).to_bytes(32,'little')
        require(row['flags'] & 0xe0000000 == 0x40000000 and row['nrelocs'] == 0 and row['code'] == raw,
                'exact readonly relocation-free IV')
        out[name] = life.constants.constant(linked,record['reference_targets'][name],raw)
    return out


def reconcile(records,anchors,parent,clear_rva,copy_rva,fill_rva):
    require(set(records) == set(PINS) and set(anchors) == set(ANCHORS),'complete state/caller population')
    for caller,callee in ((BEGIN,NEW),(REHASH,NEW),(OWNER_FINISH,FINISH),(REHASH,FINISH)):
        require(anchors[caller]['reference_targets'].get(callee) == records[callee]['rva'],'actual state caller edge')
    expected = {n:r['rva'] for n,r in records.items()} | {
                life.wiping.WIPE:parent['records'][life.QUARANTINE]['reference_targets'][life.wiping.WIPE],
                life.SCRATCH:parent['records'][life.SCRATCH]['rva'],life.bounded.CLEAR:clear_rva,
                'memcpy':copy_rva,'memset':fill_rva}
    for record in (*records.values(),*anchors.values()):
        require(record['image_sha256'] == parent['image_sha256'],'same selected image')
        for name,target in record['reference_targets'].items():
            if name in expected: require(target == expected[name],'same state cleanup/copy target')
    for name,size in ((NEW,7800),(FINISH,2104),(COPY,40)):
        frames = records[name]['unwind'];saved = [dict(register_class='xmm',register=6,offset=7728)] if name == NEW else []
        require(len(frames) == 1 and frames[0]['stack_bytes'] == size and frames[0]['saved_registers'] == saved and
                frames[0]['chain'] is None,'complete local state frame')
    for name,callees in ((NEW,(life.SCRATCH,life.wiping.WIPE,'memcpy','memset')),
                         (FINISH,(life.SCRATCH,life.wiping.WIPE,life.bounded.CLEAR,COPY,BYTES)),(COPY,(BYTES,))):
        for callee in callees: require(records[name]['reference_targets'].get(callee) == expected[callee],'required cleanup edge')


def geometry(window):
    body = life.Frame.enter(window,window.high-32,56)
    worker = life.Frame.enter(window,body.current,1208)
    receive = life.Frame.enter(window,worker.current,168)
    result = {}
    for caller,callee in ((BEGIN,NEW),(REHASH,NEW),(OWNER_FINISH,FINISH),(REHASH,FINISH)):
        owner = life.Frame.enter(window,receive.current,ANCHORS[caller][3])
        frame = life.Frame.enter(window,owner.current,7800 if callee == NEW else 2104)
        slots = ((192,720),(1376,736),(2112,736),(2850,1024),(192,1170),(3874,750),
                 (4624,1170),(5808,750),(6558,1170),(7728,16)) if callee == NEW else (
                     (32,32),(64,1984),(864,1170),(144,704),(1952,32))
        result[caller+' -> '+callee] = dict(rsp_from_high=frame.current-window.high,
            spans=[frame.slot('state/session/staging copy or saved register',at,n) for at,n in slots],
            unqualified_callee=frame.unknown_callee('KAT/engine/copy entry and home'))
    return dict(paths=result,maximum_transitive_depth_qualified=False,
                constructor_saved_xmm6_individually_erased=False,all_moved_copies_individually_erased=False,
                outer_window_cleanup_required=True)


def inspect(base,mutate=False):
    parent = life.inspect(base,life.specification(life.SPEC.read_bytes()))
    row = shared.catalog(shared.CATALOG.read_bytes())[2];profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][1]
    directory = base/Path(row['object']).parent
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();ir = preconditions((directory/'normal_rust.ll').read_bytes())
    require(digest(data) == parent['object_sha256'] and digest(image) == parent['image_sha256'],'same reviewed inputs')
    anchors = {};records = {};count = 0
    receiver_record = shared.caller.bind(data,image,life.RECEIVE)
    for name,(size,ch,rh,_,prolog) in ANCHORS.items():
        _,_,_,code,refs = obj.select(data,name)
        require(len(code) == size and digest(code) == ch and digest(shared.encoded(refs)) == rh,'complete owner caller extent')
        require(code.startswith(bytes.fromhex(prolog)),'actual owner fixed prologue')
        anchors[name] = life.memory.handlers.bind(data,image,name,[receiver_record])
        require(receiver_record['reference_targets'].get(name) == anchors[name]['rva'],'receiver reaches this state caller')
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);instructions(name,code)
        if name != BYTES: records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: body_check(name,bad,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted state/helper byte mutant')
    records[BYTES] = life.bounded.leaf.bind(data,image,BYTES,list(records.values()))
    memory = life.memory.inspect(data,image,47)['runtime_targets']
    reconcile(records,anchors,parent,parent['records'][life.QUARANTINE]['reference_targets'][life.bounded.CLEAR],
              memory['memcpy'],memory['memset'])
    values = constants(data,image,records[NEW])
    linked,_ = shared.caller.pe.linked(image)
    address = records[NEW]['reference_targets']['__chkstk']
    raw = runtime.executable(linked,address,78)
    require(digest(raw) == runtime.BODIES['__chkstk'][2],'exact previously reviewed stack probe')
    require(anchors[REHASH]['reference_targets']['__chkstk'] == address,'same constructor/rehash stack probe')
    return dict(schema=1,status='SAVED_SHA_NI_STATE_CALLER_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                constants=values,preconditions=ir,geometry=geometry(life.Window(0,65536)),
                stack_probe=dict(rva=address,bytes=78,sha256=digest(raw),execution_context_qualified=False),
                actual_body_byte_mutations_rejected=count,engine_and_kat_semantics_qualified=False,
                whole_owner_operation_semantics_qualified=False,handler_semantics_qualified=False,
                whole_image_qualified=False,independently_verified=False,native_run_added=False,release_gate_changed=False)


def report(base,mutate=False):
    result = inspect(base,mutate)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha-ni-state.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(report(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
