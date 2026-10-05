"""Saved SHA-NI admission, cancellation and resident teardown; not all callees."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_worker_boundaries as workers
import windows_enclave_worker_memory as memory
import windows_enclave_bounded_owner as wiping
import windows_enclave_construction_review as constants
from windows_enclave_frame_geometry import Frame, Window

shared = workers.shared
bounded = wiping.dispatch
require, digest = shared.require, shared.digest
PREFIX = '_RNvMs_Cs11e1ovcwz1T_16sha2_acceleratedNtB4_5Owner'
QUARANTINE, OPERATION, CLEAR_OWNER, CANCEL = (PREFIX+s for s in ('10quarantine','9operation','5clear','6cancel'))
GUARD = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCs11e1ovcwz1T_16sha2_accelerated9OperationEBD_'
GUARD_ALIAS = '_RNvXCs11e1ovcwz1T_16sha2_acceleratedNtB2_9OperationNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
NEW = '_RNvMs_Cs6XEeBPE9QTS_25sha2_accelerated_residentNtB4_8Resident3new'
DROP = '_RNvXs0_Cs6XEeBPE9QTS_25sha2_accelerated_residentNtB5_8ResidentNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
SCRATCH = '_RNvMNtNtCshYLbG8W7MpL_17brynja_crypto_cpu18hardened_execution7scratchNtB2_7Scratch4wipe'
CHECK = '_RNvCs11e1ovcwz1T_16sha2_accelerated15check_authority'
RECEIVE = '_RNvCs4RPH1Q6pgLN_23sha2_accelerated_worker7receive'
NONE = '__xmm@00000000000000000000000000000002'
SPEC = shared.CATALOG.with_name('sha-ni-lifecycle-20261005.json')
SPEC_HASH = '46c4e258aaf812425f6763901a5b3a8f84beb091844f0c73d76ee3f7121f5943'
NAMES = (QUARANTINE, OPERATION, CLEAR_OWNER, CANCEL, GUARD, NEW, DROP, SCRATCH)

# Every common path copies 2000 bytes to RSP+32, takes the source enum, tests
# the exact None sentinel, conditionally drops its typed owners, clears output
# and invalidates the algorithm. This does NOT erase the whole enum copy.
TAKE = ('488d4c242041b8d00700004889f2e800000000'
        '48c746080000000048c70602000000c5f96f442420c5f9ef0500000000'
        'c4e27917c07422488d8c2450030000e80000000048837c247000740d'
        '488d8c2480000000e800000000488d8ed0070000ba20000000e800000000'
        '66c78600080000ffff')
REVOKE = '488b86f007000080780802740bc640080248c70003000000c6860408000003'
TAKES = {QUARANTINE:(11,), CLEAR_OWNER:(11,), OPERATION:(41,223,426),
         CANCEL:(64,222), GUARD:(20,)}
REVOKES = {QUARANTINE:(126,), OPERATION:(156,338,541), CANCEL:(179,), GUARD:(135,)}
LANDMARKS = {
    QUARANTINE:((0,'564881ecf00700004889ce'),(157,'4881c4f00700005ec3')),
    CLEAR_OWNER:((0,'564881ecf00700004889ce'),(126,'4881c4f00700005ec3')),
    GUARD:((0,'564881ecf0070000f6c201'),(17,'4889ce'),(166,'4881c4f00700005ec3')),
    OPERATION:((0,'56574881ecf80700004889d64889cf0fb682040800004438c80f94c13c030f95c084c1'),
               (187,'c60702c6470802'),(199,'4d85c0'),
               (204,'488b86f807000048ffc04c39c0'),(369,'c60701c6470802'),
               (381,'488b86f007000080780900'),(394,'80780801'),
               (400,'4c8986f8070000488937c6470800'),(419,'c60706c6470802'),
               (572,'4881c4f80700005f5ec3')),
    CANCEL:((0,'564881ecf00700004889ce440fb68904080000418d41ff3c02'),
            (27,'4989d0488d4c24204889f2e800000000807c242802'),
            (54,'0fb6442420'),(210,'b002'),(217,'488b742420'),
            (337,'c6860408000000b0ff4881c4f00700005ec3')),
    NEW:((0,'41565657534881ece80f00004889d74889cee800000000b10228c148c70702000000884f08c647090084c0'),
         (49,'4c8d7710c5f857c0c5fc118424e9070000488d9c2409080000488d54242a41b8df0700004889d9c5f877e800000000'),
         (96,'48c747180000000048c7471002000000c6472006488d4f2141b8df0700004889dae800000000'),
         (134,'4889bf0008000048c787080800000000000066c78710080000ffffc687140800000048893e48897e084c897610'),
         (181,'31c0'),(243,'c646080648c706000000004881c4e80f00005b5f5e415ec3')),
    DROP:((0,'56574881ecf80700004889d74889ce'),
          (15,'488d4c242041b8d0070000e80000000048c747080000000048c70702000000'
              'c5f96f442420c5f9ef0500000000c4e27917c07422488d8c2450030000e800000000'
              '48837c247000740d488d8c2480000000e800000000488d8fd0070000ba20000000e80000000066c78700080000ffff'),
          (127,'c5f96f07c5f9ef0500000000c4e27917c0741f488d8f30030000e80000000048837f5000740c4883c7604889f9e80000000031c0'),
          (243,'4881c4f80700005f5ec3')),
    SCRATCH:((0,'564883ec204889ceba80020000e8000000004881c680020000ba400000004889f14883c4205ee900000000'),),
}
BRANCHES = {GUARD:((11,'0f85',166),),
            OPERATION:((35,'0f85',199),(194,'e9',572),(202,'74',223),(217,'0f84',381),
                       (376,'e9',572),(392,'75',419),(398,'75',419),(414,'e9',572)),
            CANCEL:((25,'73',64),(48,'0f85',217),(59,'e9',346),(212,'e9',346)),
            NEW:((43,'0f84',181),(179,'eb',254))}


def specification(raw):
    require(digest(raw) == SPEC_HASH, 'SHA-NI lifecycle review identity')
    result = json.loads(raw)
    require(result['schema'] == 1 and result['route'] == 'sha2/mod.rs::open_sha_ni' and
            set(result['functions']) == set(NAMES), 'complete reviewed body set')
    return result['functions']


def page_loop(register):
    require(register in ('rsi','rdi'), 'reviewed page base')
    reg = '06' if register == 'rsi' else '07'
    return bytes.fromhex('c604'+reg+'00'+''.join('c644'+reg+f'{i:02x}00' for i in range(1,8))+
                         '4883c008483d0010000075cd')


def segments(name):
    result = [(at,bytes.fromhex(raw)) for at,raw in LANDMARKS[name]]
    result += [(at,bytes.fromhex(TAKE)) for at in TAKES.get(name,())]
    result += [(at,bytes.fromhex(REVOKE)) for at in REVOKES.get(name,())]
    if name in (NEW,DROP): result.append((192,page_loop('rdi' if name == NEW else 'rsi')))
    for at,raw,target in BRANCHES.get(name,()):
        op = bytes.fromhex(raw); width = 4 if len(op) == 2 or op == b'\xe9' else 1
        result.append((at,op+(target-at-len(op)-width).to_bytes(width,'little',signed=True)))
    return result


def instructions(name,code):
    for at,raw in segments(name):
        require(code[at:at+len(raw)] == raw, 'SHA-NI lifetime instruction/branch')


def sequence_model(stored,requested):
    require(all(type(v) is int and 0 <= v < 1<<64 for v in (stored,requested)), 'u64 sequence')
    return requested != 0 and ((stored+1) & ((1<<64)-1)) == requested


def erased_regions(active,has_scratch):
    """Relative to the moved enum, not the original owner or whole page."""
    require(type(active) is bool and type(has_scratch) is bool, 'explicit state classification')
    return ([(816,1170)] if active else []) + ([(96,704)] if active and has_scratch else [])


def reconcile(records,anchors,wipe,clear,copy_rva,pins):
    require(set(records) == set(NAMES), 'all lifecycle bodies')
    all_records = {**anchors,**records,wiping.WIPE:wipe,bounded.CLEAR:clear}
    require(len({r['image_sha256'] for r in all_records.values()}) == 1, 'same lifecycle image')
    for name,size in (('RetainedWork',1208),(RECEIVE,168)):
        f = anchors[name]['unwind']
        require(len(f) == 1 and f[0]['stack_bytes'] == size and f[0]['chain'] is None and
                not f[0]['saved_registers'], 'actual outer frame geometry')
    for name,record in records.items():
        f = record['unwind']
        require(len(f) == 1 and f[0]['stack_bytes'] == pins[name]['stack_bytes'] and
                f[0]['chain'] is None and not f[0]['saved_registers'], 'complete fixed lifecycle frame')
    for record in all_records.values():
        for symbol,address in record['reference_targets'].items():
            if symbol in all_records: require(address == all_records[symbol]['rva'], 'same selected callee')
            if symbol == 'memcpy': require(address == copy_rva, 'reviewed memory runtime')
            if symbol == GUARD_ALIAS: require(address == records[GUARD]['rva'], 'merged guard identity')
    for caller,callee in (('RetainedWork',NEW),('RetainedWork',DROP),('RetainedWork',QUARANTINE),
                          (RECEIVE,CANCEL),(RECEIVE,CLEAR_OWNER),(RECEIVE,OPERATION),(CANCEL,OPERATION)):
        require(all_records[caller]['reference_targets'].get(callee) == records[callee]['rva'], 'required admission/drop edge')
    require(anchors[RECEIVE]['reference_targets'].get(GUARD_ALIAS) == records[GUARD]['rva'], 'receiver guard drop edge')
    for name in (QUARANTINE,OPERATION,CLEAR_OWNER,CANCEL,GUARD,DROP):
        for callee in (wiping.WIPE,SCRATCH,bounded.CLEAR):
            require(records[name]['reference_targets'].get(callee) == all_records[callee]['rva'], 'complete cleanup chain')


def geometry(window):
    body = Frame.enter(window,window.high-32,56)
    worker = Frame.enter(window,body.current,1208)
    receive = Frame.enter(window,worker.current,168)
    cancel = Frame.enter(window,receive.current,2040)
    frames = {'direct quarantine':Frame.enter(window,worker.current,2040),
              'resident drop':Frame.enter(window,worker.current,2056),
              'receiver clear/guard':Frame.enter(window,receive.current,2040),
              'cancel':cancel,'cancel admission':Frame.enter(window,cancel.current,2056)}
    paths = {}
    for name,frame in frames.items():
        paths[name] = dict(rsp_from_high=frame.current-window.high,
                          spans=[frame.slot('moved state',32,2000),frame.slot('workspace',848,1170),
                                 frame.slot('scratch',128,704)],
                          wipe_clearer=Frame.enter(window,frame.current,40).unknown_callee('clearer entry/home'),
                          memory_entry=frame.unknown_callee('memcpy entry/home'))
    new = Frame.enter(window,worker.current,4104)
    return dict(paths=paths,constructor_rsp_from_high=new.current-window.high,
                constructor_copies=[new.slot('source inactive state/output',42,2015),
                                    new.slot('placement copy',2057,2015)],
                constructor_kat_entry=new.unknown_callee('startup KAT entry/home'),
                original_inactive_owner_storage_erased=False,complete_moved_enum_individually_erased=False,
                outer_window_and_page_teardown_required=True,maximum_transitive_depth_qualified=False)


def inspect(base,pins,mutate=False):
    import windows_enclave_sha_ni_receiver as receiver
    row = shared.catalog(shared.CATALOG.read_bytes())[2]
    profile = workers.specification(workers.SPEC.read_bytes())['profiles'][1]
    require(row['route'] == profile['route'] == 'sha2/mod.rs::open_sha_ni', 'SHA-NI route')
    directory = base/Path(row['object']).parent
    lib = (directory/'normal_rust.lib').read_bytes()
    require(digest(lib) == profile['archive_sha256'], 'SHA-NI saved archive')
    data = workers.archive.members(lib)[profile['member']]
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(data) == profile['object_sha256'] and digest(native) == row['object_sha256'] and
            digest(image) == row['sha256'], 'saved object/image identity')
    for name,h in profile['source_sha256'].items():
        require(digest((directory/name).read_bytes()) == h, 'saved worker source identity')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    parent = shared.inspect(native,image,wrapper)
    anchors = {}
    for name,pin in profile['functions'].items():
        code,refs = shared.caller.function(data,name);workers.body_check(code,refs,pin)
        anchors[name] = shared.caller.bind(data,image,name)
    require(anchors['RetainedWork']['rva'] == parent['retained_worker_rva'], 'actual C-to-worker edge')
    templates = workers.transport.specification(shared.CATALOG.with_name('transport-templates-20261005.json').read_bytes())
    tp = templates['profiles'][1]
    sdk = (base/'sdk-system32-review/vertdll.dll').read_bytes()
    shared.sdk.sdk_review.inspect(sdk)
    transport = workers.transport.inspect(native,image,wrapper,sdk,tp,templates['templates'])
    workers.reconcile(profile,anchors,parent,{tp['prefix']+n:v['rva'] for n,v in transport['records'].items()})
    runtime = memory.inspect(data,image,47);records = {};mutations = 0
    for name in NAMES:
        code,refs = shared.caller.function(data,name)
        workers.body_check(code,refs,pins[name]);instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: workers.body_check(bad,refs,pins[name])
                except ValueError: mutations += 1
                else: raise AssertionError('accepted lifecycle mutation')
    code,refs = shared.caller.function(data,wiping.WIPE)
    wiping.body_check(wiping.WIPE,code,refs);regions = wiping.wipe_plan(code,refs)
    wipe = shared.caller.bind(data,image,wiping.WIPE)
    require(len(wipe['unwind']) == 1 and wipe['unwind'][0]['stack_bytes'] == 40 and
            wipe['unwind'][0]['chain'] is None and not wipe['unwind'][0]['saved_registers'], 'wipe frame')
    code,refs = shared.caller.function(data,bounded.CLEAR)
    require(len(code) == 105 and digest(code) == bounded.CLEAR_HASH and not refs, 'same complete volatile clearer')
    clear = bounded.leaf.bind(data,image,bounded.CLEAR,[wipe,*records.values()])
    reconcile(records,anchors,wipe,clear,runtime['runtime_targets']['memcpy'],pins)
    rows,_ = shared.caller.pe.linked(image)
    for record in records.values():
        if NONE in record['reference_targets']:
            constants.constant(rows,record['reference_targets'][NONE],bytes.fromhex('02000000000000000000000000000000'))
    check,refs = shared.caller.function(data,CHECK)
    require(check == bytes.fromhex('b006807909007401c3807908010f94c0f6d80c06c3') and not refs,
            'exact authority kernel/health leaf')
    checked = bounded.leaf.bind(data,image,CHECK,list(anchors.values()))
    ingress = receiver.inspect(data,image,anchors[RECEIVE],(directory/'normal_rust.ll').read_bytes(),mutate)
    return dict(schema=1,status='SAVED_SHA_NI_LIFECYCLE_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                authority_leaf=checked,receiver=ingress,transport=transport,
                workspace_regions=regions,scratch_regions=[(0,640),(640,64)],
                full_page_zero_loop=dict(bytes=4096,stride=8,stores_per_iteration=8),
                geometry=geometry(Window(0,65536)),actual_body_byte_mutations_rejected=mutations,
                active_owner_with_scratch_bytes_individually_erased=1170+704,complete_enum_bytes=2000,
                kat_and_state_operations_qualified=False,handler_semantics_qualified=False,
                whole_image_qualified=False,native_run_added=False,independently_verified=False,release_gate_changed=False)


def report(base,mutate=False):
    result = inspect(base,specification(SPEC.read_bytes()),mutate)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha-ni-lifecycle.py'),
                  Path(__file__).with_name('test-windows-enclave-sha-ni-receiver.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = SPEC_HASH
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    result = report(a.saved_directory,a.mutate)
    text = json.dumps(result,indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
