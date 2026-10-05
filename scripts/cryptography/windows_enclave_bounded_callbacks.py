"""Saved bounded input/observation adapters; no OS or loaded-SDK attestation."""
import argparse
import json
from pathlib import Path
import re

import windows_enclave_bounded_sha256 as sha

shared,dispatch = sha.shared,sha.dispatch
require,digest = shared.require,shared.digest
SPECS = {
    'PublicInputCopy':(182,'eeac8c4b35b1194613158506c5094117bfe560ebe5cc14679e7c741302aa1a22',
                       '2ce7774f59debb850d5e79162ea5cfe2a16e4484bad68f7247e765282bcbf7ce'),
    'PublicInputObserve':(134,'3630a7c1a1947676f756ca71c58d55e62436a894afaacc6c0bd204a09fd77b81',
                          'a424252e652a1d23226dfc8901b01935c31bf71ae5b8f348164b36194aea7603'),
    'PublicInputSource':(30,'66647bf7816d34951576eaac97fd7b37de42a0d1de829a0a74d77be356aa0694',
                         '2ce7065769adfdb229994e929c8035ff7946d8f52422040e959304ca19957eb5'),
    'PublicRehashObserve':(149,'ca11ba27e89e133dfdf3f6734580bd57718b99e33d3083c5dcccc18c3976765d',
                           '5e4441f0958efb01de80a11538565411b38db2e0ebaf0cb2ed2ba97137064750'),
    'PublicRetainedInput':(201,'0340665402e5c4d13ad985faa7ab901e101651bad3cea80d5a796d2d5979050c',
                           '123ccc4a31cfbb5f1ae1a07aa72e2e681999314e4fc85b51b0d646459e8e2aae'),
    'PublicInputControl':(44,'de983ef3a2c6f6bfd53016962fd11187a041b1d558971e955b4a93763b2f3a00',
                          '49eb30cbc05780256618170d4e4fa4e093554d42bf0c1f9d09864a6d443799d5'),
    'PublicRehashControl':(58,'82cea8f385025781d796c9d37eb04bb2632ea385a95a8364d45e258298ce0571',
                           '9f02522bfa273246aca9dc68cfe7a64d96b5935628d9e9d5a3f38febc6e70176'),
}
LEAVES = set(SPECS)-{'PublicInputCopy'}
GLOBALS = {'active':4,'retained_call':4,'PublicLockedLow':8,'PublicLockedHigh':8,
           'input_source':8,'input_report':88,'rehash_report':64,'cross_report':48,'public_copy_calls':8}
EXPORTS = ('PublicRetainedInput','PublicInputControl','PublicRehashControl')
COPY_LANDMARKS = ((0,'40534883ec20'),(0x2a,'4883f901'),(0x39,'4981f900040000'),
                  (0x49,'483bd0'),(0x4e,'482bc24c3bc8'),(0x5b,'4983f920'),
                  (0x61,'4883fb01'),(0x67,'4d85c9'),(0x6c,'48391d08000000'),
                  (0x75,'48c1e3044d8bc148897c2430498bd3488d3d00000000498bca48ff043be80000000085c0'),
                  (0x9b,'48ff443b08488b7c24304883c4205bc3b8054000804883c4205bc3'))
COPY_BRANCHES = ((0x17,'0f84',0xab),(0x24,'0f84',0xab),(0x2e,'77',0xab),
                 (0x37,'72',0xab),(0x40,'77',0xab),(0x4c,'77',0xab),(0x54,'77',0xab),
                 (0x59,'75',0x61),(0x5f,'eb',0x73),(0x65,'75',0x75),(0x6a,'74',0xab),
                 (0x73,'75',0xab),(0x99,'75',0xa0))


def check_body(name,code,refs):
    size,code_hash,refs_hash = SPECS[name]
    require(len(code) == size and digest(code) == code_hash,'complete callback body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete callback references')


def copy_instructions(code):
    for offset,text in COPY_LANDMARKS:
        raw = bytes.fromhex(text)
        require(code[offset:offset+len(raw)] == raw,'copy admission/count/status instruction')
    for offset,text,target in COPY_BRANCHES:
        opcode = bytes.fromhex(text);width = 4 if len(opcode) == 2 else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,'copy branch destination')


def report_plan(name,code,refs):
    require(name in ('PublicInputObserve','PublicRehashObserve'),'known observer')
    count,start,base,symbol = (7,0x31,32,'input_report') if name == 'PublicInputObserve' else (8,0x35,0,'rehash_report')
    writes = []
    for i in range(count):
        load = bytes.fromhex('488b01') if i == 0 else bytes.fromhex('488b41')+bytes([i*8])
        raw = load+bytes.fromhex('488905')+(base+i*8).to_bytes(4,'little')
        require(code[start:start+len(raw)] == raw,'exact metadata word load/store')
        expected = dict(offset=start+len(load)+3,symbol=symbol,trailing=0,addend=base+i*8)
        require([r for r in refs if r['offset'] == expected['offset']] == [expected],'metadata store relocation')
        writes.append(dict(source=i*8,destination=base+i*8,bytes=8))
        start += len(raw)
    require(code[start:] == bytes.fromhex('b801000000c333c0c3'),'observer success/rejection tail')
    return writes


def bind_leaf(data,image,name):
    # Not a generic relaxed caller binder: only six individually pinned,
    # manually reviewed call-free/stack-free bodies with RIP-relative data.
    require(name in LEAVES,'reviewed callback leaf population')
    code,refs = shared.caller.function(data,name);check_body(name,code,refs)
    require(all(r['symbol'] in GLOBALS for r in refs),'only reviewed data references')
    rows,functions = shared.caller.pe.linked(image)
    parts,cursor = [],0
    for ref in refs:
        at = ref['offset'];parts.extend((re.escape(code[cursor:at]),b'.{4}'));cursor = at+4
    parts.append(re.escape(code[cursor:]));pattern = b'(?=('+b''.join(parts)+b'))'
    found = [(r,m.start()) for r in rows if r['flags'] & 0x20000000
             for m in re.finditer(pattern,r['code'],re.DOTALL)]
    require(len(found) == 1,'unique complete callback leaf')
    row,offset = found[0];rva = row['rva']+offset
    require(not row['flags'] & 0x80000000 and offset+len(code) <= row['virtual_size'],'mapped nonwritable callback')
    require(not any(a < rva+len(code) and rva < b for a,b,_ in functions),'callback leaf has no unwind overlap')
    targets = {}
    for ref in refs:
        at = ref['offset'];delta = int.from_bytes(row['code'][offset+at:offset+at+4],'little',signed=True)
        target = rva+at+4+ref['trailing']+delta-ref['addend']
        require(ref['symbol'] not in targets or targets[ref['symbol']] == target,'consistent callback global')
        targets[ref['symbol']] = target
    return dict(entry=name,rva=rva,size=len(code),reference_targets=targets,image_sha256=digest(image),
                object_sha256=digest(data),no_unwind=True,whole_image_qualified=False)


def exported(image,name):
    rows,_ = shared.caller.pe.linked(image)
    rva,size = shared.sdk.directory(image,0)
    header = dispatch.mapping.mapped(rows,rva,40)
    *_,count,names,addresses,pointers,ordinals = shared.caller.pe.unpack('<IIHHIIIIIII',header,0)
    require(0 < names <= count <= 8192,'bounded application exports')
    found,seen = [],set()
    for i in range(names):
        ptr, = shared.caller.pe.unpack('<I',dispatch.mapping.mapped(rows,pointers+4*i,4),0)
        text = shared.sdk.string(rows,ptr)
        require(text not in seen,'unique application export name');seen.add(text)
        if text != name: continue
        ordinal, = shared.caller.pe.unpack('<H',dispatch.mapping.mapped(rows,ordinals+2*i,2),0)
        require(ordinal < count,'application export ordinal')
        target, = shared.caller.pe.unpack('<I',dispatch.mapping.mapped(rows,addresses+4*ordinal,4),0)
        require(not rva <= target < rva+size,'no forwarded application entry')
        owners = [r for r in rows if r['rva'] <= target < r['rva']+min(len(r['code']),r['virtual_size'])]
        require(len(owners) == 1 and owners[0]['flags'] & 0xa0000020 == 0x20000020,'export in nonwritable mapped code')
        found.append(target)
    require(len(found) == 1,'unique named application export')
    return found[0]


def reconcile(records,anchors,parent,image):
    require(set(records) == set(SPECS),'complete callback population')
    identities = dict(parent['reference_targets'])
    for record in records.values():
        require(record['image_sha256'] == parent['image_sha256'],'same callback image')
        for symbol,target in record['reference_targets'].items():
            require(symbol not in identities or identities[symbol] == target,'same callback global/callee')
            identities[symbol] = target
    incoming = {sha.owner.borrowed.RECEIVE:('PublicInputCopy',),
                sha.owner.borrowed.HASH:('PublicInputSource','PublicInputObserve'),sha.rehash.REHASH:('PublicRehashObserve',)}
    require(set(anchors) == set(incoming),'complete Rust callback caller set')
    for name,edges in incoming.items():
        require(anchors[name]['image_sha256'] == parent['image_sha256'],'same Rust caller image')
        for edge in edges:
            require(anchors[name]['reference_targets'].get(edge) == records[edge]['rva'],'exact Rust callback edge')
    for name in EXPORTS: require(exported(image,name) == records[name]['rva'],'named exported control entry')
    rows,_ = shared.caller.pe.linked(image)
    spans = []
    for name,size in GLOBALS.items():
        address = identities[name]
        require(sum(r['rva'] <= address and address+size <= r['rva']+r['virtual_size'] and
                    r['flags'] & 0xe0000000 == 0xc0000000 for r in rows) == 1,'complete writable nonexecutable metadata')
        spans.append(dict(name=name,rva=address,bytes=size))
    ordered = sorted(spans,key=lambda s:s['rva'])
    require(all(a['rva']+a['bytes'] <= b['rva'] for a,b in zip(ordered,ordered[1:])),'nonoverlapping metadata regions')
    return identities,spans


def copy_frames(record):
    frames = record['unwind'];start = record['rva']
    require(len(frames) == 3 and [(f['start']-start,f['end']-start,f['stack_bytes']) for f in frames] ==
            [(0,124,40),(124,171,0),(171,182,0)],'complete copy unwind fragments')
    require(frames[0]['chain'] is None and all(tuple(f['chain'] or ()) ==
            (start,start+124,frames[0]['unwind_rva']) for f in frames[1:]),'copy chains reuse primary frame')
    require([f['saved_registers'] for f in frames] == [[],[dict(register_class='gpr',register=7,offset=48)],[]],
            'conditional saved RDI home spill')


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    hashed = dispatch.Frame.enter(window,worker.current,2584)
    receive = dispatch.Frame.enter(window,hashed.current,296)
    copy = dispatch.Frame.enter(window,receive.current,40)
    sdk = dispatch.Frame.enter(window,copy.current,40)
    return dict(copy_rsp_from_high=copy.current-window.high,sdk_copy_rsp_from_high=sdk.current-window.high,
                spans=[copy.slot('saved RBX',-8,8,'entry'),copy.slot('conditional saved RDI',48,8),
                       window.span('input observer return/home',hashed.current-8,40),
                       window.span('copy syscall return',sdk.current-8,8)],
                unknown_callee=sdk.unknown_callee('SDK syscall entry/home, not kernel storage'),
                exported_control_frames_included=False,maximum_transitive_depth_qualified=False,
                kernel_storage_qualified=False,sdk_self_erasure_claimed=False)


def inbound_edges(code):
    status = shared.sdk.status;entry = status.sdk.BODIES['EnclaveCopyIntoEnclave'][0]
    require(len(code) == 23 and code[:7] == bytes.fromhex('4883ec2841b101') and
            code[12:18] == bytes.fromhex('8bc84883c428'),'inbound flag and status handoff')
    require(status.relative_target(entry,code,7,0xe8) == status.sdk.BODIES['copy_syscall_stub'][0] and
            status.relative_target(entry,code,18,0xe9) == status.BODIES['copy_status'][0],'inbound syscall and status tail')


def inspect(data,native,image,wrapper,sdk_data,mutate=False):
    sha.inspect(data,native,image,wrapper)
    parent = shared.inspect(native,image,wrapper)
    records,plans,count = {},{},0
    for name in SPECS:
        code,refs = shared.caller.function(native,name);check_body(name,code,refs)
        if name == 'PublicInputCopy':
            copy_instructions(code);records[name] = shared.caller.bind(native,image,name);copy_frames(records[name])
        else: records[name] = bind_leaf(native,image,name)
        if name in ('PublicInputObserve','PublicRehashObserve'): plans[name] = report_plan(name,code,refs)
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: check_body(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual callback body mutation')
    anchors = {n:shared.caller.bind(data,image,n) for n in
               (sha.owner.borrowed.RECEIVE,sha.owner.borrowed.HASH,sha.rehash.REHASH)}
    identities,spans = reconcile(records,anchors,parent,image)
    imports = shared.sdk.imports(image)['vertdll.dll'];rows,functions = shared.caller.pe.linked(image)
    thunk = shared.sdk.thunk(rows,functions,identities['EnclaveCopyIntoEnclave'],imports['EnclaveCopyIntoEnclave'])
    status = shared.sdk.status;status.inspect(sdk_data)
    entry,body = status.sdk.BODIES['EnclaveCopyIntoEnclave'];code = bytes.fromhex(body)
    require(shared.sdk.export(sdk_data,'EnclaveCopyIntoEnclave') == entry,'saved SDK named inbound export')
    inbound_edges(code)
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_CALLBACK_NORMAL_PATH_REVIEW',records=records,
                report_writes=plans,metadata_regions=spans,geometry=geometry(dispatch.Window(0,65536)),
                sdk_copy=dict(thunk_rva=identities['EnclaveCopyIntoEnclave'],thunk=thunk,
                              import_rva=imports['EnclaveCopyIntoEnclave'],export_rva=entry,sha256=digest(sdk_data)),
                actual_body_byte_mutations_rejected=count,loaded_sdk_identity_proven=False,
                sdk_status_tail_review_reused=True,whole_image_qualified=False,native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[0]
    require(row['route'] == 'mod.rs::open','bounded image')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == dispatch.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sdk-system32-review/vertdll.dll').read_bytes(),args.mutate)
    sources = ('windows_enclave_bounded_callbacks.py','test-windows-enclave-bounded-callbacks.py',
               'windows_enclave_bounded_sha256.py','windows_enclave_bounded_owner.py','windows_enclave_bounded_rehash.py',
               'windows_enclave_bounded_input.py','windows_enclave_bounded_dispatch.py','windows_enclave_sequential_c.py',
               'windows_enclave_sdk_return.py','windows_enclave_sdk_status.py','windows_enclave_sdk_frames.py',
               'windows_enclave_caller_binding.py','windows_enclave_caller_unwind.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
