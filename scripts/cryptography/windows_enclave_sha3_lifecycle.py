"""Saved scalar SHA-3 cleanup chain. Not complete SHA-3 or OS-unwind qualification."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_lifecycle_shapes as s
import windows_enclave_worker_boundaries as workers
import windows_enclave_bounded_dispatch as bounded

shared,obj = workers.shared,workers.obj
require,digest = shared.require,shared.digest
ASM_HASH = '919b5839ec10122d88ece4df038a4c56a93b2ad2789c75242f8f65a5c3b3cf8c'


def body_check(name,code,refs):
    length,ch,rh = s.PINS[name]
    require(len(code)==length and digest(code)==ch,'complete scalar SHA-3 lifecycle body')
    require(digest(shared.encoded(refs))==rh,'complete scalar SHA-3 lifecycle references')


def coverage(regions):
    cursor = 0
    require(len(regions)==13,'thirteen owned regions')
    for start,length in sorted(regions):
        require(start==cursor and length>0,'no gap or overlap in active owner')
        cursor += length
    require(cursor==1040,'complete active sponge owner')


def instructions(name,code,refs):
    if name==s.WIPE:
        expected,expected_refs = s.wipe_shape();coverage(s.REGIONS)
        require(code==expected and refs==expected_refs,'all thirteen erasures and exact clearing calls/tail')
    else:
        require(code==bytes.fromhex(s.EXACT[name]),'reviewed lifecycle instruction shape')


def table_destinations(raw,address,start):
    require(len(raw)==32,'complete eight-entry drop table')
    offsets = tuple(address+int.from_bytes(raw[i:i+4],'little',signed=True)-start for i in range(0,32,4))
    require(offsets==s.DESTINATIONS,'drop table selects reviewed variant paths')
    return offsets


def table(data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,s.DROP)
    refs = [r for r in refs if r['symbol']=='.rdata']
    require(len(refs)==1 and refs[0]['offset']==19 and refs[0]['addend']==refs[0]['trailing']==0,
            'single exact drop-table operand')
    symbol = symbols[refs[0]['symbol_index']]
    require(symbol['value']==0 and 1<=symbol['section']<=len(rows),'defined drop table')
    section = rows[symbol['section']-1]
    require(section['code']==s.TABLE and section['flags'] & 0xe0000000 == 0x40000000,'readonly reviewed object table')
    relocs = obj.relocations(data,section,symbols)
    require(set(relocs)==set(range(0,32,4)),'complete table relocation population')
    for at,ref in relocs.items():
        target = symbols[ref['symbol']]
        require(ref['kind']==4 and target['section']==selected['section'] and target['value']==0 and
                target['name']=='.text','table targets this destructor')
        require(int.from_bytes(s.TABLE[at:at+4],'little')-at-4==s.DESTINATIONS[at//4],'object table destination')
    linked,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    mapped = [r for r in linked if r['rva']<=address and address+32<=r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(mapped)==1 and mapped[0]['flags'] & 0xe0000000 == 0x40000000,'readonly linked table')
    raw = bounded.mapping.mapped(linked,address,32)
    return raw,dict(rva=address,bytes=32,destinations=table_destinations(raw,address,record['rva']))


def cancellation(phase,stored,requested):
    """Model the inspected comparison branches for valid initialized owners."""
    require(type(phase) is int and 0<=phase<=7,'valid owner phase')
    require(all(type(v) is int and 0<=v<1<<64 for v in (stored,requested)),'u64 sequence domain')
    valid = phase in range(1,7)
    accepted = valid and requested!=0 and ((stored+1) & ((1<<64)-1))==requested
    return dict(error=None if accepted else 'Sequence' if valid else 'State',
                phase=0 if accepted else 7,sequence=requested if accepted else stored,
                active_state_dropped=True,retained_output_erased=True)


def state_writes(tag,setup_present=False):
    """Owner-relative normal writes; no invalid-discriminant/OS-exception claim."""
    require(type(tag) is int and 0<=tag<=8 and type(setup_present) is bool,'valid initialized state')
    require(tag>=7 or not setup_present,'optional sponge belongs only to setup variants')
    if tag==0: return dict(volatile=[],ordinary_zero=[],ordinary_markers=[])
    if tag<7:
        base = 1 if tag<5 else 2
        return dict(volatile=[(1024+base+a,n) for a,n in s.REGIONS],ordinary_zero=[],ordinary_markers=[])
    # Setup Drop calls wipe, then drops its Option. A present owner is wiped
    # twice before None is stored. Public lengths are ordinary stores, not
    # claimed to have volatile erasure semantics.
    active = [(1108+a,n) for a,n in s.REGIONS]*2 if setup_present else []
    return dict(volatile=active+[(1104,1)],ordinary_zero=[(1107,1),(1105,1),(2148,1),(1040,64)],
                ordinary_markers=[(1106,3)])


def reconcile(records,anchors,jump):
    require(set(records)==set(s.PINS) and set(anchors)=={'RetainedWork',s.RECEIVE},'complete lifecycle population')
    image = records[s.ZERO]['image_sha256']
    for name,r in records.items():
        require(r['image_sha256']==image,'same lifecycle image')
        expected_edges = ({s.DROP,s.ZERO} if name in (s.QUARANTINE,s.CLEAR_OWNER,s.CANCEL) else
                          {s.WIPE,s.ZERO,'.rdata'} if name==s.DROP else {s.ZERO} if name==s.WIPE else set())
        require(set(r['reference_targets'])==expected_edges,'complete lifecycle call edge population')
        for callee,address in r['reference_targets'].items():
            expected = jump['rva'] if callee=='.rdata' and name==s.DROP else records.get(callee,{}).get('rva')
            require(expected is not None and expected==address,'exact lifecycle callee')
        if name!=s.ZERO:
            f = r['unwind']
            require(len(f)==1 and f[0]['stack_bytes']==s.FRAMES[name] and f[0]['chain'] is None and
                    not f[0]['saved_registers'],'complete fixed lifecycle frame')
    for caller,callees in {'RetainedWork':(s.QUARANTINE,s.CLEAR_OWNER,s.DROP,s.ZERO,s.RECEIVE),
                          s.RECEIVE:(s.CANCEL,)}.items():
        r = anchors[caller];require(r['image_sha256']==image,'same lifecycle caller')
        for callee in callees:
            destination = (records | anchors)[callee]['rva']
            require(r['reference_targets'].get(callee)==destination,'actual incoming lifecycle call')


def teardown_assembly(raw):
    require(digest(raw)==ASM_HASH,'same scalar SHA-3 assembly')
    text = raw.decode();require(text.count('\nRetainedWork:\n')==1,'unique worker assembler label')
    start = text.index('\nRetainedWork:\n');end = text.index('.seh_endproc',start)
    body = '\n'.join(' '.join(line.split()) for line in text[start:end].splitlines())
    for sequence in (
        'callq '+s.CLEAR_OWNER+'|addq $1024, %rsi|movq %rsi, %rcx|callq '+s.DROP,
        'movq $0, _RNvCsgzEJPm6isiJ_18sha3_stream_worker4LIVE.0(%rip)',
        '|'.join('movb $0, '+('' if i==0 else str(i))+'(%rcx,%rdx)' for i in range(8)),
        'addq $8, %rdx|cmpq $4096, %rdx|jne .LBB0_7',
    ):
        require(sequence.replace('|','\n') in body,'typed destruction then full-page clearing')


def geometry(window):
    body = bounded.Frame.enter(window,window.high-32,56)
    worker = bounded.Frame.enter(window,body.current,1208)
    receiver = bounded.Frame.enter(window,worker.current,200)
    cancel = bounded.Frame.enter(window,receiver.current,56)
    drop = bounded.Frame.enter(window,cancel.current,56)
    wipe = bounded.Frame.enter(window,drop.current,40)
    return dict(cancel_rsp_from_high=cancel.current-window.high,setup_wipe_rsp_from_high=wipe.current-window.high,
                clearing_leaf_entry_from_high=wipe.current-8-window.high,
                saved_registers_require_window_clearing=True,inactive_owner_bytes_require_page_clearing=True,
                maximum_whole_image_depth_qualified=False,other_owner_operation_paths_qualified=False)


def inspect(base,mutate=False):
    row = shared.catalog(shared.CATALOG.read_bytes())[3]
    profile = workers.specification(workers.SPEC.read_bytes())['profiles'][2]
    require(row['route']==profile['route']=='sha3/mod.rs::open','exact scalar SHA-3 route')
    directory = (base/row['object']).parent;lib = (directory/'normal_rust.lib').read_bytes()
    require(digest(lib)==profile['archive_sha256'],'saved scalar archive')
    data = workers.archive.members(lib)[profile['member']]
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(data)==profile['object_sha256'] and digest(native)==row['object_sha256'] and
            digest(image)==row['sha256'],'saved scalar object/C/image identity')
    parent = shared.inspect(native,image,(base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes())
    anchors = {n:shared.caller.bind(data,image,n) for n in ('RetainedWork',s.RECEIVE)}
    require(anchors['RetainedWork']['rva']==parent['retained_worker_rva'],'reviewed wrapper calls this worker')
    for name,r in anchors.items():
        code,refs = shared.caller.function(data,name);workers.body_check(code,refs,profile['functions'][name])
        require([f['stack_bytes'] for f in r['unwind']]==profile['functions'][name]['stack_bytes'],'same caller frame')
    teardown_assembly((directory/'normal_rust.s').read_bytes())
    records = {};count = 0
    for name in s.PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);instructions(name,code,refs)
        records[name] = (bounded.leaf.bind(data,image,name,list(records.values())) if name==s.ZERO else
                         shared.caller.bind(data,image,name))
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: body_check(name,bad,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted lifecycle body mutation')
    raw,jump = table(data,image,records[s.DROP]);table_count = 0
    if mutate:
        for at in range(32):
            bad = bytearray(raw);bad[at] ^= 1
            try: table_destinations(bad,jump['rva'],records[s.DROP]['rva'])
            except ValueError: table_count += 1
            else: raise AssertionError('accepted lifecycle table mutation')
    reconcile(records,anchors,jump)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_LIFECYCLE_REVIEW',route=row['route'],image_sha256=digest(image),
                  object_sha256=digest(data),records=records,anchors=anchors,jump_table=jump,
                  active_sponge_regions=s.REGIONS,geometry=geometry(bounded.Window(0,65536)),
                  actual_body_byte_mutations_rejected=count,actual_table_byte_mutations_rejected=table_count,
                  independently_verified=False,native_run_added=False,release_gate_changed=False,
                  arbitrary_exception_cleanup_qualified=False,whole_image_qualified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-lifecycle.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
