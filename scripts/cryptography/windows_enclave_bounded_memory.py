"""Reconcile saved bounded-image memory helpers; offline author review only."""
import argparse
import json
from pathlib import Path
import struct
import sys

import windows_enclave_memory_runtime as prior
import windows_enclave_bounded_export as exported

shared,dispatch = exported.shared,exported.dispatch
rehash = exported.sha.rehash
borrowed = rehash.borrowed
require,digest = shared.require,shared.digest
DELTA = -22608
TABLE_DELTA = -25968
TARGETS = {0:0,0x11060:0xa060,0x11068:0xa068,0x11070:0xa070,0x118bc:0xa88c}
UNWIND = {'copy_rep':36432,'copy':36424,'fill_rep':36448,'fill':36424}
HASHES = {
    'copy_rep':prior.BODIES['copy_rep'][2],
    'copy':'718e1fc1c5c447145ffb0fc72ff208bbbe0a09aca2868312f218683e3b4af0ec',
    'fill_rep':prior.BODIES['fill_rep'][2],
    'fill':'7eb6a5ccdaf8ab4147a7982a39b5124840c6fd044d8684c638eff6f46db3146e',
}
CALLS = {rehash.REHASH:((174,'memset'),(199,'memcpy')),
         borrowed.HASH:((176,'memset'),(201,'memcpy'),(363,'memset'))}
ARGUMENTS = {
    rehash.REHASH:((154,'4c8db424e800000041b8800300004c89f131d2e800000000'
                         '4c8da424ee04000041b8000400004c89e14c89f2e800000000'),),
    borrowed.HASH:((156,'4c8da424ee00000041b8800300004c89e131d2e800000000'
                         '4c8dbc242e05000041b8000400004c89f94c89e2e800000000'),
                   (343,'488dac24ee04000041b8400400004c89e131d2e800000000')),
}


def normalize(bodies):
    """Validate actual destinations BEFORE replacing only their four-byte operands."""
    require(set(bodies) == set(prior.BODIES),'complete bounded runtime population')
    result = {}
    for n,(_,size,_) in prior.BODIES.items():
        require(len(bodies[n]) == size,'complete bounded runtime body')
        result[n] = bytearray(bodies[n])
    for n,address,prefix,target,suffix in prior.RIP_READS:
        at = address-prior.BODIES[n][0];p,s = bytes.fromhex(prefix),bytes.fromhex(suffix)
        end = at+len(p)+4+len(s);operand = at+len(p)
        require(bodies[n][at:operand] == p and bodies[n][operand+4:end] == s,'RIP operand instruction')
        actual = prior.BODIES[n][0]+DELTA+end+int.from_bytes(bodies[n][operand:operand+4],'little',signed=True)
        require(actual == TARGETS[target],'exact bounded RIP destination')
        result[n][operand:operand+4] = (target-prior.BODIES[n][0]-end).to_bytes(4,'little',signed=True)
    for n,address,table,small in prior.DISPATCH:
        at = address-prior.BODIES[n][0]
        p = bytes.fromhex('478b8c82' if small else '478b9c9a')
        s = bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
        require(bodies[n][at:at+4] == p and bodies[n][at+8:at+14] == s,'complete bounded table dispatch')
        require(int.from_bytes(bodies[n][at+4:at+8],'little') == table+TABLE_DELTA,'exact bounded table address')
        result[n][at+4:at+8] = struct.pack('<I',table)
    return {n:bytes(b) for n,b in result.items()}


def check_bodies(bodies):
    # Exact baseline equality also rejects any unenumerated relocation or change.
    normalized = normalize(bodies)
    prior.check_bodies(normalized);prior.check_instructions(normalized)
    require(all(digest(bodies[n]) == HASHES[n] for n in HASHES),'exact saved bounded runtime hashes')


def tables(rows):
    result = {}
    for address,targets in prior.TABLES.items():
        actual = address+TABLE_DELTA;shifted = tuple(t+DELTA for t in targets)
        n = 'copy' if address < 0xea00 else 'fill'
        start,size,_ = prior.BODIES[n]
        require(all(start+DELTA <= t < start+DELTA+size for t in shifted),'table stays in reviewed body')
        record = prior.session.setup.construction.constant(rows,actual,struct.pack('<16I',*shifted))
        result[hex(actual)] = record | dict(previous_rva=address,targets=shifted)
    return result


def frames(rows,functions):
    result = {}
    for n,(start,size,_) in prior.BODIES.items():
        start += DELTA;unwind = UNWIND[n]
        require([f for f in functions if f[0] < start+size and start < f[1]] ==
                [(start,start+size,unwind)],'exact bounded memory runtime extent')
        _,raw,stack = prior.UNWIND[n]
        prior.session.setup.construction.constant(rows,unwind,bytes.fromhex(raw))
        result[n] = dict(rva=start,bytes=size,unwind_rva=unwind,unwind_hex=raw,
                         instruction_review_fixed_frame_bytes=stack,unwind_semantics_qualified=False)
    return result


def selectors(rows):
    result = []
    for old,size in ((0x11060,4),(0x11068,8),(0x11070,8),(0x118bc,1)):
        address = TARGETS[old]
        owners = [r for r in rows if r['rva'] < address+size and address < r['rva']+r['virtual_size']]
        require(len(owners) == 1,'unique runtime selector mapping')
        row = owners[0]
        require(row['rva'] <= address and address+size <= row['rva']+row['virtual_size'] and
                row['flags'] & 0xa0000000 == 0x80000000,'complete writable nonexecutable selector')
        result.append(dict(rva=address,bytes=size,live_value_established=False))
    return result


def call_population(data):
    """Enumerate ALL executable COFF relocations, including unselected functions."""
    rows,symbols = dispatch.obj.tables(data);result = []
    for index,row in enumerate(rows,1):
        if not row['flags'] & 0x20000000: continue
        for offset,ref in dispatch.obj.relocations(data,row,symbols).items():
            name = symbols[ref['symbol']]['name']
            if name not in ('memcpy','memset'): continue
            owners = [s for s in symbols.values() if s['section'] == index and s['kind'] == 0x20]
            require(len(owners) == 1 and owners[0]['value'] == 0,'one complete memory caller per section')
            require(ref['kind'] == 4 and offset > 0 and row['code'][offset-1] == 0xe8 and
                    row['code'][offset:offset+4] == bytes(4),'direct memory call without addend')
            result.append((owners[0]['name'],offset,name))
    return sorted(result)


def incoming(data,native,image):
    expected = sorted((name,at,symbol) for name,calls in CALLS.items() for at,symbol in calls)
    require(call_population(data) == expected and not call_population(native),'complete Rust/C memory call population')
    result = {}
    for name in CALLS:
        code,refs = shared.caller.function(data,name)
        (rehash if name == rehash.REHASH else borrowed).body_check(name,code,refs)
        for at,raw in ARGUMENTS[name]:
            b = bytes.fromhex(raw);require(code[at:at+len(b)] == b,'memory caller arguments')
        record = shared.caller.bind(data,image,name)
        for symbol,helper in (('memcpy','copy'),('memset','fill')):
            require(record['reference_targets'][symbol] == prior.BODIES[helper][0]+DELTA,'bound actual helper callee')
        result[name] = dict(rva=record['rva'],calls=CALLS[name])
    return result


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    records = {}
    for name,fixed,src,dst in (('rehash',2504,232,1262),('hash',2584,238,1326)):
        frame = dispatch.Frame.enter(window,worker.current,fixed)
        spans = [frame.slot('zero-fill prefix',src,896),frame.slot('copy source',src,1024),
                 frame.slot('copy destination',dst,1024)]
        require(src+1024 <= dst,'nonoverlapping memcpy ranges')
        if name == 'hash': spans.append(frame.slot('input workspace fill',src,1088))
        # Tail REP helpers share the vector helper's return address, no extra CALL.
        deepest = frame.current-8-16
        window.span('REP return and saved caller registers',deepest,24)
        records[name] = dict(caller_rsp_from_high=frame.current-window.high,spans=spans,
                             deepest_memory_rsp_from_high=deepest-window.high)
    return dict(callers=records,rep_tail_transfer=True,individual_saved_register_slots_erased=False,
                payload_registers_erased=False,outer_window_and_return_cleanup_required=True,
                maximum_whole_image_depth_qualified=False)


def inspect(data,native,image,wrapper,sdk_data,mutate=False):
    exported.inspect(data,native,image,wrapper,sdk_data)
    rows,functions = shared.caller.pe.linked(image)
    bodies = {n:prior.session.executable(rows,a+DELTA,size) for n,(a,size,_) in prior.BODIES.items()}
    check_bodies(bodies);table_records = tables(rows);frame_records = frames(rows,functions)
    count,table_count = 0,0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed = bytearray(body);changed[i] ^= 1
                try: check_bodies(bodies | {name:bytes(changed)})
                except ValueError: count += 1
                else: raise AssertionError('accepted memory body mutation')
        for address in prior.TABLES:
            address += TABLE_DELTA
            index = next(i for i,r in enumerate(rows) if r['rva'] <= address < r['rva']+r['virtual_size'])
            row = rows[index]
            for i in range(64):
                changed = bytearray(row['code']);changed[address-row['rva']+i] ^= 1
                altered = rows[:index]+[row | {'code':bytes(changed)}]+rows[index+1:]
                try: tables(altered)
                except ValueError: table_count += 1
                else: raise AssertionError('accepted memory table mutation')
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_MEMORY_RUNTIME_RECONCILIATION',
                image_sha256=digest(image),object_sha256=digest(data),body_sha256=HASHES,
                normalized_body_sha256={n:digest(b) for n,b in normalize(bodies).items()},
                relocation_operands_checked=len(prior.RIP_READS)+len(prior.DISPATCH),
                frames=frame_records,tables=table_records,selectors=selectors(rows),
                incoming=incoming(data,native,image),geometry=geometry(dispatch.Window(0,65536)),
                actual_body_byte_mutations_rejected=count,actual_table_byte_mutations_rejected=table_count,
                arbitrary_exception_cleanup_qualified=False,general_memmove_correctness_qualified=False,
                live_dispatch_values_qualified=False,whole_image_qualified=False,native_run_added=False,
                independently_verified=False,release_gate_changed=False)


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
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-bounded-memory.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
