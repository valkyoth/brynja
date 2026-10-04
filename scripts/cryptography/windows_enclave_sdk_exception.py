"""Saved SDK exceptional storage accounting, not exception-cleanup qualification."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_decoders as decoders
from windows_enclave_frame_geometry import Frame, Window

diagnostic = decoders.diagnostic
require = decoders.require
BODIES = {
    'fatal': (0x1160,373,'a542e93a0b33a454b8412a8b9a87f98b40e463cee6d6ceadf944b7993f062996'),
    'exception': (0xbc90,534,'3b7c2275254686cefa221c80a5749c491d352a4bd6927dbc239f77835726ac0e'),
    'terminate_stub': (0x1cd00,11,'c95cb992ecdbb6ae60311086a60a23b1aaea00281ed3abe8edadce1f1305c702'),
    'raise_stub': (0x1cde0,11,'2cc438dcfe8a7d3b401b118c8c78d1177f25607befa003272302373805db7169'),
}
EDGES = tuple(('fatal',a,t) for a,t in ((0x11a0,0x1440),(0x11be,0x8b60),
    (0x120a,0xc320),(0x12b7,0xbf30),(0x12c8,0x1cd00))) + tuple(
    ('exception',a,t) for a,t in ((0xbcea,0x1f030),(0xbd6b,0x161a4),
    (0xbd8d,0x1d1f0),(0xbda7,0x162b4),(0xbdb1,0x1500),(0xbddc,0x8b60),
    (0xbe12,0xc320),(0xbe29,0x1b40),(0xbe43,0x8790),(0xbe52,0x1650),
    (0xbe61,0x1ce20),(0xbe97,0x1cde0),(0xbea0,0xbeb0)))
ANCHORS = (
    ('fatal',0x1160,'48894c24084881ec88000000'),
    ('exception',0xbc90,'4055415641574881ec50010000488d6c2440'),
    ('exception',0xbcef,'0fba6f0407'),
    ('exception',0xbd70,'8b4500488d480f483bc8770a48b9f0ffffffffffff0f4883e1f0488bc1'),
    ('exception',0xbd92,'482be14c8d45004c8bce418bd6488d5c2440'),
    ('exception',0xbdbd,'4c8d452048834d28ff488d5508498bce44897d20c74524000000014c897d30'),
    ('exception',0xbe17,'488b83f800000048894710'),
    ('exception',0xbe7b,'488da510010000415f415e5dc3'),
)
# RIP-relative instruction, prefix, target, optional immediate after displacement.
REFERENCES = (
    (0x1199,'488d0d',0x28860,''),(0x11a5,'488b05',0x28958,''),
    (0x11ed,'488d05',0x28860,''),(0x1219,'488905',0x28958,''),
    (0x122c,'488905',0x288f8,''),(0x1233,'488b05',0x28958,''),
    (0x123a,'488905',0x287d0,''),(0x1249,'488905',0x288e0,''),
    (0x1250,'c705',0x287c0,'090400c0'),(0x125a,'c705',0x287c4,'01000000'),
    (0x1264,'c705',0x287d8,'01000000'),(0x1277,'488d0d',0x287e0,''),
    (0x128f,'488b0d',0x28040,''),(0x12a4,'488b0d',0x28048,''),
    (0x12b0,'488d0d',0x20000,''),
)
GLOBALS = (('captured context envelope',0x28860,768),
           ('selected fatal record envelope',0x287c0,40))
UNREVIEWED = ((0x161a4,'runtime context size and feature-dependent helpers'),
    (0x162b4,'runtime context initialization'),(0x1500,'extended context capture'),
    (0x1b40,'exception instruction-pointer helper'),(0x8790,'exception dispatcher'),
    (0x1650,'context restore'),(0xbf30,'fatal diagnostic wrapper and transitive calls'))


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete exceptional body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'exceptional body: '+name)


def check_edges(bodies):
    for name,address,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            address-BODIES[name][0],0xe8) == target,'exceptional call: '+name)
    for name,address,hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        offset = address-BODIES[name][0]
        require(bodies[name][offset:offset+len(code)] == code,'exceptional instruction anchor')
    for address,prefix,target,immediate in REFERENCES:
        prefix,immediate = bytes.fromhex(prefix),bytes.fromhex(immediate)
        size = len(prefix)+4+len(immediate)
        offset = address-BODIES['fatal'][0]
        code = bodies['fatal'][offset:offset+size]
        require(len(code) == size and code[:len(prefix)] == prefix and
            code[len(prefix)+4:] == immediate and
            address+size+int.from_bytes(code[len(prefix):len(prefix)+4],'little',signed=True) == target,
            'fatal global RIP reference')


def global_storage(rows):
    result = []
    for name,rva,size in GLOBALS:
        # Virtual storage can be zero-initialized; do not require raw file bytes.
        matches = [r for r in rows if r['flags'] & 0x80000000 and
                   not r['flags'] & 0x20000000 and
                   0 <= rva-r['rva'] <= r['virtual_size']-size]
        require(len(matches) == 1,'unique writable non-executable global envelope')
        result.append(dict(name=name,rva=rva,bytes=size,storage='SDK image global',
                           covered_by_stack_window=False,erasure_qualified=False))
    return result


def mutations(bodies):
    check_bodies(bodies)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try: check_bodies(bodies | {name:bytes(changed)})
            except ValueError: count += 1
            else: raise AssertionError('accepted exceptional body mutation')
    return count


def allocation_size(size):
    """The caller zero-extends a DWORD, so its 64-bit +15 cannot overflow."""
    require(type(size) is int and 0 <= size <= 0xffffffff,'DWORD context-size output')
    return (size+15) & -16


def dynamic_geometry(window,caller,size):
    """Illustrative supplied size only; not a bound on the size helper's output."""
    frame = Frame.enter(window,caller,360)
    allocation = allocation_size(size)
    current = frame.current-allocation
    window.span('dynamic frame and caller home',current,frame.entry+40-current)
    outgoing = window.span('dynamic outgoing unwind arguments',current+32,32)
    # A pointer is not a destination envelope: initialization/capture can align
    # or write beyond the requested bytes. Those helpers are still unqualified.
    return dict(size_output=size,allocation_bytes=allocation,
        rsp_from_high=current-window.high,context_pointer_from_high=current+64-window.high,
        outgoing=outgoing,context_write_extent=None,cleanup_qualified=False)


def geometry(window,capacity):
    result = {}
    for path,row in diagnostic.geometry(window,capacity).items():
        caller = window.high+row['frames']['buffer_dynamic']
        exception = Frame.enter(window,caller,360)
        # Cookie checker tail-jumps fatal; it does NOT add another return slot.
        fatal = Frame.enter(window,caller,136)
        record = window.high+row['frames']['buffer_fixed']+96
        spans = [exception.slot('exception pushes',-24,24,'entry'),
            exception.slot('exception home RBX RSI RDI',16,24,'entry'),
            exception.slot('size output DWORD',64,4),
            exception.slot('image base and unwind outputs',72,24),
            exception.slot('history header and twelve entries',96,216),
            exception.slot('exception cookie',320,8),
            window.span('exception caller flags write',record+4,4),
            window.span('exception caller instruction pointer write',record+16,8),
            fatal.slot('fatal input home',8,8,'entry'),
            fatal.slot('fatal outgoing unwind arguments',32,32),
            fatal.slot('fatal five local pointers',64,40),
            fatal.slot('fatal cookie copies',104,16)]
        result[path] = dict(fixed_frames={n:f.current-window.high for n,f in
            (('exception',exception),('fatal_via_cookie_tail',fatal))},spans=spans,
            dynamic_allocation_bytes=None,context_write_extent=None,
            nonnull_history_pointer_from_high=exception.current+96-window.high,
            history_write_bounds_qualified=False,maximum_transitive_depth=None,
            exception_cleanup_qualified=False)
    return result


def inspect(data,exercise_mutations=False):
    previous = decoders.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_EXCEPTIONAL_STORAGE_NOT_CLEANUP_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=r,bytes=s,sha256=h) for n,(r,s,h) in BODIES.items()},
        direct_transfers=len(EDGES),instruction_anchors=len(ANCHORS),global_references=len(REFERENCES),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        global_storage=global_storage(rows),
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        exception_unwind_cleanup_qualified=False,maximum_transitive_depth_qualified=False,
        runtime_context_size_qualified=False,sdk_global_erasure_qualified=False,
        kernel_storage_qualified=False,sdk_self_erasure_claimed=False,
        side_effects=[
            'fatal register capture writes SDK global storage outside the stack clearing window',
            'exception path modifies caller flags and instruction pointer',
            'exception lookup receives a nonnull history table unlike the earlier null-history origins',
            'runtime-sized context allocation and extended-state writes have no qualified bound here',
            'normal restore and RSP reset are not stack or global erasure',
            'syscall stubs identify transitions not kernel storage or termination guarantees'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in (0x1160,0xbc90)] +
                   [dict(rva=r,reason=s) for r,s in UNREVIEWED],residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
