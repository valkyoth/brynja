"""Saved SDK dispatch/restore frames with explicit external continuation limits."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_context as context
from windows_enclave_frame_geometry import Frame, Window

diagnostic = context.diagnostic
require = context.require
BODIES = {
    'dispatch': (0x8790,956,'17540f0c172e6cf304e0cc9cadcd2b8ec4c2ab085afd1f7f03e16a756fc3319d'),
    'restore': (0x1650,1256,'5bd226a61890d63b640f8f8c28faac10d50629809bcdd480ee218b06c1be13d0'),
    'ip_hook': (0x1b40,1,'ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e'),
    'raise': (0x1b50,112,'331891b1795a59a399395758c891d189a950fbdbf2d460750660743ae9818024'),
    'capture_prefix': (0x13c0,112,'ff2b2fd0a050aa290bcfecde3b6a290be3d37deab2b6033a4fb4458bf49217a6'),
    'handler': (0x1d570,21,'dc05021d8eb9e0c825296d890625aa16daf4061c7ac874594fd905ecfe62e26f'),
    'continue_stub': (0x1cd30,11,'a21bf8e175288351b76ae6920de8cbb6766cf7b475f4537cee07bda8859749ac'),
}
EDGES = tuple(('dispatch',a,0xe8,t) for a,t in (
    (0x87dc,0x1f030),(0x8808,0x1f030),(0x881f,0x16d9c),(0x882f,0x166f8),
    (0x8844,0x161a4),(0x8866,0x1d1f0),(0x8880,0x162b4),(0x888b,0x93b8),
    (0x88ce,0x8b60),(0x8918,0xc3f0),(0x8931,0x172fc),(0x8996,0x1d570),
    (0x89ec,0x93b8),(0x8a18,0xc320),(0x8a33,0x8b60),(0x8a50,0xc4e8),
    (0x8ae4,0x172fc),(0x8aff,0xbeb0),(0x8b10,0xbeb0),(0x8b2d,0x1ce20))) + (
    ('restore',0x17aa,0xe8,0x1cd30),('raise',0x1b5a,0xe8,0x13c0),
    ('raise',0x1bb0,0xe9,0x8790),('raise',0x1bbb,0xe9,0x1cde0))
ANCHORS = (
    ('dispatch',0x8790,'4055565741544155415641574881ec00020000488d6c2470'),
    ('dispatch',0x8834,'41bc0b001000488d5500418bcc4533c0'),
    ('dispatch',0x886b,'482be14c8d45384533c9418bd44c8d742470'),
    ('restore',0x1650,'485556574883ec30488bec'),
    ('restore',0x1927,'4883ec304c8bc44881ecf0040000488bf1488bfcb99a000000f348a5'),
    ('restore',0x1925,'48cf'),('restore',0x1b36,'48cf'),
    ('restore',0x199f,'488d150a000000ffe2'),
    ('restore',0x19d0,'488d15d1fdffffffe2'),
    ('restore',0x19b0,'488b4120ffd0'),
    ('restore',0x1805,'0fae2b44894318'),('restore',0x1a16,'0fae2b44894318'),
    ('ip_hook',0x1b40,'c3'),('raise',0x1b50,'4852514883ec28'),
    ('raise',0x1baa,'4883c428595a'),('raise',0x1bb5,'4883c428595a'),
    ('capture_prefix',0x13c0,'489c'),('capture_prefix',0x1427,'488d1549000000ffe2'),
    ('handler',0x1d570,'4883ec284c894c2420498b4130ffd0904883c428c3'),
)
UNREVIEWED = ((0x16d9c,'initial stack bounds'),(0x172fc,'stack-frame bounds/progression'),
    (0x93b8,'context copy'),(0xc3f0,'alternate unwind adapter'))


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete dispatch/restore population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'dispatch/restore body: '+name)


def check_edges(bodies):
    for name,address,opcode,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            address-BODIES[name][0],opcode) == target,'dispatch/restore transfer')
    for name,address,hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        offset = address-BODIES[name][0]
        require(bodies[name][offset:offset+len(code)] == code,'continuation/frame anchor')


def mutations(bodies):
    check_bodies(bodies)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try: check_bodies(bodies | {name:bytes(changed)})
            except ValueError: count += 1
            else: raise AssertionError('accepted dispatch/restore body mutation')
    return count


def geometry(window,capacity,exception_size):
    """Illustrative valid basic dispatcher size, not arbitrary exception bounds."""
    result = {}
    for path,row in context.exception.geometry(window,capacity).items():
        outer = window.high+row['fixed_frames']['exception']
        caller = outer-context.exception.allocation_size(exception_size)
        dispatch = Frame.enter(window,caller,568)
        # Constant basic flags/mask, conditional on the size helper succeeding.
        work = Frame(window,dispatch.entry,dispatch.current-1280)
        window.span('dispatcher dynamic frame',work.current,dispatch.entry+40-work.current)
        restore = Frame.enter(window,caller,72)  # Sibling of dispatch, not nested.
        copied = Frame(window,restore.entry,restore.current-1312)
        window.span('special restore frame',copied.current,restore.entry+40-copied.current)
        handler = Frame.enter(window,work.current,40)
        raise_status = Frame.enter(window,work.current,1432)
        raise_context = Frame.enter(window,raise_status.current,56)
        # raise_context restores its own RSP then tail-jumps: no second return.
        tail_dispatch = Frame.enter(window,raise_status.current,568)
        spans = [dispatch.slot('dispatch seven pushes',-56,56,'entry'),
            dispatch.slot('dispatch RBX home',24,8,'entry'),
            dispatch.slot('dispatch locals and metadata pointers',112,64),
            dispatch.slot('dispatch handler record',176,80),
            dispatch.slot('dispatch original context pointer',256,8),
            dispatch.slot('dispatch history table',272,216),
            dispatch.slot('dispatch cookie',496,8),
            work.slot('dispatch outgoing unwind arguments',32,64),
            work.slot('conditional basic context and metadata envelope',112,1264),
            handler.slot('handler dispatcher pointer',32,8),
            restore.slot('restore three pushes',-24,24,'entry'),
            restore.slot('direct IRET staging envelope',0,34),
            copied.slot('special restore copied base context',0,1232),
            copied.slot('special restore adjusted metadata',1232,24),
            copied.slot('special restore auxiliary RIP',1264,8),
            copied.slot('special restore auxiliary RSP',1288,8),
            copied.slot('special IRET staging overlaps copied context',0,34),
            raise_context.slot('raise-context saved arguments',-16,16,'entry'),
            window.span('capture-prefix return and flags',raise_context.current-16,16)]
        return_slots = [restore.slot('direct IRET RIP',0,8),restore.slot('direct IRET CS',8,2),
            restore.slot('direct IRET EFLAGS',16,4),restore.slot('direct IRET RSP',24,8),
            restore.slot('direct IRET SS',32,2)]
        result[path] = dict(illustrative_exception_size=exception_size,
            frames={n:f.current-window.high for n,f in (('dispatch_fixed',dispatch),
                ('dispatch_dynamic',work),('handler',handler),('restore',restore),
                ('special_restore',copied),('first_status_raise',raise_status),
                ('raise_context',raise_context),('tail_dispatch_fixed',tail_dispatch))},
            spans=spans,iret_field_writes=return_slots,
            external_entries=[handler.unknown_callee('unwind handler from dispatcher record'),
                              copied.unknown_callee('restore callback from exception record')],
            actual_runtime_allocation_observed=False,continuation_target_validated=False,
            maximum_transitive_depth=None,cleanup_qualified=False)
    return result


def inspect(data,exercise_mutations=False):
    previous = context.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,r,s,True) for n,(r,s,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_DISPATCH_RESTORE_EXTERNAL_CONTINUATIONS_UNQUALIFIED',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=r,bytes=s,sha256=h) for n,(r,s,h) in BODIES.items()},
        direct_transfers=len(EDGES),instruction_anchors=len(ANCHORS),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c,1279) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        exception_unwind_cleanup_qualified=False,external_callback_cleanup_qualified=False,
        continuation_targets_validated=False,arbitrary_context_bounds_qualified=False,
        sdk_self_erasure_claimed=False,
        side_effects=[
            'dispatch copies context and updates exception flags and nonnull history storage',
            'dispatch calls a metadata-selected handler and restore can call an exception-record callback',
            'IRET restores context-selected stack and instruction pointers instead of wiping the abandoned frame',
            'special restore copies 1232 context bytes and adjusts metadata on its own stack',
            'XRSTOR paths temporarily exchange MXCSR in context-derived extended storage',
            'raise helper restores its own frame before tail dispatch or kernel transition',
            'the selected instruction-pointer hook is one RET byte in this saved image'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in
                    (0x1b40,0x8790,0x1650,0x1b50)] + [dict(rva=r,reason=s) for r,s in UNREVIEWED],
        residuals=previous['residuals']+[
            'external handler and continuation targets; recursive exceptions and fatal transitions'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
