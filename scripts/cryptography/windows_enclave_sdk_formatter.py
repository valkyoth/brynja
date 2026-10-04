"""Saved-SDK formatter frame review, not a generic formatter or OS proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_diagnostic as diagnostic
from windows_enclave_frame_geometry import Frame, Window

# Complete manually inspected instruction ranges. Hashes bind the review, not
# a semantic proof. Keep proprietary SDK bytes in the owner's local artifacts.
BODIES = {
    'format_engine': (0x2968, 2160, 'b294c72e1b49d47aa91eba79215f139cdc34415a952c058fd2589c9dfedc953b'),
    'output_error': (0x2958, 8, '86fad30a60e4e6a65ef2493138b94ab29108aecc62b05d7f8b36b9d51796eaef'),
    'put': (0x31e0, 71, 'b942e19a16927b86cbe9d466b703968a77732515027225d56dc48364cae5c022'),
    'pad': (0x3230, 81, 'f00f38a9348bb49bfd9177fca51b5dd5fd95f048e6f42aa2fc9d8ae960fbbfb9'),
    'write': (0x3288, 128, 'bf32dae453fb05cddea6a35734be79aa558900bb0f7bda73f9e24fc7def4f321'),
    'errno_pointer': (0x3c44, 16, '63d9fa50d9af44b94e3b7b5bc3cf6d9cd81264fec3100c7e241b62fbde87d6d0'),
    'count_enabled': (0x3318, 24, '2a2d2588c3e14a5087423ad0e3d245847e2411cde8312f74e8189a53c7ed27b5'),
    'fill_thunk': (0x1f030, 5, '18d84f906432bd864ff1649a605031967ee0733f8197c640e70758ed63341e3c'),
    'fill': (0x1dbc0, 486, '3a490a60c3543f00d65030a9686c60ab08587adf7d3459c5f43798344d5a0b75'),
    'fill_large': (0x1ddc0, 51, '7a12a41499a9caa3b4e73de18044e0ba7fabf28570c3fef325c1ea2444cfb6ee'),
}
EDGES = (
    ('format_engine',0x29d4,0xe8,0x1f030), ('format_engine',0x2c28,0xe8,0x33f4),
    ('format_engine',0x2e7a,0xe8,0x3230), ('format_engine',0x2e91,0xe8,0x3288),
    ('format_engine',0x2eac,0xe8,0x3230), ('format_engine',0x2ee4,0xe8,0x33f4),
    ('format_engine',0x2f09,0xe8,0x3288), ('format_engine',0x2f2f,0xe8,0x3288),
    ('format_engine',0x2f55,0xe8,0x3230), ('format_engine',0x2f78,0xe8,0x3318),
    ('format_engine',0x3076,0xe8,0x31e0), ('format_engine',0x31a6,0xe8,0x1058),
    ('format_engine',0x31b8,0xe8,0x1ce20), ('put',0x3211,0xe8,0x2958),
    ('pad',0x325e,0xe8,0x31e0), ('write',0x32ca,0xe8,0x31e0),
    ('write',0x32d7,0xe8,0x3c44), ('write',0x32e9,0xe8,0x31e0),
    ('fill_thunk',0x1f030,0xe9,0x1dbc0),
)


def check_bodies(bodies):
    diagnostic.status.sdk.require(set(bodies) == set(BODIES), 'formatter population')
    for name,(_,size,digest) in BODIES.items():
        body = bodies[name]
        diagnostic.status.sdk.require(len(body) == size and
            hashlib.sha256(body).hexdigest() == digest, 'formatter body: '+name)


def check_edges(bodies):
    diagnostic.status.sdk.require(BODIES['format_engine'][0] == 0x2968,
                                  'previous formatter boundary')
    for name,instruction,opcode,target in EDGES:
        diagnostic.status.sdk.require(diagnostic.status.relative_target(
            BODIES[name][0],bodies[name],instruction-BODIES[name][0],opcode) == target,
            'formatter transfer: '+name)


def mutations(bodies):
    """Exercise each real body byte independently of the outer DLL hash."""
    check_bodies(bodies)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try:
                check_bodies(bodies | {name:bytes(changed)})
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted changed formatter instruction body')
    return count


def geometry(window, capacity):
    result = {}
    for path,previous in diagnostic.geometry(window,capacity).items():
        caller = window.high+previous['frames']['format_wrapper']
        engine = Frame.enter(window,caller,696)  # seven pushes + 0x280 allocation
        writer = Frame.enter(window,engine.current,40)
        put = Frame.enter(window,writer.current,40)
        spans = [
            engine.slot('engine RBX home save',24,8,'entry'),
            engine.slot('engine seven pushed GPRs',-56,56,'entry'),
            engine.slot('engine locals and argument staging',32,80),
            engine.slot('engine conversion scratch',112,512),
            engine.slot('engine wide-character temporary',624,6),
            engine.slot('engine cookie',632,8),
            writer.slot('writer/padder three home saves',8,24,'entry'),
            writer.slot('writer/padder pushed register',-8,8,'entry'),
            put.slot('put pushed RBX',-8,8,'entry'),
            window.span('output-error leaf return/home',put.current-8,40),
            # A fill tail transfer does not add another return address.
            window.span('fill optional RDI push and return',engine.current-16,16),
        ]
        result[path] = dict(frames=dict(engine=engine.current-window.high,
            writer_or_padder=writer.current-window.high,put=put.current-window.high),
            spans=spans,unreviewed=engine.unknown_callee('wide/invalid/fatal helper entry'),
            selected_leaf_low_from_high=put.current-8-window.high)
    return result


def inspect(data, exercise_mutations=False):
    previous = diagnostic.inspect(data)
    sections,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(sections,rva,size,True)
              for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_SDK_FORMATTER_FRAMES_NOT_TRANSITIVE_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest)
                for n,(rva,size,digest) in BODIES.items()},
        direct_transfers=len(EDGES),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,arbitrary_formats_qualified=False,
        exception_unwind_cleanup_qualified=False,
        thread_relative_read=dict(base='value at GS:0x30',offset=0x1500,bytes=4),
        unresolved=[dict(rva=rva,reason=reason) for rva,reason in (
            (0x33f4,'wide-character conversion path'),(0x1058,'invalid-argument path'),
            (0xbc90,'exception dispatch with runtime-sized context allocation'),
            (0x1160,'fatal cookie-failure path'))],
        residuals=previous['residuals'],
        buffer_full_wipe_on_exit_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
