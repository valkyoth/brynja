"""Saved context helpers and conditional layout models, not native size evidence."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_exception as exception
from windows_enclave_frame_geometry import Frame, Window

diagnostic = exception.diagnostic
require = exception.require
BODIES = {
    'size_adapter': (0x161a4,19,'20598934b3ef7b32a95e2307ca8da9bc6e1fd4796c133e58254b4e28c4f10ccc'),
    'size_worker': (0x161c0,235,'9b6fb9b196944b630710dc6eeca258898e0414a93a74c83a03747b3412f36d5c'),
    'initialize': (0x162b4,487,'c5b9b8661c8f2c74111dea8de9f40eb4e05ac05b3a2ba7a998958a77fec4ffe6'),
    'xstate_size': (0x165d4,76,'efff0365f606ce2f30bec449175d48508ed419be9dcf8ba92d88e4f77c09a554'),
    'shape': (0x16628,90,'c4756dbbca8ab5f3cd88b0b596f1c27e66e518a7e779b105cc14c0dec9a5ff03'),
    'mask': (0x166b8,56,'d6262ddbe604861cc62266f3b0ec36b480753001a3662a9c268c6eac478597f8'),
    'capture': (0x1500,317,'32630bc6937feef852d46b9d63d41666c7b2cc88fc1f4663dc78b6f0ee743d20'),
}
EDGES = (('size_adapter',0x161b2,0xe9,0x161c0),
    ('size_worker',0x161f9,0xe8,0x167dc),('size_worker',0x16211,0xe8,0x16628),
    ('size_worker',0x1625f,0xe8,0x166b8),('size_worker',0x1626e,0xe8,0x165d4),
    ('initialize',0x162e8,0xe8,0x167c0),('initialize',0x163df,0xe8,0x166b8),
    ('initialize',0x163f3,0xe8,0x165d4),('initialize',0x16406,0xe8,0x1f030))
ANCHORS = (
    ('size_worker',0x161cf,'5541564157488bec4883ec30'),
    ('size_worker',0x16273,'442bdb418d8b40feffff03c8'),
    ('size_worker',0x16289,'ffc803c3418907'),
    ('initialize',0x162c3,'5741544155415641574883ec30'),
    ('initialize',0x16316,'488d4d0f4883e1f0897930488d99d0040000'),
    ('initialize',0x163a3,'488d6b5f4883e5c0'),
    ('initialize',0x163fd,'8db000feffff448bc6'),
    ('initialize',0x16478,'49895d00'),
    ('xstate_size',0x16607,'83c03f83e0c00302'),
    ('capture',0x1500,'48519c4883ec28'),
    ('capture',0x156c,'488d1549000000ffe2'),
    ('capture',0x1629,'c74130000000008149300f0010004883c43059c3'),
)
U32 = (1 << 32)-1
U64 = (1 << 64)-1


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete context-helper population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'context body: '+name)


def check_edges(bodies):
    for name,address,opcode,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            address-BODIES[name][0],opcode) == target,'context helper transfer')
    for name,address,hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        offset = address-BODIES[name][0]
        require(bodies[name][offset:offset+len(code)] == code,'context instruction anchor')


def mutations(bodies):
    check_bodies(bodies)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try: check_bodies(bodies | {name:bytes(changed)})
            except ValueError: count += 1
            else: raise AssertionError('accepted context body mutation')
    return count


def integer(value,maximum):
    require(type(value) is int and 0 <= value <= maximum,'unsigned model input')
    return value


def xstate_size(mask,compact,alignment_mask,sizes,standard_size):
    """Raw helper arithmetic, including DWORD wrap; no validation of OS tables."""
    integer(mask,U64)
    integer(alignment_mask,U64)
    integer(standard_size,U32)
    require(type(compact) is bool and len(sizes) == 62,'feature table model shape')
    for size in sizes: integer(size,U32)
    if not compact: return standard_size
    result = 0x240
    for bit,size in enumerate(sizes,2):
        if mask & (1 << bit):
            if alignment_mask & (1 << bit): result = ((result+63)&U32)&~63
            result = (result+size)&U32
    return result


def x64_layout(base,extended,state_size=0):
    """Conditional x64 layout after successful flag validation; not all callers.

    The feature mask/table is upstream input, not inferred from this model.
    Preservation of DWORD arithmetic deliberately exposes wrap/underflow rather
    than silently turning SDK arithmetic into checked Python arithmetic.
    """
    integer(base,U64)
    integer(state_size,U32)
    require(type(extended) is bool and base % 16 == 0 and base <= U64-(1 << 33),
            'selected aligned x64 context base with model arithmetic headroom')
    metadata = base+0x4d0
    writes = [dict(name='context flags',address=base+48,bytes=4),
              dict(name='selected metadata fields',address=metadata,bytes=24)]
    size_output = 1279
    if extended:
        start = (metadata+0x5f)&-64
        length = (state_size-0x200)&U32
        if length: writes.append(dict(name='extended initialization fill',address=start,bytes=length))
        # Compacted mode also stores an eight-byte mask at start+8. Report
        # that separately: malformed tables must not hide it in a short fill.
        writes.append(dict(name='possible compacted mask',address=start+8,bytes=8))
        size_output = (815+state_size)&U32
    return dict(size_output=size_output,allocation_bytes=exception.allocation_size(size_output),
        writes=[dict(name=w['name'],offset=w['address']-base,bytes=w['bytes']) for w in writes],
        writes_fit_size_output=all(w['address']+w['bytes'] <= base+size_output for w in writes),
        configuration_validated=False,erasure_qualified=False)


def geometry(window,capacity,size):
    result = {}
    for path,row in exception.geometry(window,capacity).items():
        caller = window.high+row['fixed_frames']['exception']
        size_frame = Frame.enter(window,caller,72)
        dynamic = caller-exception.allocation_size(size)
        window.span('illustrative dynamic context and fixed frame',dynamic,caller+360-dynamic)
        initialize = Frame.enter(window,dynamic,88)
        capture = Frame.enter(window,dynamic,56)
        spans = [size_frame.slot('size worker home RBX RSI',8,16,'entry'),
            size_frame.slot('size worker home RDI',32,8,'entry'),
            size_frame.slot('size worker three pushes',-24,24,'entry'),
            size_frame.slot('size worker three DWORD locals',32,12),
            size_frame.slot('size worker mask in third home',24,8,'entry'),
            initialize.slot('initializer three home saves',8,24,'entry'),
            initialize.slot('initializer five pushes',-40,40,'entry'),
            initialize.slot('initializer flag result',32,4),
            initialize.slot('initializer mask in fourth home',32,8,'entry'),
            capture.slot('capture RCX and flags pushes',-16,16,'entry'),
            window.span('size output reused for metadata pointer',caller+64,8),
            size_frame.unknown_callee('flags leaf return/home'),
            initialize.unknown_callee('flags leaf return/home')]
        context = dynamic+64
        # Entry 0x1500 skips alternate entry 0x1580's volatile saves/FXSAVE.
        captures = [window.span(name,context+offset,length) for name,offset,length in (
            ('flags MXCSR segments EFLAGS',48,24),('nonvolatile GPRs and RSP',144,40),
            ('R12-R15 and RIP',216,40),('x87 control and zero fields',256,6),
            ('saved MXCSR',280,4),('XMM6-XMM15',512,160))]
        result[path] = dict(illustrative_size_output=size,
            frames={n:f.current-window.high for n,f in
                    (('size',size_frame),('initialize',initialize),('capture',capture))},
            spans=spans,capture_spans=captures,actual_runtime_size_observed=False,
            transitive_depth_bound=None,cleanup_qualified=False)
    return result


def inspect(data,exercise_mutations=False):
    previous = exception.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_CONTEXT_HELPERS_CONDITIONAL_LAYOUT_ONLY',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=r,bytes=s,sha256=h) for n,(r,s,h) in BODIES.items()},
        direct_transfers=len(EDGES),instruction_anchors=len(ANCHORS),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        illustrative_layouts={'basic':x64_layout(0,False),'extended_576':x64_layout(0,True,576)},
        geometry={str(c):{str(s):geometry(Window(0,65536),c,s) for s in (1279,1391)}
                  for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        runtime_feature_table_validated=False,maximum_transitive_depth_qualified=False,
        exception_unwind_cleanup_qualified=False,complete_extended_register_capture=False,
        sdk_self_erasure_claimed=False,
        side_effects=[
            'size and layout depend on a Windows-owned feature table not established by saved DLL bytes',
            'SDK size and fill arithmetic uses DWORD wrap; models do not certify malformed tables',
            'initialization clearing is not exit erasure',
            'selected capture entry skips volatile GPR and FXSAVE alternate entry',
            'capture saves XMM6-XMM15 and nonvolatile GPRs then replaces flags with 0x10000f',
            'initializer replaces the caller DWORD size slot with an eight-byte metadata pointer'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in (0x161a4,0x162b4,0x1500)],
        residuals=previous['residuals']+['runtime feature table sizes masks and alignment validity'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
