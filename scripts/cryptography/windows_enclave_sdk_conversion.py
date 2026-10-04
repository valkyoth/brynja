"""Saved-SDK conversion/context frames; no exceptional cleanup qualification."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_formatter as formatter
from windows_enclave_frame_geometry import Frame, Window

BODIES = {
    'wide_adapter': (0x33f4, 20, '37b06291f160bc15c3b8a4379d5eca9b103e39a28c470db3e823d78ce9cf356e'),
    'wide_helper': (0x3338, 182, '1758d1be1606ceb8e39395dfb2596c84411ad70fbaff9e09e7f5d185931e65c7'),
    'wide_unsupported': (0x5468, 6, '4807e08e2c30c197bced82f7ec820a50ba15c4b5c05ffbd737b763637b3e9c5a'),
    'invalid_argument': (0x1058, 258, 'f0a312f0786b150fcee4885f9fcb73313665f9528aacd6391b4b075ba6b1a51c'),
    'capture_context': (0x1440, 175, '178aaab860c4f1714765f5d0a9052a3de48f9e165cb81395e1c5b4bb2998769e'),
}
EDGES = (
    ('wide_adapter',0x33fe,0x3338),
    ('wide_helper',0x3386,0x1058), ('wide_helper',0x33c2,0x5468),
    ('wide_helper',0x33cb,0x3c44),
    ('invalid_argument',0x1094,0x1440), ('invalid_argument',0x10ab,0x8b60),
    ('invalid_argument',0x10e5,0xc320), ('invalid_argument',0x1115,0x1f030),
    ('invalid_argument',0x1135,0x168a4), ('invalid_argument',0x1144,0x1ce20),
)


def require(ok, message):
    formatter.diagnostic.status.sdk.require(ok, message)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES), 'complete conversion/context population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'conversion/context body: '+name)


def check_edges(bodies):
    for name,instruction,target in EDGES:
        require(formatter.diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            instruction-BODIES[name][0],0xe8) == target, 'conversion/context call: '+name)


def mutations(bodies):
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
                raise AssertionError('conversion/context byte mutation accepted')
    return count


def geometry(window, capacity):
    result = {}
    for path,previous in formatter.geometry(window,capacity).items():
        engine_sp = window.high+previous['frames']['engine']
        adapter = Frame.enter(window,engine_sp,56)
        helper = Frame.enter(window,adapter.current,56)
        spans = [adapter.slot('adapter fifth argument',32,8),
                 helper.slot('wide input home spill',32,2,'entry'),
                 helper.slot('wide helper RBX push',-8,8,'entry'),
                 helper.slot('wide helper result in caller home',72,4),
                 helper.slot('wide helper fifth argument',32,4),
                 window.span('unsupported/error-pointer leaf return',helper.current-8,8)]
        invalid_paths = {}
        # Direct engine call and conservative helper-invalid branch. This does
        # not assert the latter is reached with the fixed 6/512-byte capacities.
        for origin,caller_sp in (('engine',engine_sp),('wide_helper',helper.current)):
            invalid = Frame.enter(window,caller_sp,1512)  # push RBP + 0x5e0
            # RBP = current + 256; observed capture stores extend to +0x300.
            context = invalid.current+256
            require(context % 16 == 0, 'aligned observed FXSAVE destination')
            saved = [
                invalid.slot('invalid RBX home save',8,8,'entry'),
                invalid.slot('invalid RBP push',-8,8,'entry'),
                invalid.slot('invalid call arguments and result slots',32,56),
                invalid.slot('invalid exception record',96,152),
                window.span('context scalar/register destination envelope',context,256),
                window.span('context FXSAVE destination',context+256,512),
                invalid.slot('invalid cookie',1488,8),
                window.span('capture PUSHF and return',invalid.current-16,16)]
            # Invalid-argument diagnostic re-entry goes through the SAME guard
            # already bound in diagnostic.buffer. No assumed recursive bound.
            entry = Frame.enter(window,invalid.current,72)
            retry = Frame.enter(window,entry.current,72)
            buffer = Frame.enter(window,retry.current,328)
            invalid_paths[origin] = dict(frame_from_high=invalid.current-window.high,
                spans=saved,reentry_frames=dict(entry=entry.current-window.high,
                    retry=retry.current-window.high,guarded_buffer=buffer.current-window.high),
                unreviewed=invalid.unknown_callee('lookup/unwind/fatal helper entry'))
        result[path] = dict(frames=dict(adapter=adapter.current-window.high,
            helper=helper.current-window.high),spans=spans,invalid_paths=invalid_paths)
    return result


def inspect(data, exercise_mutations=False):
    previous = formatter.inspect(data)
    sections,_ = formatter.diagnostic.status.sdk.pe.linked(data)
    bodies = {n:formatter.diagnostic.extract(sections,rva,size,True)
              for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_SDK_CONVERSION_CONTEXT_NOT_EXCEPTION_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest)
                for n,(rva,size,digest) in BODIES.items()},
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c)
                  for c in formatter.diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        context_erased_by_capture_helper=False,
        conversion_leaf_return='0xc00000bb',
        thread_relative_write=dict(base='value at GS:0x30',offset=0x1500,bytes=4,value=42,
                                   cleared_by_window_proven=False),
        diagnostic_reentry=dict(cycle_observed=True,
            guard='buffer tests bit 2 at pointer GS:0x30 + 0x17ee before dynamic allocation',
            nested_formatting_skipped_if_flag_preserved=True,
            exception_safe_guard_lifecycle_qualified=False),
        unresolved=[dict(rva=rva,reason=reason) for rva,reason in (
            (0x8b60,'runtime lookup'),(0xc320,'runtime unwind processing'),
            (0xbc90,'exception dispatch with runtime-sized context allocation'),
            (0x1160,'fatal cookie-failure path'))],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
