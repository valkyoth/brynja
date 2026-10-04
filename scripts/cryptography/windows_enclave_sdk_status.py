"""Pinned status-helper review for one saved SDK file, not OS qualification."""
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_sdk_frames as sdk
from windows_enclave_frame_geometry import Frame, Window, scheduler

# Manually reviewed complete bodies; names describe this file's selected helpers.
BODIES = {
    'copy_status': (0x3c8c,
        '4883ec28e83b79000085c07e080fb7c00d000007804883c428c3'),
    'call_status': (0x3cb0,
        '4883ec28e8177900008bc8e8787a00008bc14883c428c3'),
    'status_to_error': (0xb5d0,
        '894c24084883ec2865488b0425300000004885c0740c898850120000eb048b4c2430e80d0000004883c428c3'),
    'status_lookup': (0xb604,
        '40534883ec204533c085c9750733c0e91101000081f903010000750ab8e5030000e9ff0000008bc10fbae11d'
        '0f82f3000000250000ff003d0000070075178bc1c1e81883c080a9bfffffff75080fb7c1e9d00000008bc148'
        '8d1d9e49ffff8bd125000000f081e2ffffffcf41b9570100003d000000d00f45d1438d0c08448bd2d1e98b84'
        'cb402b0200442bd03bd07306448d49ffeb110fb684cb442b0200443bd07247448d4101453bc176cd8bc22500'
        '00ffff3d000001c075050fb7c2eb66488d0d86520100e8d5b10000488d0dc2520100e8c9b10000488d0dee52'
        '0100e8bdb10000b83d010000eb3b80bccb452b0200010fb784cb462b0200750d4103c20fb78443000a0200eb'
        '1c428d14500fb78c53000a02008d42010fb78443000a0200c1e0100bc14883c4205bc3'),
    'set_last_error': (0xb738,
        '65488b0425300000008b15fdd5010085d274053bca7501cc3948687403894868c3'),
    'diagnostic_entry': (0x168a4,
        '4c8bdc49894b08498953104d8943184d894b204883ec48ba65000000498d43104c8bc9498943d8448d429ee8'
        '3c0000004883c448c3'),
}
# Instruction offsets, opcodes and exact targets, including copy tail transfers.
EDGES = (
    ('EnclaveCopyIntoEnclave', 18, 0xe9, 'copy_status'),
    ('EnclaveCopyOutOfEnclave', 18, 0xe9, 'copy_status'),
    ('CallEnclave', 50, 0xe8, 'call_status'),
    ('copy_status', 4, 0xe8, 'status_to_error'),
    ('call_status', 4, 0xe8, 'status_to_error'),
    ('call_status', 11, 0xe8, 'set_last_error'),
    ('status_to_error', 34, 0xe8, 'status_lookup'),
    ('status_lookup', 198, 0xe8, 'diagnostic_entry'),
    ('status_lookup', 210, 0xe8, 'diagnostic_entry'),
    ('status_lookup', 222, 0xe8, 'diagnostic_entry'),
)
DEEP_DIAGNOSTIC_RVA = 0x16910


def check_bodies(bodies):
    sdk.require(set(bodies) == set(BODIES), 'complete status-helper population')
    for name, (_, code) in BODIES.items():
        sdk.require(bodies[name] == bytes.fromhex(code), 'changed status body: '+name)


def relative_target(rva, code, offset, opcode):
    sdk.require(type(offset) is int and 0 <= offset <= len(code)-5, 'bounded instruction')
    sdk.require(code[offset] == opcode and opcode in (0xe8, 0xe9), 'reviewed direct transfer')
    return rva+offset+5+int.from_bytes(code[offset+1:offset+5], 'little', signed=True)


def check_edges():
    population = sdk.BODIES | BODIES
    for source, offset, opcode, target in EDGES:
        rva, code = population[source]
        sdk.require(relative_target(rva, bytes.fromhex(code), offset, opcode)
                    == population[target][0], 'status transfer: '+source)
    rva, code = BODIES['diagnostic_entry']
    sdk.require(relative_target(rva, bytes.fromhex(code), 43, 0xe8)
                == DEEP_DIAGNOSTIC_RVA, 'explicit unreviewed diagnostic boundary')


def geometry(window):
    callers = scheduler(window)['frames']
    call = Frame.enter(window, window.high+callers['dispatch']['current_from_high'], 40)
    # Copy exports restore RSP and tail-jump: no extra return address/frame.
    starts = {'copy': window.high+callers['copy_adapter']['current_from_high'],
              'call_error': call.current}
    result = {}
    for path, caller_sp in starts.items():
        status = Frame.enter(window, caller_sp, 40)
        convert = Frame.enter(window, status.current, 40)
        lookup = Frame.enter(window, convert.current, 40)  # push RBX + 32 bytes
        diagnostic = Frame.enter(window, lookup.current, 72)
        spans = [convert.slot('status home spill', 8, 4, 'entry'),
                 lookup.slot('lookup saved RBX', -8, 8, 'entry')]
        spans += [diagnostic.slot('diagnostic '+name, offset, 8, 'entry')
                  for name, offset in (('RCX',8), ('RDX',16), ('R8',24), ('R9',32),
                                       ('varargs pointer',-40))]
        if path == 'call_error':
            spans.append(window.span('last-error leaf return/home', status.current-8, 40))
        result[path] = dict(frames={n: f.current-window.high for n,f in
            (('status',status), ('convert',convert), ('lookup',lookup),
             ('diagnostic_entry',diagnostic))}, spans=spans,
            unknown_callee=diagnostic.unknown_callee('deeper diagnostic entry/home'))
    return dict(paths=result, copy_status_is_tail_transfer=True,
        kernel_storage_qualified=False, loaded_module_identity_proven=False,
        diagnostic_callee_depth_qualified=False, maximum_transitive_depth_qualified=False,
        thread_relative_status_storage_cleared_by_window=False)


def inspect(data):
    previous = sdk.inspect(data)  # Full-file pin and the six original bodies.
    rows, _ = sdk.pe.linked(data)
    bodies = {}
    for name, (rva, code) in BODIES.items():
        size = len(bytes.fromhex(code))
        matches = [r for r in rows if r['flags'] & 0x20000000
                   and not r['flags'] & 0x80000000 and
                   0 <= rva-r['rva'] <= min(len(r['code']),r['virtual_size'])-size]
        sdk.require(len(matches) == 1, 'bounded nonwritable status code: '+name)
        row = matches[0]
        bodies[name] = row['code'][rva-row['rva']:rva-row['rva']+size]
    check_bodies(bodies)
    check_edges()
    return dict(schema=1,status='SAVED_SDK_STATUS_PATH_REVIEW_NOT_OS_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        bodies={n:dict(rva=rva,bytes=len(bytes.fromhex(code)),
                       sha256=hashlib.sha256(bytes.fromhex(code)).hexdigest())
                for n,(rva,code) in BODIES.items()},
        geometry=geometry(Window(0,65536)),
        thread_relative_writes=[
            dict(body='status_to_error',base='value at GS:0x30',offset=0x1250,bytes=4,
                 value='incoming 32-bit status',inside_cleared_window_proven=False),
            dict(body='set_last_error',base='value at GS:0x30',offset=0x68,bytes=4,
                 value='converted 32-bit error',inside_cleared_window_proven=False)],
        unresolved=[dict(rva=DEEP_DIAGNOSTIC_RVA,reason='deeper diagnostic implementation'),
                    dict(body='set_last_error',reason='conditional INT3 and interruption paths'),
                    dict(reason='kernel transfer storage and loaded-module identity')])


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1]).read_bytes()),indent=2))
