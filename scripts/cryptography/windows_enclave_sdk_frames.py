"""Review of one saved vertdll build, NOT loaded-module or OS qualification.

Exact body bytes support the manually reviewed frame model. This is an offline
review aid, not a release gate, generic disassembler, signature or taint checker.
"""
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_wrapper_binding as pe
from windows_enclave_frame_geometry import Frame, Window, scheduler

IMAGE_SHA256 = 'f5bfb961d19775123c93b8cdf4318238acdf9647bb4518bf009d1969b4d2612f'
# RVAs and complete instruction bodies from the saved 10.0.26100.9444 file.
BODIES = {
    'CallEnclave': (0x1010, '40534883ec20498bd948895424384c8d4c243833d24533c0e873c0010085c0780f488b442438488903b801000000eb098bc8e8692c000033c04883c4205bc3'),
    'EnclaveCopyIntoEnclave': (0x4090, '4883ec2841b101e8d48b01008bc84883c428e9e5fbffff'),
    'EnclaveCopyOutOfEnclave': (0x40b0, '4883ec284533c9e8b48b01008bc84883c428e9c5fbffff'),
    'RtlCallEnclave': (0x1d0a0,
        '4881ec38010000488d8424000100000f297424300f297c2440440f29442450440f294c2460440f29542470'
        '440f295880440f296090440f2968a0440f2970b0440f2978c0488968f8488bec4889184889780848897010'
        '4c8960184c8968204c8970284c897830e885fcffff488d8c24000100000f287424300f287c2440440f28442450'
        '440f284c2460440f28542470440f285980440f286190440f2869a0440f2871b0440f2879c0488b19488b7908'
        '488b71104c8b61184c8b69204c8b71284c8b7930488b69f84881c438010000c3'),
    'copy_syscall_stub': (0x1cc70, '4c8bd1b8190000080f05c3'),
    'call_syscall_stub': (0x1cd90, '4c8bd1b8930000000f05c3'),
}


def require(ok, message):
    if not ok: raise ValueError('saved SDK review: ' + message)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES), 'complete exact body population')
    for name, (_, expected) in BODIES.items():
        require(bodies[name] == bytes.fromhex(expected), 'changed body: ' + name)


def geometry(window):
    # Starting caller RSPs come from the separately bound scheduler model.
    callers = scheduler(window)['frames']
    call = Frame.enter(window, window.high+callers['dispatch']['current_from_high'], 40)
    rtl = Frame.enter(window, call.current, 312)
    copy = Frame.enter(window, window.high+callers['copy_adapter']['current_from_high'], 40)
    spans = [call.slot('CallEnclave saved RBX', -8, 8, 'entry'),
             call.slot('CallEnclave argument/result home', 56, 8)]
    spans += [rtl.slot('RtlCallEnclave XMM'+str(i), 48+(i-6)*16, 16) for i in range(6, 16)]
    spans += [rtl.slot('RtlCallEnclave '+name, offset, 8) for name, offset in
              (('RBP',248), ('RBX',256), ('RDI',264), ('RSI',272),
               ('R12',280), ('R13',288), ('R14',296), ('R15',304))]
    # Syscall stubs have no software stack adjustment or stores. Only the call
    # instruction's return address is mapped here, NOT a kernel context frame.
    spans += [window.span('call syscall return', rtl.current-8, 8),
              window.span('copy syscall return', copy.current-8, 8)]
    return dict(spans=spans, rtl_frame_from_high=rtl.current-window.high,
                copy_frame_from_high=copy.current-window.high,
                kernel_storage_qualified=False, status_helper_depth_qualified=False,
                sdk_self_erasure_claimed=False, maximum_transitive_depth_qualified=False)


def inspect(data):
    require(hashlib.sha256(data).hexdigest() == IMAGE_SHA256, 'different SDK file')
    rows, _ = pe.linked(data)
    bodies = {}
    for name, (rva, expected) in BODIES.items():
        size = len(bytes.fromhex(expected))
        matches = [r for r in rows if r['flags'] & 0x20000000 and not r['flags'] & 0x80000000
                   and 0 <= rva-r['rva'] <= min(len(r['code']), r['virtual_size'])-size]
        require(len(matches) == 1, 'bounded nonwritable code: ' + name)
        row = matches[0]
        bodies[name] = row['code'][rva-row['rva']:rva-row['rva']+size]
    check_bodies(bodies)
    return dict(schema=1, status='SAVED_SDK_SELECTED_FRAMES_NOT_OS_QUALIFICATION',
                image_sha256=IMAGE_SHA256, version_observed='10.0.26100.9444',
                loaded_module_identity_proven=False, native_enclave_run_added=False,
                whole_image_qualified=False, production_qualified=False,
                bodies={n: dict(rva=rva, bytes=len(bytes.fromhex(code)),
                        sha256=hashlib.sha256(bytes.fromhex(code)).hexdigest())
                        for n,(rva,code) in BODIES.items()},
                geometry=geometry(Window(0,65536)))


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1]).read_bytes()), indent=2))
