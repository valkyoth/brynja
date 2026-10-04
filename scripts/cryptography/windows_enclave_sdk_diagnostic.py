"""Selected saved-SDK diagnostic frames; not transitive or runtime qualification."""
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_sdk_status as status
from windows_enclave_frame_geometry import Frame, Window

# Complete bodies manually inspected in the pinned saved DLL, not live code.
BODIES = {
    'retry': (0x16910,
        '488bc44889580848896810488970184889782041564883ec404c8b742470bb8000000081fb00020000'
        '498bf9418bf08bea0f92c04c8bcf88442438448bc6895c24308bd54c89742420e83e00000081fb0002'
        '000073123d05000080750b83eb8081fb0002000076c9488b5c2450488b6c2458488b742460488b7c24'
        '684883c440415ec3'),
    'buffer': (0x1699c,
        '4055565741544155415641574881ec10010000488d6c2420488b05851601004833c5488985e0000000'
        '4c894d184489450c8955084c8b8d50010000448bad600100000f57c00f11453065488b042530000000'
        '488945284c8da0ee1700004c896520410fb7042441bf020000004184c7740733c0e9a001000066410b'
        'c76641890424498d450f493bc5770a48b8f0ffffffffffff0f4883e0f0e8b7670000482be0488d7424'
        '20458d75ff83650000498d45ff33ff41ba0d0000c0483dfeffff7f410f47fa897d0085ff784933ff89'
        '7d044d8d7dff4c8b4518498bd7488bcee85abdfeff85c0780f4898493bc77708751241883c37eb0c41'
        '883c37bf05000080897d04897d008b5508448b450c41bf02000000eb084585ed7403c60600897d1080'
        'bd6801000000740c81ff050000800f84c500000081ff05000080750f418d45fec604300a41c6043600'
        'eb0e4983ceff49ffc642803c360075f648897538664489753065488b04256000000048837838007469'
        '65488b042560000000807802007515488b056d6001008a88d402000080e10380f903744533d241b898'
        '000000488d4d40e8ee840000c7454006000140488365480044897d5883654400410fb7c648ffc04889'
        '456048897568488d4d40e82251ffffeb224c8b6520eb1c488d4d30e881b0feff8bf83d03000080750c'
        'b901000000e85eb0feff33ffb8fdff000066412104248bc7eb12488b552841b8fdff000066442182ee'
        '170000488b8de00000004833cde85d620000488da5f0000000415f415e415d415c5f5e5dc3'),
    'probe': (0x1d1f0,
        '4883ec104c8914244c895c24084d33db4c8d5424184c2bd04d0f42d3654c8b1c25100000004d3bd3'
        '7315664181e200f04d8d9b00f0ffff45841b4d3bd372f14c8b14244c8b5c24084883c410c3'),
    'format_adapter': (0x27d8,'4883ec384c894c24204533c9e80b0000004883c438c3'),
    'format_wrapper': (0x27f4,
        '48895c240848897c241055488bec4883ec608365dc000f57c08365fc004d8bd1498bc0488bd9f30f7f'
        '45ec4d85c074614885d274124885c97457b9ffffff7f894dd8483bd177038955d84c8b4d30488d4dd0'
        '4d8bc2c745e842000000488bd048895de048895dd0e8080100008bf84885db741a836dd8017809488b'
        '4dd0c60100eb0b488d55d033c9e8d70000008bc7eb184883642420004533c94533c033d233c9e8bee7'
        'ffff83c8ff488b5c2470488b7c24784883c4605dc3'),
    'trap': (0x1bf0,'ccc3'),
    'debug_output': (0x1c00,'458bc8448bc2668b11488b4908b801000000cd2dccc3'),
    'cookie': (0x1ce20,'483b0d19b20000751048c1c11066f7c1ffff7501c348c1c910e92243feff'),
}
FORMATS = {
    0x20950: b'RTL: RtlNtStatusToDosError(0x%lx): No Valid Win32 Error Mapping\n\0',
    0x20998: b'RTL: Edit ntos\\rtl\\generr.c to correct the problem\n\0',
    0x209d0: b'RTL: ERROR_MR_MID_NOT_FOUND is being returned\n\0',
}
# Source, instruction RVA, opcode, target; unknown callees remain explicit.
EDGES = (
    ('retry',0x16959,0xe8,0x1699c),
    ('buffer',0x16a34,0xe8,0x1d1f0), ('buffer',0x16a79,0xe8,0x27d8),
    ('buffer',0x16b3d,0xe8,0x1f030), ('buffer',0x16b69,0xe8,0xbc90),
    ('buffer',0x16b7a,0xe8,0x1c00), ('buffer',0x16b8d,0xe8,0x1bf0),
    ('buffer',0x16bbe,0xe8,0x1ce20), ('format_adapter',0x27e4,0xe8,0x27f4),
    ('format_wrapper',0x285b,0xe8,0x2968), ('format_wrapper',0x287c,0xe8,0x2958),
    ('format_wrapper',0x2895,0xe8,0x1058), ('cookie',0x1ce39,0xe9,0x1160),
)
CAPACITIES = (128,256,384,512)


def extract(rows, rva, size, executable):
    matches = [r for r in rows if not r['flags'] & 0x80000000
               and bool(r['flags'] & 0x20000000) == executable
               and 0 <= rva-r['rva'] <= min(len(r['code']),r['virtual_size'])-size]
    status.sdk.require(len(matches) == 1, 'unique bounded diagnostic section')
    row = matches[0]
    return row['code'][rva-row['rva']:rva-row['rva']+size]


def check_bodies(bodies):
    status.sdk.require(set(bodies) == set(BODIES), 'complete diagnostic population')
    for name,(_,code) in BODIES.items():
        status.sdk.require(bodies[name] == bytes.fromhex(code), 'diagnostic body: '+name)


def check_edges():
    status.sdk.require(BODIES['retry'][0] == status.DEEP_DIAGNOSTIC_RVA,
                       'extension of existing diagnostic boundary')
    for source,instruction,opcode,target in EDGES:
        rva,code = BODIES[source]
        status.sdk.require(status.relative_target(rva,bytes.fromhex(code),instruction-rva,opcode)
                           == target, 'diagnostic transfer: '+source)


def geometry(window, capacity):
    # This is NOT a bound for arbitrary callers of the internal SDK function.
    status.sdk.require(type(capacity) is int and capacity in CAPACITIES,
                       'capacity from pinned retry caller')
    result = {}
    for path,prior in status.geometry(window)['paths'].items():
        retry = Frame.enter(window,window.high+prior['frames']['diagnostic_entry'],72)
        fixed = Frame.enter(window,retry.current,328)
        dynamic = Frame(window,fixed.entry,fixed.current-capacity)
        window.span('dynamic frame and home',dynamic.current,fixed.entry+40-dynamic.current)
        adapter = Frame.enter(window,dynamic.current,56)
        formatter = Frame.enter(window,adapter.current,104)
        spans = [retry.slot('retry home GPR saves',8,32,'entry'),
                 retry.slot('retry R14 push',-8,8,'entry'),
                 retry.slot('retry varargs pointer',32,8),
                 retry.slot('retry capacity and retry flag',48,9),
                 fixed.slot('buffer seven GPR pushes',-56,56,'entry'),
                 fixed.slot('buffer locals including format/thread pointers',32,48),
                 fixed.slot('output descriptor',80,16),
                 fixed.slot('exception record',96,152),
                 fixed.slot('security cookie',256,8),
                 dynamic.slot('diagnostic output buffer',32,capacity),
                 adapter.slot('formatter varargs pointer',32,8),
                 formatter.slot('formatter home GPR saves',8,16,'entry'),
                 formatter.slot('formatter RBP push',-8,8,'entry'),
                 formatter.slot('formatter locals',48,48),
                 # Probe's special ABI saves 16 bytes, with no aligned call frame.
                 window.span('probe R10/R11 saves and return',fixed.current-24,24)]
        result[path] = dict(capacity=capacity,frames={n:f.current-window.high for n,f in
            (('retry',retry),('buffer_fixed',fixed),('buffer_dynamic',dynamic),
             ('format_adapter',adapter),('format_wrapper',formatter))},spans=spans,
            unknown_callees=[formatter.unknown_callee('formatter/termination/invalid-argument entry'),
                             dynamic.unknown_callee('exception/memset/fatal-cookie entry')])
    return result


def inspect(data):
    previous = status.inspect(data)
    rows,_ = status.sdk.pe.linked(data)
    check_bodies({n:extract(rows,rva,len(bytes.fromhex(code)),True)
                  for n,(rva,code) in BODIES.items()})
    for rva,expected in FORMATS.items():
        status.sdk.require(extract(rows,rva,len(expected),False) == expected,
                           'fixed status diagnostic format')
    check_edges()
    return dict(schema=1,status='SAVED_SDK_DIAGNOSTIC_REVIEW_NOT_OS_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,probe_page_touches_bounded_by_window=False,
        thread_relative_storage_cleared_by_window=False,
        bodies={n:dict(rva=rva,bytes=len(bytes.fromhex(code)),
                       sha256=hashlib.sha256(bytes.fromhex(code)).hexdigest())
                for n,(rva,code) in BODIES.items()},
        formats={hex(rva):value[:-1].decode('ascii') for rva,value in FORMATS.items()},
        geometry={str(cap):geometry(Window(0,65536),cap) for cap in CAPACITIES},
        retry_is_sequential_not_recursive=True,buffer_full_wipe_in_body_observed=False,
        thread_relative_flag=dict(base='value at GS:0x30',offset=0x17ee,bytes=2,mask=2),
        unresolved=[dict(rva=rva,reason=reason) for rva,reason in (
            (0x2968,'format engine'),(0x2958,'format termination helper'),
            (0x1058,'invalid-argument path'),(0x1f030,'exception-record initialization helper'),
            (0xbc90,'exception dispatch'),(0x1160,'fatal cookie-failure path'))],
        residuals=['INT3/INT2D and exception/unwind behavior',
                   'GS stack-limit-dependent probe addresses',
                   'runtime loaded-module identity and kernel context storage'])


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1]).read_bytes()),indent=2))
