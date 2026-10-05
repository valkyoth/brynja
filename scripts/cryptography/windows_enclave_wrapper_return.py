"""Saved scheduler wrapper handoff; no arbitrary unwind or whole-image claim."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_return as sdk_return
from windows_enclave_frame_geometry import Window, require

root = sdk_return.root
pe = root.caller.pe
WRAPPER_OBJECT = 'b9f10f1a6c18de9cfb64859eb4248b8b562299aa964d9494789f923acf99dc7b'
BODIES = {
    'wrapper': ('PublicStackFrame',402,'40c136db6a38a23ad2576fc29427ce6e93c99805746b5f1519eacbd49fe90a53'),
    'body': ('PublicStackBody',340,'ed5351c7e8bc12399d48e07646696249a1632026c2c8a6ac710923c18ab83f2c'),
    'finish': ('PublicStackFinish',110,'74935e78712bded3ce47cbea29765848837efcf67212f55830c41515eecbc463'),
    'restore': ('PublicStackRestore',186,'3c587ee8091fffc479512d3f78f79bd3f8f187acf49448dc74e33c676212d66d'),
}
REFERENCES = {
    'wrapper':'1a855b17bc0656f27ba8c286a2ba9cdcd85c2edbd98d6fc52f731e0c9757e34a',
    'body':'f0875504946b0385c20386ced2b5fe90d8991684b2f94d7f328772232f10bc6f',
    'finish':'fc4937ad72c85ff212a1ce9824a145aaad5b1f32af2a979fca1eb82fe18c7a63',
    'restore':'4e2a405be4e8a9091a8151166ba4b1364f51a329f94931b88a339e8a8364bbc3',
}
COOKIE = bytes.fromhex('483b0dd98a0000751048c1c11066f7c1ffff7501c348c1c910e9c2030000')
ANCHORS = (
    ('body',0xf8,'488b0d00000000e800000000'),
    ('body',0x12d,'33c0'), ('body',0x12f,'488b8c24900000004833cce800000000'),
    ('body',0x13f,'4c8d9c24a0000000498b5b18498b7320498be35fc3'),
    ('wrapper',0xaa,'488d62e0e8000000004c8bc0'),
    ('wrapper',0xb8,'49c7c0ffffffff'),
    ('wrapper',0xbf,'48837d20007403c5f877'),
    ('wrapper',0xc9,'660fefc0660fefc9660fefd2660fefdb660fefe4660fefed'),
    ('wrapper',0xe1,'33c033c933d24533c94533d24533db'),
    ('wrapper',0xf0,'4c8b5d104d8b13498da2e0efffff498b530833c0'),
    ('wrapper',0x104,'4989024983c2084c3bd2'),
    ('wrapper',0x110,'4d8b134533c94d0b0a4983c2084c3bd2'),
    ('wrapper',0x122,'4d85c9'), ('wrapper',0x127,'498bcb498bd0e800000000'),
    ('wrapper',0x134,'48c7c0ffffffff'),
    ('wrapper',0x13b,'48894518488b4d10e8000000004885c0'),
    ('wrapper',0x14d,'488b4518'), ('wrapper',0x153,'48c7c0ffffffff'),
    ('wrapper',0x15a,'48837d20007403c5f877'),
    ('wrapper',0x164,'660fefc0660fefc9660fefd2660fefdb660fefe4660fefed'),
    ('wrapper',0x17c,'33c933d24533c04533c94533d24533db488d65005dc3'),
    ('finish',0x16,'895934488bfa48c744243000000000'),
    ('finish',0x4d,'48395c2430'),
    ('finish',0x54,'33db85db48c7c0ffffffff488b5c2438480f45c74883c4205fc3'),
    ('restore',0x3f,'c7432c00000000'), ('restore',0x6e,'c7432800000000'),
    ('restore',0xa3,'33ff488b742440897b38488b5c24388bc74883c4205fc3'),
)
BRANCHES = (
    ('body',0x104,b'\xeb',0x12f),('body',0x120,b'\xeb',0x12f),
    ('wrapper',0x84,b'\x74',0xb8),('wrapper',0xb6,b'\xeb',0xbf),
    ('wrapper',0xc4,b'\x74',0xc9),('wrapper',0x10e,b'\x72',0x104),
    ('wrapper',0x120,b'\x72',0x116),('wrapper',0x125,b'\x75',0x134),
    ('wrapper',0x132,b'\xeb',0x13b),('wrapper',0x14b,b'\x74',0x153),
    ('wrapper',0x151,b'\xeb',0x15a),('wrapper',0x15f,b'\x74',0x164),
    ('finish',0x28,b'\x74',0x54),('finish',0x4b,b'\x74',0x54),('finish',0x52,b'\x74',0x56),
    ('restore',0x1d,b'\x74',0x46),('restore',0x39,b'\x75',0x3f),('restore',0x3d,b'\xeb',0x46),
    ('restore',0x4a,b'\x74',0x75),('restore',0x6c,b'\x74',0xa3),('restore',0x77,b'\x74',0xa3),
    ('restore',0x8f,b'\x74',0xa3),('restore',0xa1,b'\x75',0xa5),
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'wrapper-return body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'wrapper-return body: '+name)


def check_references(refs):
    require(set(refs) == set(REFERENCES),'wrapper-return reference population')
    for name,rows in refs.items():
        raw = json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
        require(hashlib.sha256(raw).hexdigest() == REFERENCES[name],'wrapper-return relocation identity')


def check_instructions(bodies):
    require(set(bodies) == set(BODIES),'wrapper-return instruction population')
    for name,offset,hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code,'wrapper-return instruction landmark')
    for name,offset,opcode,target in BRANCHES:
        require(bodies[name][offset:offset+1] == opcode and
                offset+2+int.from_bytes(bodies[name][offset+1:offset+2],'little',signed=True) == target,
                'wrapper-return branch')


def cookie_check(rows, functions, record):
    address = record['reference_targets']['__security_check_cookie']
    require(address == 0x8520 and root.slot.binding.mapped(rows,address,len(COOKIE)) == COOKIE,
            'complete saved cookie checker')
    extents = [f for f in functions if f[0] < address+len(COOKIE) and address < f[1]]
    require(len(extents) == 1 and extents[0][:2] == (address,address+len(COOKIE)) and
            root.slot.binding.mapped(rows,extents[0][2],4) == b'\x01\0\0\0',
            'exact cookie extent and zero-frame metadata')
    # Both conditional failures skip the sole RET; they do not reach reclamation.
    require(address+7+int.from_bytes(COOKIE[3:7],'little',signed=True) ==
            record['reference_targets']['__security_cookie'],'same public stack cookie')
    return dict(rva=address,bytes=len(COOKIE),normal_return_offset=20,fatal_tail_rva=0x8900,
                normal_path_preserves_rax=True,secret_payload_processed=False,failure_cleanup_qualified=False)


def geometry(window):
    # The saved wrapper derives a 64-KiB aligned range and uses eight-byte loops.
    spans = [window.span('clear/readback word',address,8) for address in range(window.low,window.high,8)]
    return dict(words=len(spans),bytes=sum(s['bytes'] for s in spans),first=spans[0],last=spans[-1],
                callback_rsp_from_low=-4128,callback_stack_inside_cleared_window=False,
                runtime_placement_measured=False)


def inspect(data,native,image,wrapper,mutate=False):
    previous = root.inspect(data,native,image)
    require(hashlib.sha256(wrapper).hexdigest() == WRAPPER_OBJECT,'tested wrapper object')
    selected = {n:root.caller.function(wrapper if n == 'wrapper' else native,s[0]) for n,s in BODIES.items()}
    bodies,refs = {n:v[0] for n,v in selected.items()},{n:v[1] for n,v in selected.items()}
    check_bodies(bodies); check_references(refs); check_instructions(bodies)
    records = {n:root.slot.binding.bind(native,image,BODIES[n][0]) for n in ('body','finish','restore')}
    records['wrapper'] = pe.bind(wrapper,image,'PublicStackFrame')
    for name in ('body','finish','restore'):
        require(records['wrapper']['call_target_rvas'][BODIES[name][0]] == records[name]['rva'],
                'same linked wrapper callee')
    require(records['body']['reference_targets']['PrivateWaveRoot'] == previous['entries']['root']['rva'],
            'same reviewed root')
    imports = sdk_return.imports(image)['vertdll.dll']
    require(records['finish']['reference_targets']['__imp_CallEnclave'] == imports['CallEnclave'] and
            records['restore']['reference_targets']['__imp_VirtualProtect'] == imports['VirtualProtect'],
            'same named post-clear SDK imports')
    rows,functions = pe.linked(image)
    cookie = cookie_check(rows,functions,records['body'])
    count = 0
    if mutate:
        for name,code in bodies.items():
            for index in range(len(code)):
                changed = bytearray(code); changed[index] ^= 1
                try: check_bodies(bodies | {name:bytes(changed)})
                except ValueError: count += 1
                else: raise AssertionError('accepted wrapper-return body mutation')
    return dict(schema=1,date='2026-10-05',status='SAVED_NORMAL_RETURN_CLEARING_WRAPPER_HANDOFF',
                object_sha256=previous['object_sha256'],native_object_sha256=previous['native_object_sha256'],
                image_sha256=previous['image_sha256'],wrapper_object_sha256=WRAPPER_OBJECT,
                entries=records,cookie=cookie,geometry=geometry(Window(0,65536)),
                body_byte_mutations_rejected=count,instruction_landmarks=len(ANCHORS),
                branch_landmarks=len(BRANCHES),normal_order=['root returns public result',
                    'body cookie check and ABI restore','pre-callback volatile register clear',
                    'whole-window clear and readback','finish callback only if readback clean',
                    'guard restoration attempt','final volatile register clear','wrapper returns public result'],
                nonvolatile_xmm_low_halves_preserved=True,callback_payload_is_public=True,
                callback_sdk_and_page_helper_semantics_qualified=False,
                arbitrary_exception_cleanup_qualified=False,whole_image_qualified=False,
                native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('object','native_object','image','wrapper'): parser.add_argument(name,type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    result = inspect(*(getattr(args,n).read_bytes() for n in ('object','native_object','image','wrapper')),args.mutate)
    sources = ('windows_enclave_wrapper_return.py','test-windows-enclave-wrapper-return.py',
               'windows_enclave_sdk_return.py','windows_enclave_root_return.py',
               'windows_enclave_wrapper_binding.py','windows_enclave_caller_handlers.py',
               'windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
