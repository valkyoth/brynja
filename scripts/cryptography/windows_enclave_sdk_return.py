"""Reconcile the saved root's SDK import/return chain; not runtime attestation."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_root_return as root
import windows_enclave_sdk_dispatch_helpers as sdk_review
import windows_enclave_sdk_status as status
from windows_enclave_frame_geometry import Window, scheduler, require

pe = root.caller.pe
mapped = root.slot.binding.mapped
SYMBOL = 'EnclaveCopyOutOfEnclave'


def directory(data, index):
    offset, = pe.unpack('<I', data, 0x3c)
    optional_size, = pe.unpack('<H', data, offset+20)
    optional = pe.span(data, offset+24, optional_size)
    count, = pe.unpack('<I', optional, 108)
    require(0 <= index < count <= 16, 'bounded directory index')
    rva, size = pe.unpack('<II', optional, 112+8*index)
    require(rva > 0 and 0 < size <= 65536, 'bounded nonempty directory')
    return rva, size


def string(rows, rva):
    found = [r for r in rows if r['rva'] <= rva < r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(found) == 1, 'unique string storage')
    row = found[0]
    length = min(256, min(len(row['code']),row['virtual_size'])-(rva-row['rva']))
    raw = mapped(rows,rva,length)
    end = raw.find(b'\0')
    require(0 < end < 256 and all(32 <= b <= 126 for b in raw[:end]), 'bounded ASCII identity')
    return raw[:end].decode('ascii')


def imports(data):
    rows,_ = pe.linked(data)
    rva,size = directory(data,1)
    require(size % 20 == 0 and size <= 20*65, 'bounded import descriptors')
    descriptors = mapped(rows,rva,size)
    result = {}
    for offset in range(0,size,20):
        lookup,stamp,forward,name,iat = pe.unpack('<IIIII',descriptors,offset)
        if not any((lookup,stamp,forward,name,iat)):
            require(not any(descriptors[offset:]), 'terminal import descriptor')
            return result
        require(lookup and iat and stamp == forward == 0, 'unbound named import descriptor')
        module = string(rows,name)
        require(module not in result, 'unique imported library')
        symbols = {}
        for index in range(256):
            field = lookup+index*8
            item, = pe.unpack('<Q',mapped(rows,field,8),0)
            initial, = pe.unpack('<Q',mapped(rows,iat+index*8,8),0)
            require(initial == item, 'saved unbound IAT matches lookup')
            if item == 0: break
            require(item < 1 << 32, 'named nonordinal import')
            mapped(rows,item,2)  # hint, not the symbol identity
            symbol = string(rows,item+2)
            require(symbol not in symbols, 'unique imported symbol')
            symbols[symbol] = iat+index*8
        else: raise ValueError('SDK return: unterminated import table')
        result[module] = symbols
    raise ValueError('SDK return: missing descriptor terminator')


def export(data, symbol):
    rows,_ = pe.linked(data)
    rva,size = directory(data,0)
    header = mapped(rows,rva,40)
    _,_,_,_,name,_,functions,names,addresses,name_ptrs,ordinals = pe.unpack('<IIHHIIIIIII',header,0)
    require(string(rows,name).lower() == 'vertdll.dll', 'saved SDK export module identity')
    require(0 < names <= functions <= 8192, 'bounded export population')
    funcs = mapped(rows,addresses,functions*4)
    pointers = mapped(rows,name_ptrs,names*4)
    indexes = mapped(rows,ordinals,names*2)
    found,seen = [],set()
    for index in range(names):
        pointer, = pe.unpack('<I',pointers,index*4)
        text = string(rows,pointer)
        require(text not in seen, 'unique named export')
        seen.add(text)
        ordinal, = pe.unpack('<H',indexes,index*2)
        require(ordinal < functions, 'bounded export ordinal')
        if text == symbol:
            target, = pe.unpack('<I',funcs,ordinal*4)
            require(not rva <= target < rva+size, 'no forwarded selected SDK export')
            code = [r for r in rows if r['rva'] <= target < r['rva']+min(len(r['code']),r['virtual_size'])]
            require(len(code) == 1 and code[0]['flags'] & 0xa0000020 == 0x20000020,
                    'selected export in nonwritable code')
            found.append(target)
    require(len(found) == 1, 'unique selected SDK export')
    return found[0]


def thunk(rows, functions, rva, expected):
    code = mapped(rows,rva,6)
    owners = [r for r in rows if r['rva'] <= rva and
              rva+6 <= r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(owners) == 1 and owners[0]['flags'] & 0xa0000020 == 0x20000020,
            'nonwritable executable import thunk')
    require(code[:2] == b'\xff\x25', 'complete RIP-relative import tail jump')
    require(rva+6+int.from_bytes(code[2:],'little',signed=True) == expected, 'exact named import slot')
    require(not any(a < rva+6 and rva < b for a,b,_ in functions), 'no overlapping thunk unwind record')
    return code.hex()


def copy_edges():
    rva,body = status.sdk.BODIES[SYMBOL]
    code = bytes.fromhex(body)
    require(code[:7] == bytes.fromhex('4883ec284533c9'), 'outbound copy flag and fixed frame')
    require(status.relative_target(rva,code,7,0xe8) == status.sdk.BODIES['copy_syscall_stub'][0],
            'copy syscall edge')
    require(code[12:18] == bytes.fromhex('8bc84883c428'), 'status handoff and restored copy frame')
    require(status.relative_target(rva,code,18,0xe9) == status.BODIES['copy_status'][0],
            'copy status tail edge')
    status.check_edges()


def inspect(data,native,image,sdk):
    previous = root.inspect(data,native,image)
    reviewed = sdk_review.inspect(sdk)
    table = imports(image)
    require(set(table) == {'vertdll.dll','ucrtbase_enclave.dll'}, 'original scheduler import closure')
    require(SYMBOL in table['vertdll.dll'], 'output import present')
    slot = table['vertdll.dll'][SYMBOL]
    require(slot == 0xd0a8, 'reviewed output IAT slot')
    address = previous['sdk_output_target_rva']
    rows,functions = pe.linked(image)
    code = thunk(rows,functions,address,slot)
    target = export(sdk,SYMBOL)
    require(target == status.sdk.BODIES[SYMBOL][0], 'reviewed SDK implementation identity')
    copy_edges()
    window = Window(0,65536)
    geometry = status.sdk.geometry(window)
    status_geometry = status.geometry(window)['paths']['copy']
    return dict(schema=1,date='2026-10-05',status='SAVED_ROOT_SDK_OUTPUT_RETURN_RECONCILIATION',
        object_sha256=previous['object_sha256'],native_object_sha256=previous['native_object_sha256'],
        image_sha256=previous['image_sha256'],sdk_sha256=reviewed['image_sha256'],
        root_rva=previous['entries']['root']['rva'],adapter_rva=previous['entries']['output']['rva'],
        import_module='vertdll.dll',import_symbol=SYMBOL,iat_rva=slot,thunk_rva=address,thunk_hex=code,
        saved_export_rva=target,copy_syscall_rva=status.sdk.BODIES['copy_syscall_stub'][0],
        copy_status_rva=status.BODIES['copy_status'][0],
        root_frame_from_high=scheduler(window)['frames']['root']['current_from_high'],
        output_adapter_frame_from_high=scheduler(window)['frames']['copy_adapter']['current_from_high'],
        sdk_copy_frame_from_high=geometry['copy_frame_from_high'],status_geometry=status_geometry,
        sdk_review_unresolved=reviewed['unresolved'],sdk_review_residuals=reviewed['residuals'],
        saved_import_export_chain_reconciled=True,loaded_application_iat_proven=False,
        loaded_module_identity_proven=False,kernel_storage_qualified=False,sdk_self_erasure_claimed=False,
        public_output_transactional=False,maximum_transitive_depth_qualified=False,
        native_run_added=False,whole_image_qualified=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('object','native_object','image','sdk'): parser.add_argument(name,type=Path)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    result = inspect(*(getattr(args,n).read_bytes() for n in ('object','native_object','image','sdk')))
    names = ('windows_enclave_sdk_return.py','test-windows-enclave-sdk-return.py',
             'windows_enclave_root_return.py','windows_enclave_frame_geometry.py',
             'windows_enclave_wrapper_binding.py')
    # Bind all previously selected SDK review modules, not only the outer driver.
    paths = {Path(__file__).with_name(n) for n in names}
    paths.update(Path(__file__).parent.glob('windows_enclave_sdk_*.py'))
    result['source_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
