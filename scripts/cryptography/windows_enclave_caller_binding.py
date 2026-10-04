"""Bind selected single-section AMD64 COFF callers to a saved PE image.

Review aid only: exact bytes plus enumerated REL32 references and runtime extent.
No callee semantics, data-flow, signature, stack-depth or cleanup qualification.
Unsupported layouts fail rather than using disassembler names as identity proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

import windows_enclave_wrapper_binding as pe
import windows_enclave_caller_unwind as unwind


def require(ok, message):
    if not ok: raise ValueError('caller binding: ' + message)


def function(data, entry):
    require(0 < len(data) <= 64 * 1024 * 1024, 'bounded COFF')
    machine, count, _, table, number, optional, _ = pe.unpack('<HHIIIHH', data, 0)
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096
            and 0 < number <= 100000, 'bounded ordinary AMD64 COFF')
    rows = [pe.sections(data, 20 + i * 40, 1)[0] for i in range(count)]
    raw = pe.span(data, table, number * 18)
    strings_at = table + number * 18
    length, = pe.unpack('<I', data, strings_at)
    require(4 <= length <= 8 * 1024 * 1024, 'bounded symbol strings')
    strings = pe.span(data, strings_at, length)
    symbols, index = {}, 0
    while index < number:
        item = raw[index * 18:(index + 1) * 18]
        if item[:4] == bytes(4):
            offset, = pe.unpack('<I', item, 4)
            require(4 <= offset < len(strings), 'symbol offset')
            end = strings.find(b'\0', offset)
            require(end != -1, 'terminated symbol')
            name = strings[offset:end].decode('ascii')
        else: name = item[:8].rstrip(b'\0').decode('ascii')
        value, section, kind, storage, aux = pe.unpack('<IhHBB', item, 8)
        require(index + aux < number, 'bounded auxiliary symbols')
        symbols[index] = dict(name=name, value=value, section=section, kind=kind, storage=storage)
        index += 1 + aux
    selected = [s for s in symbols.values() if s['name'] == entry]
    require(len(selected) == 1 and selected[0]['kind'] == 0x20
            and selected[0]['value'] == 0 and selected[0]['storage'] in (2, 3)
            and 1 <= selected[0]['section'] <= count, 'unique function at section start')
    section = selected[0]['section']
    require(len([s for s in symbols.values() if s['section'] == section and s['kind'] == 0x20]) == 1,
            'single function in section')
    row = rows[section - 1]
    code = row['code']
    require(row['flags'] & 0x20000020 == 0x20000020 and not row['flags'] & 0x80000000
            and 0 < len(code) <= 65536 and row['nrelocs'] <= 4096, 'bounded nonwritable executable caller')
    refs = []
    for i in range(row['nrelocs']):
        place, symbol, kind = pe.unpack('<IIH', data, row['relocs'] + i * 10)
        require(symbol in symbols and 4 <= kind <= 9 and 0 <= place <= len(code) - 4,
                'only bounded REL32 through REL32_5 references')
        addend, = pe.unpack('<i', code, place)
        refs.append(dict(offset=place, symbol=symbols[symbol]['name'], trailing=kind - 4, addend=addend))
    refs.sort(key=lambda ref: ref['offset'])
    require(all(a['offset'] + 4 <= b['offset'] for a, b in zip(refs, refs[1:])), 'nonoverlapping references')
    return code, refs


def bind(obj, image, entry):
    code, refs = function(obj, entry)
    rows, functions = pe.linked(image)
    parts, cursor = [], 0
    for ref in refs:
        place = ref['offset']
        parts += [re.escape(code[cursor:place]), b'.{4}']
        cursor = place + 4
    parts.append(re.escape(code[cursor:]))
    pattern = b'(?=(' + b''.join(parts) + b'))'
    found = [(r, m.start()) for r in rows if r['flags'] & 0x20000000
             for m in re.finditer(pattern, r['code'], re.DOTALL)]
    require(len(found) == 1, 'caller bytes absent or ambiguous')
    row, offset = found[0]
    require(not row['flags'] & 0x80000000 and offset + len(code) <= row['virtual_size'],
            'caller within nonwritable mapped code')
    start = row['rva'] + offset
    frames = unwind.extent(rows, functions, start, len(code))
    targets, references = {}, []
    for ref in refs:
        place = ref['offset']
        delta, = pe.unpack('<i', row['code'], offset + place)
        target = start + place + 4 + ref['trailing'] + delta
        symbol = target - ref['addend']
        require(any(r['rva'] <= target < r['rva'] + (min(len(r['code']), r['virtual_size'])
                    if r['flags'] & 0x20000000 else r['virtual_size']) for r in rows),
                'reference outside image code/data')
        require(ref['symbol'] not in targets or targets[ref['symbol']] == symbol,
                'inconsistent symbol references')
        targets[ref['symbol']] = symbol
        references.append(ref | dict(target_rva=target, symbol_rva=symbol))
    return dict(entry=entry, rva=start, size=len(code), reference_targets=targets, references=references, unwind=frames,
                object_sha256=hashlib.sha256(obj).hexdigest(), image_sha256=hashlib.sha256(image).hexdigest(),
                whole_image_qualified=False, callee_semantics_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object', type=Path)
    parser.add_argument('image', type=Path)
    parser.add_argument('entry')
    args = parser.parse_args()
    print(json.dumps(bind(args.object.read_bytes(), args.image.read_bytes(), args.entry), indent=2))
