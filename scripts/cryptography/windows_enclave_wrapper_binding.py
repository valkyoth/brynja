"""Bind the concurrent MASM wrapper's COFF bytes to a linked AMD64 PE image.

Exact code match except enumerated REL32 call relocations; not an image loader,
signature verifier, callee audit, or proof of register/whole-image cleanup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

CALLS = {
    'PublicStackFrame': {'__chkstk', 'PublicStackAdmit', 'PublicStackBody',
                         'PublicStackFinish', 'PublicStackRestore'},
}


def require(ok, message):
    if not ok: raise ValueError('wrapper binding: ' + message)


def span(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, 'truncated span')
    return data[offset:offset + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, span(data, offset, struct.calcsize(fmt)))


def sections(data, offset, count):
    require(1 <= count <= 96, 'section count')
    result = []
    for index in range(count):
        row = span(data, offset + index * 40, 40)
        name = row[:8].rstrip(b'\0')
        virtual_size, rva, size, raw, relocs, _, nrelocs, _, flags = unpack('<IIIIIIHHI', row, 8)
        content = span(data, raw, size) if size else b''
        result.append(dict(name=name, virtual_size=virtual_size, rva=rva, raw=raw,
                           code=content, relocs=relocs, nrelocs=nrelocs, flags=flags))
    return result


def coff(data, entry):
    require(entry in CALLS and len(data) <= 64 * 1024 * 1024, 'entry/object bound')
    machine, count, _, table, number, optional, _ = unpack('<HHIIIHH', data, 0)
    require(machine == 0x8664 and optional == 0 and 0 < number <= 100000, 'AMD64 COFF required')
    rows = sections(data, 20, count)
    texts = [(i + 1, row) for i, row in enumerate(rows) if row['flags'] & 0x20000000 and row['code']]
    require(len(texts) == 1, 'exactly one nonempty executable object section')
    section_number, text = texts[0]
    code = text['code']
    require(0 < len(code) <= 4096 and text['flags'] & 0x20, 'bounded code section')
    raw_symbols = span(data, table, number * 18)
    string_offset = table + number * 18
    string_size, = unpack('<I', data, string_offset)
    require(string_size >= 4, 'string table size')
    strings = span(data, string_offset, string_size)
    symbols, index = {}, 0
    while index < number:
        raw = raw_symbols[index * 18:(index + 1) * 18]
        if raw[:4] == b'\0' * 4:
            offset, = unpack('<I', raw, 4)
            require(4 <= offset < len(strings), 'symbol name offset')
            end = strings.find(b'\0', offset)
            require(end != -1, 'terminated symbol name')
            name = strings[offset:end].decode('ascii')
        else:
            name = raw[:8].rstrip(b'\0').decode('ascii')
        value, section, kind, storage, aux = unpack('<IhHBB', raw, 8)
        require(index + aux < number, 'auxiliary symbols')
        symbols[index] = (name, value, section, kind, storage)
        index += 1 + aux
    entries = [s for s in symbols.values() if s[0] == entry]
    require(entries == [(entry, 0, section_number, 0x20, 2)], 'exact wrapper function at section start')
    require(text['nrelocs'] == len(CALLS[entry]), 'exact relocation count')
    calls = []
    for index in range(text['nrelocs']):
        offset, symbol, kind = unpack('<IIH', data, text['relocs'] + index * 10)
        require(symbol in symbols, 'relocation symbol')
        name, value, section, _, storage = symbols[symbol]
        require(kind == 4 and section == value == 0 and storage == 2 and name in CALLS[entry],
                'only reviewed external REL32 calls')
        require(offset > 0 and span(code, offset - 1, 5) == b'\xe8\0\0\0\0', 'call encoding')
        calls.append((offset, name))
    calls.sort()
    require({name for _, name in calls} == CALLS[entry], 'complete call identities')
    require(all(b[0] >= a[0] + 5 for a, b in zip(calls, calls[1:])), 'overlapping relocations')
    return code, calls


def linked(data):
    require(len(data) <= 64 * 1024 * 1024 and data[:2] == b'MZ', 'bounded DOS image')
    pe, = unpack('<I', data, 0x3c)
    require(span(data, pe, 4) == b'PE\0\0', 'PE signature')
    machine, count, _, _, _, optional_size, _ = unpack('<HHIIIHH', data, pe + 4)
    optional = span(data, pe + 24, optional_size)
    require(machine == 0x8664 and unpack('<H', optional, 0)[0] == 0x20b, 'AMD64 PE32+')
    require(unpack('<I', optional, 108)[0] >= 4, 'exception directory present')
    pdata, size = unpack('<II', optional, 112 + 3 * 8)
    require(size > 0 and size % 12 == 0, 'runtime function table')
    rows = sections(data, pe + 24 + optional_size, count)
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            extent_a, extent_b = max(len(a['code']), a['virtual_size']), max(len(b['code']), b['virtual_size'])
            require(a['rva'] + extent_a <= b['rva'] or b['rva'] + extent_b <= a['rva'], 'overlapping section RVAs')
            if a['code'] and b['code']:
                require(a['raw'] + len(a['code']) <= b['raw'] or b['raw'] + len(b['code']) <= a['raw'],
                        'overlapping section file spans')
    tables = [r['code'][pdata - r['rva']:pdata - r['rva'] + size] for r in rows
              if 0 <= pdata - r['rva'] and size <= len(r['code']) - (pdata - r['rva'])]
    require(len(tables) == 1, 'mapped exception directory')
    functions = [unpack('<III', tables[0], offset) for offset in range(0, size, 12)]
    executable = [r for r in rows if r['flags'] & 0x20000000 and r['code']]
    require(bool(executable), 'executable sections')
    return executable, functions


def bind(obj, image, entry):
    code, calls = coff(obj, entry)
    parts, cursor = [], 0
    for offset, _ in calls:
        parts += [re.escape(code[cursor:offset]), b'.{4}']
        cursor = offset + 4
    parts.append(re.escape(code[cursor:]))
    pattern = re.compile(b''.join(parts), re.DOTALL)
    executable, functions = linked(image)
    matches = [(row, match.start()) for row in executable
               for match in re.finditer(b'(?=(' + pattern.pattern + b'))', row['code'], re.DOTALL)]
    require(len(matches) == 1, 'wrapper absent or ambiguous in executable image')
    row, offset = matches[0]
    start, end = row['rva'] + offset, row['rva'] + offset + len(code)
    require(len([f for f in functions if f[0] == start and f[1] == end]) == 1,
            'exact linked wrapper function extent')
    targets = {}
    for relocation, name in calls:
        delta, = unpack('<i', row['code'], offset + relocation)
        target = start + relocation + 4 + delta
        require(any(r['rva'] <= target < r['rva'] + min(len(r['code']), r['virtual_size'])
                    for r in executable), 'call target outside executable image')
        require(not start <= target < end, 'call target inside wrapper')
        targets[name] = target
    require(len(set(targets.values())) == len(targets), 'aliased wrapper callees')
    return dict(status='EXACT_WRAPPER_BYTES_BOUND', entry=entry, rva=start, size=len(code),
                call_target_rvas=targets, callees_semantically_qualified=False,
                whole_image_qualified=False, object_sha256=hashlib.sha256(obj).hexdigest(),
                image_sha256=hashlib.sha256(image).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object', type=Path)
    parser.add_argument('image', type=Path)
    parser.add_argument('entry', choices=CALLS)
    args = parser.parse_args()
    print(json.dumps(bind(args.object.read_bytes(), args.image.read_bytes(), args.entry), indent=2))
