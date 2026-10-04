"""Bounded COFF function extents from actual .pdata, including interior funclets.

Inspection support only. Does not interpret exception handlers or prove cleanup.
"""
import windows_enclave_wrapper_binding as pe


def require(ok, message):
    if not ok: raise ValueError('caller object: ' + message)


def tables(data):
    require(0 < len(data) <= 64 * 1024 * 1024, 'bounded object')
    machine, count, _, table, number, optional, _ = pe.unpack('<HHIIIHH', data, 0)
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096
            and 0 < number <= 100000, 'ordinary AMD64 COFF')
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
            require(4 <= offset < len(strings), 'symbol string offset')
            end = strings.find(b'\0', offset)
            require(end != -1, 'terminated symbol string')
            name = strings[offset:end].decode('ascii')
        else: name = item[:8].rstrip(b'\0').decode('ascii')
        value, section, kind, storage, aux = pe.unpack('<IhHBB', item, 8)
        require(index + aux < number, 'auxiliary symbol bound')
        symbols[index] = dict(name=name, value=value, section=section, kind=kind, storage=storage)
        index += 1 + aux
    return rows, symbols


def relocations(data, row, symbols):
    require(row['nrelocs'] <= 4096 and not row['flags'] & 0x01000000, 'bounded direct relocations')
    result = {}
    for index in range(row['nrelocs']):
        place, symbol, kind = pe.unpack('<IIH', data, row['relocs'] + index * 10)
        require(symbol in symbols and place <= len(row['code']) - 4 and place not in result,
                'bounded unique relocation')
        result[place] = dict(symbol=symbol, kind=kind)
    places = sorted(result)
    require(all(a + 4 <= b for a, b in zip(places, places[1:])), 'disjoint relocation fields')
    return result


def address(row, offset, refs, rows, symbols):
    require(offset in refs and refs[offset]['kind'] == 3, 'ADDR32NB metadata reference')
    symbol = symbols[refs[offset]['symbol']]
    require(1 <= symbol['section'] <= len(rows), 'defined metadata reference')
    addend, = pe.unpack('<I', row['code'], offset)
    value = symbol['value'] + addend
    require(value <= len(rows[symbol['section'] - 1]['code']), 'metadata reference extent')
    return symbol['section'], value


def ranges(data, rows, symbols):
    result = []
    for row in rows:
        if row['name'] != b'.pdata': continue
        require(len(row['code']) % 12 == 0, 'runtime table stride')
        refs = relocations(data, row, symbols)
        require(set(refs) == set(range(0, len(row['code']), 4)), 'complete runtime relocations')
        for offset in range(0, len(row['code']), 12):
            start = address(row, offset, refs, rows, symbols)
            end = address(row, offset + 4, refs, rows, symbols)
            info = address(row, offset + 8, refs, rows, symbols)
            require(start[0] == end[0] and start[1] < end[1], 'single-section runtime extent')
            result.append(dict(section=start[0], start=start[1], end=end[1], info=info))
    require(bool(result), 'runtime entries required')
    return result


def select(data, entry):
    rows, symbols = tables(data)
    named = [s for s in symbols.values() if s['name'] == entry]
    require(len(named) == 1 and named[0]['kind'] == 0x20 and named[0]['storage'] in (2, 3),
            'unique actual COFF function symbol')
    symbol = named[0]
    require(1 <= symbol['section'] <= len(rows), 'defined function')
    entries = ranges(data, rows, symbols)
    selected = [r for r in entries if r['section'] == symbol['section'] and r['start'] == symbol['value']]
    require(len(selected) == 1, 'one object runtime entry per selected function')
    selected = selected[0]
    start, end = selected['start'], selected['end']
    require(len([r for r in entries if r['section'] == symbol['section']
                 and r['start'] < end and start < r['end']]) == 1, 'nonoverlapping runtime ranges')
    require(len([s for s in symbols.values() if s['section'] == symbol['section']
                 and s['kind'] == 0x20 and start <= s['value'] < end]) == 1, 'unaliased function range')
    row = rows[symbol['section'] - 1]
    require(row['flags'] & 0xa0000020 == 0x20000020 and 0 < end - start <= 65536,
            'bounded nonwritable executable range')
    refs = []
    for place, ref in relocations(data, row, symbols).items():
        if place + 4 <= start or place >= end: continue
        require(start <= place and place + 4 <= end and 4 <= ref['kind'] <= 9,
                'bounded REL32 function reference')
        addend, = pe.unpack('<i', row['code'], place)
        refs.append(dict(offset=place-start, symbol=symbols[ref['symbol']]['name'],
                         symbol_index=ref['symbol'], trailing=ref['kind']-4, addend=addend))
    return rows, symbols, selected, row['code'][start:end], sorted(refs, key=lambda r: r['offset'])
