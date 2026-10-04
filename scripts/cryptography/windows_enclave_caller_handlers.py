"""Object-range and handler-metadata identity review, NOT handler qualification.

Matches function bytes and complete associated xdata with enumerated relocations.
Optional incoming references disambiguate byte-identical code shapes. Callers must
have already verified those reference records against this exact image.
"""
import hashlib
import re

import windows_enclave_caller_object as obj
import windows_enclave_wrapper_binding as pe


def require(ok, message):
    if not ok: raise ValueError('caller handlers: ' + message)


def mapped(rows, rva, length):
    found = [(r, rva-r['rva']) for r in rows if r['rva'] <= rva
             and 0 <= length <= min(len(r['code']), r['virtual_size']) - (rva-r['rva'])]
    require(len(found) == 1, 'uniquely mapped bytes')
    row, offset = found[0]
    return row['code'][offset:offset+length]


def executable(rows, rva):
    return any(r['flags'] & 0xa0000020 == 0x20000020 and r['rva'] <= rva
               < r['rva'] + min(len(r['code']), r['virtual_size']) for r in rows)


def exact(left, right, offsets):
    require(len(left) == len(right), 'exact byte extent')
    cursor = 0
    for offset in sorted(offsets):
        require(cursor <= offset <= len(left)-4, 'disjoint bounded masked fields')
        require(left[cursor:offset] == right[cursor:offset], 'nonrelocated bytes differ')
        cursor = offset + 4
    require(left[cursor:] == right[cursor:], 'nonrelocated bytes differ')


def bind(data, image, entry, anchors=()):
    rows, symbols, selected, code, refs = obj.select(data, entry)
    linked, functions = pe.linked(image)
    parts, cursor = [], 0
    for ref in refs:
        place = ref['offset']
        parts += [re.escape(code[cursor:place]), b'.{4}']
        cursor = place + 4
    parts.append(re.escape(code[cursor:]))
    pattern = b'(?=(' + b''.join(parts) + b'))'
    matches = [row['rva']+m.start() for row in linked if row['flags'] & 0xa0000020 == 0x20000020
               for m in re.finditer(pattern, row['code'][:row['virtual_size']], re.DOTALL)]
    image_hash = hashlib.sha256(image).hexdigest()
    incoming = []
    for anchor in anchors:
        require(anchor['image_sha256'] == image_hash, 'incoming reference image identity')
        if entry in anchor['reference_targets']:
            incoming.append(dict(caller=anchor['entry'], rva=anchor['reference_targets'][entry]))
    require(len({r['rva'] for r in incoming}) <= 1, 'incoming reference agreement')
    candidates = [r for r in matches if not incoming or r == incoming[0]['rva']]
    require(len(candidates) == 1, 'one caller candidate after reference constraints')
    start = candidates[0]
    runtime = [f for f in functions if f[0] < start+len(code) and start < f[1]]
    require(len(runtime) == 1 and runtime[0][:2] == (start, start+len(code)), 'exact single runtime extent')
    _, _, info_rva = runtime[0]
    linked_code = mapped(linked, start, len(code))
    targets = {}
    for ref in refs:
        delta, = pe.unpack('<i', linked_code, ref['offset'])
        target = start + ref['offset'] + 4 + ref['trailing'] + delta - ref['addend']
        require(any(r['rva'] <= target < r['rva'] + r['virtual_size'] for r in linked), 'in-image reference')
        require(ref['symbol'] not in targets or targets[ref['symbol']] == target, 'consistent code references')
        targets[ref['symbol']] = target
    # Bind the entire object's associated xdata section, not just its header.
    info_section, info_offset = selected['info']
    xdata = rows[info_section-1]
    require(xdata['name'] == b'.xdata' and not xdata['flags'] & 0xa0000000
            and 0 < len(xdata['code']) <= 65536, 'bounded nonexecutable nonwritable xdata section')
    xrefs = obj.relocations(data, xdata, symbols)
    require(all(r['kind'] == 3 for r in xrefs.values()), 'only ADDR32NB xdata references')
    xbase = info_rva - info_offset
    xbytes = mapped(linked, xbase, len(xdata['code']))
    exact(xdata['code'], xbytes, xrefs)
    metadata = []
    for place, ref in sorted(xrefs.items()):
        symbol = symbols[ref['symbol']]
        addend, = pe.unpack('<I', xdata['code'], place)
        target, = pe.unpack('<I', xbytes, place)
        require(any(r['rva'] <= target < r['rva'] + r['virtual_size'] for r in linked), 'in-image metadata reference')
        if symbol['section'] == info_section:
            require(target == xbase + symbol['value'] + addend, 'internal xdata reference identity')
        elif symbol['section'] == selected['section']:
            require(target == start-selected['start'] + symbol['value'] + addend, 'associated code reference identity')
        metadata.append(dict(offset=place, symbol=symbol['name'], target_rva=target,
                             symbol_rva=target-addend, section=symbol['section']))
    header = mapped(linked, info_rva, 4)
    version, flags = header[0] & 7, header[0] >> 3
    require(version == 1 and flags in (0, 1, 2, 3), 'nonchained version-one metadata')
    prefix_size = 4 + ((header[2]+1) & ~1)*2
    require(info_offset % 4 == info_rva % 4 == 0 and header[1] <= len(code)
            and info_offset + prefix_size + (4 if flags else 0) <= len(xbytes),
            'aligned bounded unwind header/codes')
    handler = None
    if flags:
        handler_offset = info_offset + prefix_size
        handler_refs = [r for r in metadata if r['offset'] == handler_offset]
        require(len(handler_refs) == 1 and executable(linked, handler_refs[0]['target_rva']), 'executable bound handler')
        handler = handler_refs[0]
    return dict(entry=entry, rva=start, size=len(code), byte_candidates=len(matches), incoming=incoming,
                reference_targets=targets, xdata_rva=xbase, xdata_bytes=len(xbytes), metadata=metadata,
                unwind_rva=info_rva, unwind_header=list(header), handler=handler,
                image_sha256=image_hash, object_sha256=hashlib.sha256(data).hexdigest(),
                handler_semantics_qualified=False, whole_image_qualified=False)
