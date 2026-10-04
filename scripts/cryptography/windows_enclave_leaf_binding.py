"""Bind reviewed no-unwind COFF helpers through existing caller anchors.

Absence of unwind metadata is NOT proof of a leaf, no spills or safe cleanup.
Instruction semantics require separate review. Anchors must be independently
reproduced for the same image; this is not an untrusted-evidence admission API.
"""
import hashlib
import re

import windows_enclave_caller_binding as caller


def require(ok, message):
    if not ok: raise ValueError('leaf binding: ' + message)


def bind(obj, image, name, anchors):
    code, refs = caller.function(obj, name)
    # This helper population has no relocations except a single complete E9
    # tail thunk. Refuse to mask arbitrary operand bytes or hidden call sites.
    require(not refs or (len(code) == 5 and code == b'\xe9\0\0\0\0'
            and len(refs) == 1 and refs[0]['offset'] == 1
            and refs[0]['trailing'] == refs[0]['addend'] == 0), 'reviewed relocation shape')
    rows, functions = caller.pe.linked(image)
    pattern = b'(?=(' + (b'\xe9.{4}' if refs else re.escape(code)) + b'))'
    candidates = [(row, match.start()) for row in rows if row['flags'] & 0x20000000
                  for match in re.finditer(pattern, row['code'], re.DOTALL)]
    digest = hashlib.sha256(image).hexdigest()
    incoming = []
    for anchor in anchors:
        require(anchor['image_sha256'] == digest, 'anchor image identity')
        if name in anchor['reference_targets']:
            incoming.append((anchor['entry'], anchor['reference_targets'][name]))
    require(bool(incoming) and len({v for _,v in incoming}) == 1, 'consistent incoming references')
    target = incoming[0][1]
    found = [(row, offset) for row,offset in candidates if row['rva']+offset == target]
    require(len(found) == 1, 'anchored exact code match')
    row, offset = found[0]
    require(not row['flags'] & 0x80000000 and offset+len(code) <= row['virtual_size'],
            'nonwritable mapped code')
    require(not any(a < target+len(code) and target < b for a,b,_ in functions),
            'helper must not overlap a runtime-function entry')
    targets = {}
    if refs:
        delta, = caller.pe.unpack('<i', row['code'], offset+1)
        destination = target+5+delta
        require(any(r['flags'] & 0x20000000 and not r['flags'] & 0x80000000
                    and 0 <= destination-r['rva'] < min(len(r['code']),r['virtual_size'])
                    for r in rows) and not target <= destination < target+len(code),
                'tail target in distinct nonwritable code')
        targets[refs[0]['symbol']] = destination
    return dict(entry=name, rva=target, size=len(code), incoming=incoming,
                byte_candidates=len(candidates), reference_targets=targets,
                object_sha256=hashlib.sha256(obj).hexdigest(), image_sha256=digest,
                code_sha256=hashlib.sha256(row['code'][offset:offset+len(code)]).hexdigest(),
                whole_image_qualified=False, instruction_semantics_qualified=False)
