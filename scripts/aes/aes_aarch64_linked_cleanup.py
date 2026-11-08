"""Retained ARM caller Drop paths and binding of the imported unwind resume stub.

The OS loader, external unwinder and exception-table dispatch remain trusted.
"""
import importlib.util
import json
from pathlib import Path
import re
import struct


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module('arm_cleanup_image', 'aes_aarch64_linked.py')
names = module('arm_cleanup_names', 'aes_linked_cleanup.py')
WIDTHS = names.WIDTHS
POLICY = Path(__file__).with_name('aarch64-linked-cleanup-review.json')
require = r.require


def sections(image):
    """Read only the bounded, file-backed ELF metadata needed for import binding."""
    loads = r.segments(image)
    offset = struct.unpack_from('<Q', image, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', image, 58)
    require(size == 64 and 0 < strings < count < 4096
            and offset + size * count <= len(image), 'invalid ELF section table')
    rows = [struct.unpack_from('<IIQQQQIIQQ', image, offset + size*i) for i in range(count)]
    def content(row):
        require(row[4] + row[5] <= len(image), 'section outside file')
        return image[row[4]:row[4]+row[5]]
    require(rows[strings][1] == 3, 'invalid section-name table')
    strings = content(rows[strings])
    result = {}
    for i, row in enumerate(rows):
        name = cstring(strings, row[0])
        if name not in ('.dynsym', '.dynstr', '.rela.plt', '.plt'):
            continue
        require(name not in result and row[5] > 0, 'duplicate/empty import section')
        data = content(row)
        require(r.mapped(loads, row[3], row[5], (4, 5)) == row[4], 'import section/load mismatch')
        result[name] = (i, row, data)
    require(set(result) == {'.dynsym', '.dynstr', '.rela.plt', '.plt'}, 'missing import section')
    return result


def cstring(data, offset):
    require(0 <= offset < len(data), 'invalid string offset')
    end = data.find(b'\0', offset)
    require(end >= 0, 'unterminated ELF string')
    try:
        return data[offset:end].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('non-ASCII ELF string') from error


def resume_target(assembly, image):
    metadata = sections(image)
    sym_index, sym, symbols = metadata['.dynsym']
    str_index, strings, text = metadata['.dynstr']
    _, rela, relocations = metadata['.rela.plt']
    _, plt, _ = metadata['.plt']
    require(sym[1] == 11 and sym[6] == str_index and sym[9] == 24 and len(symbols) % 24 == 0
            and strings[1] == 3 and rela[1] == 4 and rela[6] == sym_index
            and rela[9] == 24 and len(relocations) % 24 == 0
            and plt[1] == 1 and plt[2] == 6, 'invalid import section linkage')
    # Section names are not what the runtime loader consumes. Bind the same
    # tables to PT_DYNAMIC so a stray/unreferenced relocation section cannot
    # masquerade as the live import table.
    dynamic_tables(image, sym, strings, rela)
    matches, slots = [], set()
    for i in range(0, len(relocations), 24):
        slot, info, addend = struct.unpack_from('<QQq', relocations, i)
        index, kind = info >> 32, info & 0xffffffff
        require(kind == 1026 and addend == 0 and slot not in slots
                and 0 < index < len(symbols)//24, 'invalid/duplicate PLT relocation')
        slots.add(slot)
        name, binding, visibility, section, value, size = struct.unpack_from('<IBBHQQ', symbols, index*24)
        if cstring(text, name) == '_Unwind_Resume':
            require(binding == 0x12 and visibility == 0 and section == 0 and value == 0,
                    'resume must be an undefined global function')
            matches.append(slot)
    require(len(matches) == 1, 'missing/ambiguous resume relocation')
    headers = re.findall(r'^([0-9a-f]+) <_Unwind_Resume@plt>:$', assembly, re.M)
    require(len(headers) == 1, 'missing/ambiguous resume PLT entry')
    address = int(headers[0], 16)
    require(plt[3] <= address and address + 16 <= plt[3] + plt[5]
            and address % 16 == 0, 'resume outside PLT')
    row = ('_Unwind_Resume@plt', address, 16)
    lines, raw = r.decode(assembly, row)
    pos = r.mapped(r.segments(image), address, 16, 5)
    require(raw == image[pos:pos+16], 'resume disassembly differs from ELF')
    page, load, add, jump = struct.unpack('<IIII', raw)
    require(page & 0x9f00001f == 0x90000010 and load & 0xffc003ff == 0xf9400211
            and add & 0xffc003ff == 0x91000210 and jump == 0xd61f0220,
            'unreviewed resume PLT encoding')
    immediate = ((page >> 5) & 0x7ffff) << 2 | (page >> 29) & 3
    base = (address & ~4095) + r.signed(immediate, 21)*4096
    displacement = ((load >> 10) & 0xfff)*8
    require(((add >> 10) & 0xfff) == displacement and base + displacement == matches[0],
            'resume PLT/GOT relocation mismatch')
    r.mapped(r.segments(image), matches[0], 8, 6)
    require(re.fullmatch(r'adrp x16, 0x' + f'{base:x}' + r' <[^>]+>', lines[0]) is not None
            and lines[1:] == [f'ldr x17, [x16, #{displacement}]',
                              f'add x16, x16, #{displacement}', 'br x17'],
            'resume PLT text/encoding mismatch')
    return row


def dynamic_tables(image, sym, strings, rela):
    offset = struct.unpack_from('<Q', image, 32)[0]
    size, count = struct.unpack_from('<HH', image, 54)
    require(size == 56 and offset + size*count <= len(image), 'invalid program-header table')
    rows = [struct.unpack_from('<IIQQQQQQ', image, offset+i*size) for i in range(count)]
    dynamic = [row for row in rows if row[0] == 2]
    require(len(dynamic) == 1, 'missing/ambiguous dynamic table')
    _, flags, pos, address, _, length, memory, _ = dynamic[0]
    require(flags == 6 and 0 < length <= memory and length % 16 == 0
            and r.mapped(r.segments(image), address, length, 6) == pos, 'invalid dynamic table load')
    expected = {2: rela[5], 5: strings[3], 6: sym[3], 10: strings[5],
                11: 24, 20: 7, 23: rela[3]}
    found, ended = {}, False
    for i in range(pos, pos+length, 16):
        tag, value = struct.unpack_from('<qQ', image, i)
        if ended or tag == 0:
            require(tag == value == 0, 'invalid dynamic terminator/padding')
            ended = True
        elif tag in expected:
            require(tag not in found, 'duplicate dynamic import tag')
            found[tag] = value
    require(ended and found == expected, 'dynamic/section import table mismatch')


def select(table, existing):
    selected = names.candidates(table)
    ordered = sorted([*selected.values(), *existing.values()], key=lambda row: row[1])
    require(all(a+n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])),
            'overlapping cleanup/helper bodies')
    return selected


def resume_mutations(assembly, image):
    row = resume_target(assembly, image)
    pos = r.mapped(r.segments(image), row[1], row[2], 5)
    cases = []
    for i in range(4):
        word = int.from_bytes(image[pos+4*i:pos+4*i+4], 'little')
        for bit in range(32):
            changed_word = word ^ (1 << bit)
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos+4*i, changed_word)
            # Change the printed instruction word as well as the ELF bytes;
            # operand, opcode and relocation checks must still reject it.
            pattern = r'(?m)^(\s*' + f'{row[1]+4*i:x}' + r':\s*)' + f'{word:08x}' + r'\b'
            text, count = re.subn(pattern, lambda match: match[1] + f'{changed_word:08x}', assembly)
            require(count == 1, 'ambiguous resume disassembly word')
            cases.append((text, changed))
    metadata = sections(image)
    _, sym, symbols = metadata['.dynsym']
    _, strings, text = metadata['.dynstr']
    _, rela, relocations = metadata['.rela.plt']
    for i in range(0, len(relocations), 24):
        _, info, _ = struct.unpack_from('<QQq', relocations, i)
        index = info >> 32
        name = struct.unpack_from('<I', symbols, index*24)[0]
        if cstring(text, name) != '_Unwind_Resume':
            continue
        for offset in (rela[4]+i, rela[4]+i+8, sym[4]+index*24+4, strings[4]+name):
            changed = bytearray(image); changed[offset] ^= 8
            cases.append((assembly, changed))
    # Break the relocation table's link to its symbol table.
    index = metadata['.rela.plt'][0]
    offset = struct.unpack_from('<Q', image, 40)[0] + index*64 + 40
    changed = bytearray(image); struct.pack_into('<I', changed, offset, 0)
    cases.append((assembly, changed))
    require(len(cases) == 133, 'resume mutation population mismatch')
    for text, changed in cases:
        try:
            resume_target(text, changed)
        except ValueError:
            pass
        else:
            raise ValueError('AES ARM resume mutation accepted')
    return len(cases)


def check(lines, raw, row, image, targets, role, compiler, panic, policy=None):
    policy = json.loads(POLICY.read_text()) if policy is None else policy
    require(set(policy) == {'schema', 'target', 'profile', 'review', 'configurations'}
            and policy['schema'] == 1 and policy['target'] == 'aarch64-unknown-linux-gnu'
            and policy['profile'] == 'opt3-fat-lto-cgu1-overflow'
            and policy['review'] == 'docs/assurance/aes-aarch64-linked-review.md', 'cleanup review scope changed')
    configs = {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')}
    require(set(policy['configurations']) == configs
            and all(set(rows) == set(WIDTHS) for rows in policy['configurations'].values()),
            'cleanup configuration population changed')
    require(compiler + '/' + panic in configs and role in WIDTHS
            and set(targets) == ({'zeroize', 'resume'} if panic == 'unwind' else {'zeroize'}),
            'unreviewed cleanup role/targets')
    actual, _, _ = r.observe(lines, raw, row, image, targets, callback=True)
    require(actual == policy['configurations'][compiler + '/' + panic][role],
            'cleanup instruction/encoding policy changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, row, image, targets, role, compiler, panic):
    check(lines, raw, row, image, targets, role, compiler, panic)
    pos = r.mapped(r.segments(image), row[1], row[2], 5)
    cases = [(lines[:-1], raw, image, targets)]
    for key, (name, address, size) in targets.items():
        changed = dict(targets); changed[key] = (name, address+4, size)
        cases.append((lines, raw, image, changed))
    for i, line in enumerate(lines):
        require(line != 'nop', 'unexpected NOP in reviewed cleanup body')
        changed = list(lines); changed[i] = 'nop'
        cases.append((changed, raw, image, targets))
        changed_raw = raw[:4*i] + bytes.fromhex('1f2003d5') + raw[4*i+4:]
        cases.append((changed, changed_raw, image[:pos]+changed_raw+image[pos+len(raw):], targets))
    for changed_lines, changed_raw, changed_image, changed_targets in cases:
        try:
            check(changed_lines, changed_raw, row, changed_image, changed_targets, role, compiler, panic)
        except ValueError:
            pass
        else:
            raise ValueError('AES ARM linked cleanup mutation accepted: ' + role)
    return len(cases)
