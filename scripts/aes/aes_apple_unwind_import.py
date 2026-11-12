"""Static binding of retained Apple lazy unwind and public memcmp imports.

Not a proof of dyld, the system unwinder, exception tables or runtime memory.
Only the narrow, observed lazy-binding representation is accepted.
"""
import importlib.util
from pathlib import Path
import struct

SPEC = importlib.util.spec_from_file_location('apple_import_mapping',
    Path(__file__).with_name('aes_apple_linked_kernels.py'))
mapping = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mapping)
require = mapping.require
NAME = b'__Unwind_Resume'
LIBRARY = b'/usr/lib/libSystem.B.dylib'


def uleb(data, cursor):
    value, shift = 0, 0
    for count in range(10):
        require(cursor < len(data), 'truncated bind offset')
        byte = data[cursor]
        cursor += 1
        value |= (byte & 127) << shift
        require(value < 2**64, 'bind offset overflow')
        if not byte & 128:
            require(count == 0 or byte != 0, 'noncanonical bind offset')
            return value, cursor
        shift += 7
    raise ValueError('AES Apple linked kernels: oversized bind offset')


def lazy_records(data, segments):
    records, cursor = [], 0
    while cursor < len(data):
        if not any(data[cursor:]):
            break
        begin = cursor
        opcode = data[cursor]
        require(opcode & 0xf0 == 0x70 and opcode & 15 < len(segments), 'unsupported lazy segment opcode')
        segment = segments[opcode & 15]
        offset, cursor = uleb(data, cursor + 1)
        require(data[cursor:cursor + 2] == b'\x11\x40', 'lazy binding must name strong ordinal-one import')
        cursor += 2
        end = data.find(b'\0', cursor)
        require(end > cursor and end - cursor <= 4096, 'invalid lazy symbol')
        symbol = data[cursor:end]
        require(data[end + 1:end + 3] == b'\x90\0', 'unsupported lazy bind operation/terminator')
        require(offset % 8 == 0 and offset + 8 <= segment['filesz'], 'lazy pointer outside file mapping')
        records.append({'address': segment['base'] + offset, 'name': symbol, 'offset': begin})
        cursor = end + 3
    require(records and len({r['address'] for r in records}) == len(records), 'empty/duplicate lazy pointers')
    return records


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def stub_pointer(raw, address):
    require(len(raw) == 12, 'invalid stub size')
    page, load, branch = struct.unpack('<3I', raw)
    require(page & 0x9f00001f == 0x90000010 and load & 0xffc003ff == 0xf9400210
            and branch == 0xd61f0200, 'unreviewed import stub instructions')
    immediate = ((page >> 5) & 0x7ffff) << 2 | (page >> 29) & 3
    return (address & ~4095) + signed(immediate, 21) * 4096 + ((load >> 10) & 4095) * 8


def inspect(image, symbol_name=NAME):
    require(symbol_name in (NAME, b'_memcmp'), 'unreviewed system import name')
    _, _, _, layout = mapping.parse(image, include_layout=True)
    segments, sections = layout['segments'], layout['sections']
    require(struct.unpack_from('<I', image, 24)[0] & 0x80, 'requires two-level namespace')
    cursor, commands, libraries = 32, {}, []
    for _ in range(struct.unpack_from('<I', image, 16)[0]):
        cmd, length = struct.unpack_from('<II', image, cursor)
        if cmd in (0xb, 0x80000022):
            require(cmd not in commands and length == (80 if cmd == 0xb else 48),
                    'duplicate/invalid import command')
            commands[cmd] = struct.unpack_from('<' + ('18I' if cmd == 0xb else '10I'), image, cursor + 8)
        elif cmd == 0xc:
            require(length >= 24, 'truncated library command')
            offset = struct.unpack_from('<I', image, cursor + 8)[0]
            require(24 <= offset < length, 'invalid library name offset')
            payload = image[cursor + offset:cursor + length]
            library, separator, padding = payload.partition(b'\0')
            require(separator and not any(padding), 'invalid library name')
            libraries.append(library)
        elif cmd in (0x80000018, 0x8000001f, 0x80000023, 0x20, 0x80000034):
            raise ValueError('AES Apple linked kernels: unsupported weak/reexport/upward/lazy library or chained fixups')
        cursor += length
    require(set(commands) == {0xb, 0x80000022} and libraries == [LIBRARY], 'unexpected import libraries/commands')
    link = next(s for s in segments if s['name'] == '__LINKEDIT')

    def table(offset, size):
        require(size > 0 and link['pos'] <= offset and offset + size <= link['pos'] + link['filesz'],
                'import table outside linkedit')
        return image[offset:offset + size]

    def section(seg, name, mode, protection):
        found = [s for s in sections if (s['segment'], s['name']) == (seg, name)]
        require(len(found) == 1, 'missing/duplicate import section')
        item = found[0]
        parent = next(s for s in segments if s['name'] == seg)
        require(item['flags'] & 255 == mode and parent['initial'] == protection
                and item['size'] > 0, 'invalid import section type/protection')
        return item

    stubs = section('__TEXT', '__stubs', 8, 5)
    pointers = section('__DATA', '__la_symbol_ptr', 7, 3)
    helpers = section('__TEXT', '__stub_helper', 0, 5)
    require(stubs['reserved2'] == 12 and stubs['size'] % 12 == 0 and pointers['size'] % 8 == 0,
            'invalid stub/pointer stride')
    symoff, nsym, stroff, strsize = layout['commands'][2]
    dysym = commands[0xb]
    first, count = dysym[4:6]
    indirectoff, indirectcount = dysym[12:14]
    require(count > 0 and first + count <= nsym, 'invalid undefined symbol partition')
    indirect = table(indirectoff, indirectcount * 4)
    dyld = commands[0x80000022]
    lazyoff, lazysize = dyld[6:8]
    require(dyld[4:6] == (0, 0), 'weak bindings not reviewed')
    lazy = table(lazyoff, lazysize)
    mapping.nonoverlap([(symoff, nsym * 16), (stroff, strsize), (indirectoff, len(indirect)), (lazyoff, len(lazy))])
    strings = image[stroff:stroff + strsize]
    found = []
    for i in range(nsym):
        index, kind, sect, description, value = struct.unpack_from('<IBBHQ', image, symoff + i * 16)
        if kind & 0xe0:
            continue
        end = strings.find(b'\0', index)
        if strings[index:end] == symbol_name:
            require(first <= i < first + count and (kind, sect, description, value) == (1, 0, 0x100, 0),
                    'unwind symbol must be strong undefined ordinal-one import')
            found.append(i)
    require(len(found) == 1, 'missing/duplicate unwind import')
    symbol = found[0]

    def slot(sec, stride):
        begin, n = sec['reserved1'], sec['size'] // stride
        require(begin + n <= indirectcount, 'indirect symbol table range overflow')
        found = [i for i in range(n) if struct.unpack_from('<I', indirect, 4 * (begin + i))[0] == symbol]
        require(len(found) == 1, 'missing/duplicate unwind indirect slot')
        return found[0]

    stubslot, ptrslot = slot(stubs, 12), slot(pointers, 8)
    address = stubs['address'] + 12 * stubslot
    pos = stubs['offset'] + 12 * stubslot
    pointer = pointers['address'] + 8 * ptrslot
    require(stub_pointer(image[pos:pos + 12], address) == pointer, 'stub points at wrong lazy pointer')
    records = lazy_records(lazy, segments)
    matching = [r for r in records if r['name'] == symbol_name or r['address'] == pointer]
    require(len(matching) == 1 and matching[0]['name'] == symbol_name and matching[0]['address'] == pointer,
            'lazy opcode import disagrees with symbol/indirect tables')
    initial = struct.unpack_from('<Q', image, pointers['offset'] + 8 * ptrslot)[0]
    require(helpers['address'] + 24 <= initial and initial + 12 <= helpers['address'] + helpers['size']
            and (initial - helpers['address'] - 24) % 12 == 0, 'unwind pointer lacks bounded lazy helper')
    helperpos = helpers['offset'] + initial - helpers['address']
    load, branch, entry = struct.unpack_from('<3I', image, helperpos)
    require(load == 0x18000050 and branch & 0xfc000000 == 0x14000000
            and initial + 4 + signed(branch & 0x3ffffff, 26) * 4 == helpers['address']
            and entry == matching[0]['offset'], 'lazy helper selects wrong record or dispatcher')
    return {'symbol': symbol_name.decode(), 'library': LIBRARY.decode(), 'stub_address': hex(address),
            'stub_file_offset': pos, 'pointer_address': hex(pointer), 'helper_address': hex(initial),
            'lazy_record_offset': entry,
            'scope': 'Static import declaration/stub/pointer/per-symbol helper binding only; dyld common dispatcher, rebasing and the named system function are trusted, not qualified.'}
