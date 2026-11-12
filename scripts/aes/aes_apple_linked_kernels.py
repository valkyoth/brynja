"""Bounded Mach-O ARM64 AES body review, independent of disassembler text.

Read mappings, symbols and LC_FUNCTION_STARTS from the executable itself.
Compare complete function extents against the previously reviewed AArch64
instruction encodings; never learn a policy from the binary under review.
No caller, platform admission, unwind or whole-program claim is made here.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct

SPEC = importlib.util.spec_from_file_location('apple_expansion_templates',
    Path(__file__).with_name('aes_accelerated_linked_expansion.py'))
expansion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(expansion)
TARGET = 'aarch64-unknown-linux-musl'  # Shared ISA encodings, not an ELF mapping.
LIMIT = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError('AES Apple linked kernels: ' + message)


def name(raw):
    value, separator, padding = raw.partition(b'\0')
    require(not separator or not any(padding), 'noncanonical fixed name')
    try:
        return value.decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('AES Apple linked kernels: non-ASCII fixed name') from error


def extent(offset, size, limit):
    require(0 <= offset <= limit and 0 <= size <= limit - offset, 'out-of-range extent')


def nonoverlap(rows):
    rows = sorted((start, size) for start, size in rows if size)
    require(all(a + n <= b for (a, n), (b, _) in zip(rows, rows[1:])), 'overlapping ranges')


def starts(data, base, lower, upper):
    """Canonical, bounded ULEB128 deltas plus zero padding only."""
    result, cursor, address = [], 0, base
    while cursor < len(data):
        value, shift, count = 0, 0, 0
        while True:
            require(cursor < len(data) and count < 10, 'truncated/oversized function delta')
            byte = data[cursor]
            cursor += 1
            count += 1
            value |= (byte & 127) << shift
            require(value < 2**64, 'function delta overflow')
            if not byte & 128:
                require(count == 1 or byte != 0, 'noncanonical function delta')
                break
            shift += 7
        if value == 0:
            require(not any(data[cursor:]) and result, 'invalid function-start terminator')
            return result
        address += value
        require(lower <= address < upper and address % 4 == 0, 'invalid function start')
        result.append(address)
    raise ValueError('AES Apple linked kernels: missing function-start terminator')


def parse(image, *, symbol_filter=None, include_layout=False):
    require(32 <= len(image) <= LIMIT, 'invalid image size')
    magic, cpu, subtype, kind, count, size, _, reserved = struct.unpack_from('<8I', image)
    require((magic, cpu, subtype, kind, reserved) == (0xfeedfacf, 0x100000c, 0, 2, 0),
            'requires thin little-endian ARM64 executable (not arm64e/fat/ELF)')
    require(0 < count <= 4096 and size <= len(image) - 32, 'invalid load-command table')
    cursor, segments, sections, commands = 32, [], [], {}
    for _ in range(count):
        require(cursor + 8 <= 32 + size, 'truncated load command')
        cmd, length = struct.unpack_from('<II', image, cursor)
        require(length >= 8 and length % 8 == 0 and cursor + length <= 32 + size,
                'invalid load-command length')
        if cmd == 0x19:  # LC_SEGMENT_64
            require(length >= 72, 'truncated segment')
            _, _, label, base, memsz, pos, filesz, maximum, initial, nsects, flags = struct.unpack_from(
                '<II16sQQQQiiII', image, cursor)
            label = name(label)
            require(length == 72 + 80 * nsects and filesz <= memsz and base + memsz < 2**64,
                    'invalid segment extent')
            extent(pos, filesz, len(image))
            require(0 <= initial <= 7 and 0 <= maximum <= 7 and initial & ~maximum == 0,
                    'invalid segment protections')
            require(label not in {s['name'] for s in segments}, 'duplicate segment')
            segments.append(dict(name=label, base=base, memsz=memsz, pos=pos,
                                 filesz=filesz, initial=initial, maximum=maximum))
            for i in range(nsects):
                sec, seg, address, length_, offset, align, _, _, mode, reserved1, reserved2, _ = struct.unpack_from(
                    '<16s16sQQ8I', image, cursor + 72 + 80 * i)
                require(name(seg) == label and base <= address and address + length_ <= base + memsz,
                        'section outside parent')
                require(align <= 31 and address % (1 << align) == 0, 'invalid section alignment')
                # Zero-fill sections have no file bytes. All other sections must
                # agree with the parent segment's address-to-file translation.
                if mode & 255 not in (1, 12, 18):
                    require(offset == pos + address - base and offset + length_ <= pos + filesz,
                            'section/file mapping mismatch')
                sections.append(dict(name=name(sec), segment=label, address=address,
                                     size=length_, offset=offset, flags=mode,
                                     reserved1=reserved1, reserved2=reserved2))
        elif cmd in (2, 0x26):  # LC_SYMTAB, LC_FUNCTION_STARTS
            require(cmd not in commands and length == (24 if cmd == 2 else 16),
                    'duplicate/invalid symbol or function-start command')
            commands[cmd] = struct.unpack_from('<' + ('4I' if cmd == 2 else '2I'), image, cursor + 8)
        elif cmd in (0x21, 0x2c):
            raise ValueError('AES Apple linked kernels: encrypted images are not reviewed')
        cursor += length
    require(cursor == 32 + size and set(commands) == {2, 0x26}, 'incomplete load-command table')
    nonoverlap([(s['base'], s['memsz']) for s in segments])
    nonoverlap([(s['pos'], s['filesz']) for s in segments])
    nonoverlap([(s['address'], s['size']) for s in sections])
    text = [s for s in segments if s['name'] == '__TEXT']
    link = [s for s in segments if s['name'] == '__LINKEDIT']
    code = [(i + 1, s) for i, s in enumerate(sections)
            if s['name'] == '__text' and s['segment'] == '__TEXT']
    require(len(text) == len(link) == len(code) == 1, 'missing/ambiguous text or linkedit')
    text, link, (section_index, code) = text[0], link[0], code[0]
    require(text['initial'] == text['maximum'] == 5 and text['pos'] == 0
            and text['filesz'] >= 32 + size and link['initial'] == 1,
            'unexpected text/linkedit permissions or mapping')
    require(code['flags'] & 255 == 0 and code['flags'] & 0x80000000
            and code['offset'] >= 32 + size and code['size'] > 0, 'invalid instruction section')
    symoff, nsym, stroff, strsize = commands[2]
    funoff, funsize = commands[0x26]
    require(nsym > 0 and strsize > 0 and funsize > 0, 'empty linkedit metadata')
    tables = [(symoff, nsym * 16), (stroff, strsize), (funoff, funsize)]
    for offset, length in tables:
        extent(offset, length, len(image))
        require(link['pos'] <= offset and offset + length <= link['pos'] + link['filesz'],
                'metadata outside linkedit')
    nonoverlap(tables)
    functions = starts(image[funoff:funoff + funsize], text['base'],
                       code['address'], code['address'] + code['size'])
    symbols = []
    strings = image[stroff:stroff + strsize]
    # The captured Apple linker uses a space/NUL sentinel; zero n_strx
    # means unnamed, rather than a pointer to that sentinel's text.
    require(strings.startswith((b'\0', b' \0')), 'invalid string table sentinel')
    for i in range(nsym):
        index, kind, section, _, address = struct.unpack_from('<IBBHQ', image, symoff + i * 16)
        require(index < strsize, 'symbol string offset outside table')
        if index == 0:
            continue
        end = strings.find(b'\0', index)
        require(end >= 0, 'unterminated symbol name')
        # STAB debugging records intentionally duplicate actual symbols.
        if kind & 0xe0:
            continue
        raw_name = strings[index:end]
        selected = (symbol_filter(raw_name) if symbol_filter is not None else
                    b'17brynja_crypto_cpu3aes' in raw_name and
                    (b'9transform' in raw_name or b'6expand' in raw_name))
        if not selected:
            continue
        require(kind & 0x1e == 0xe and section == section_index,
                'kernel symbol is not defined in instruction section')
        try:
            symbol = raw_name.decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('AES Apple linked kernels: invalid kernel symbol') from error
        symbols.append((symbol, address))
    result = (code, functions, symbols)
    return (*result, {'segments': segments, 'sections': sections, 'commands': commands}) if include_layout else result


def inspect(image):
    code, functions, symbols = parse(image)
    results = []
    require(len(symbols) == 6 and len(set(symbols)) == 6
            and len({s for s, _ in symbols}) == 6
            and len({a for _, a in symbols}) == 6, 'kernel population/alias mismatch')
    boundaries = {start: end for start, end in zip(functions, functions[1:])}
    for symbol, address in sorted(symbols, key=lambda row: row[1]):
        role = 'expand' if '6expand' in symbol else 'transform'
        module, method, generics = (('14aarch64_expand', '6expand', r'(?:10_Kjb0|18_Kjd0|20_Kjf0)')
                                   if role == 'expand' else ('7aarch64', '9transform', '[bdf]'))
        pattern = (r'__(?:ZN17brynja_crypto_cpu3aes' + module + method + r'17h[0-9a-f]{16}E|'
                   r'RINvNtNtC\w+_17brynja_crypto_cpu3aes' + module + method + r'Kj' + generics + r'_EB\w+_)')
        require(re.fullmatch(pattern, symbol) is not None, 'unreviewed kernel symbol')
        require(address in boundaries, 'kernel lacks two function boundaries')
        length = boundaries[address] - address
        pos = code['offset'] + address - code['address']
        raw = image[pos:pos + length]
        template = expansion.template if role == 'expand' else expansion.kernels.template
        matches = [bits for bits in (128, 192, 256) if raw == template(TARGET, bits)[1]]
        require(len(matches) == 1, 'complete function encoding/extent changed; explicit review required')
        bits = matches[0]
        if symbol.startswith('__RI'):
            expected = ({128: '10_Kjb0', 192: '18_Kjd0', 256: '20_Kjf0'} if role == 'expand'
                        else {128: 'b', 192: 'd', 256: 'f'})[bits]
            require('Kj' + expected + '_E' in symbol, 'symbol/template width mismatch')
        results.append(dict(role=role, bits=bits, symbol=symbol, address=hex(address),
                            file_offset=pos, size=length, instructions=length // 4,
                            sha256=hashlib.sha256(raw).hexdigest()))
    require(sorted((r['role'], r['bits']) for r in results)
            == [(role, bits) for role in ('expand', 'transform') for bits in (128, 192, 256)],
            'missing/duplicate width')
    return {'binary_sha256': hashlib.sha256(image).hexdigest(), 'bodies': results,
            'scope': 'Six complete Mach-O function extents match reviewed ARM encodings; callers, admission, cleanup and unwind remain unreviewed.'}
