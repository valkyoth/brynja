"""Bounded ordinary COFF archive reader for saved offline evidence (no linker)."""
from windows_enclave_caller_binding import require


def members(raw):
    require(8 <= len(raw) <= 128 * 1024 * 1024 and raw[:8] == b'!<arch>\n', 'ordinary bounded archive')
    at, names, pending = 8, None, []
    while at < len(raw):
        header = raw[at:at+60]
        require(len(header) == 60 and header[58:] == b'`\n', 'complete archive header')
        size_text = header[48:58].strip()
        require(size_text.isdigit(), 'decimal archive member size')
        size = int(size_text); start = at + 60; end = start + size
        require(end <= len(raw), 'complete archive member')
        name = header[:16].rstrip(b' ')
        if name == b'//':
            require(names is None, 'one archive long-name table')
            names = raw[start:end]
        elif name != b'/':
            require(not name.startswith(b'#1/'), 'BSD archive not reviewed')
            pending.append((name, raw[start:end]))
        at = end + size % 2
        require(at <= len(raw) and (size % 2 == 0 or raw[end:at] == b'\n'), 'archive alignment padding')
        require(len(pending) <= 4096, 'bounded member population')
    result = {}
    for name, data in pending:
        if name.startswith(b'/'):
            require(name[1:].isdigit() and names is not None, 'valid long-name reference')
            index = int(name[1:])
            require(index < len(names) and (index == 0 or names[index-1:index] in (b'\0', b'\n')),
                    'long name starts at entry boundary')
            ends = [n for n in (names.find(b'\0', index), names.find(b'/\n', index)) if n >= 0]
            require(bool(ends), 'terminated long name')
            name = names[index:min(ends)]
        else:
            name = name.removesuffix(b'/')
        # Names are opaque identifiers, never extraction paths. Toolchain
        # archives can contain path-shaped compiler-builtins member names.
        require(name and all(32 <= c < 127 for c in name), 'printable archive member identifier')
        text = name.decode('ascii')
        require(text not in result, 'unique archive member')
        result[text] = data
    require(bool(result), 'nonempty archive')
    return result
