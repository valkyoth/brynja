"""Closed symbolic LSDA binding for the reviewed ELF/Mach-O compiler rows.

Decode emitted label-relative call-site ranges, not linked binary offsets.
Actions are validated against the reviewed table; landing pads are conservative
may-edges, not a proof of personality matching, CFI recovery or runtime linking.
Layout reference: llvm-project/libcxxabi/src/cxa_personality.cpp.
"""
import re

from batch_worker_machine import machine, require


def parse(body, arm, apple):
    code, labels, raw = machine.parse(body, arm)
    lines = [re.sub(r'\s+', ' ', line.split('//', 1)[0].split('#', 1)[0].strip())
             for line in body.splitlines()]
    lines = [line for line in lines if line]
    personality = '155, _rust_eh_personality' if apple else (
        '156, DW.ref.rust_eh_personality' if arm else '155, DW.ref.rust_eh_personality')
    require([l for l in lines if l.startswith('.cfi_personality ')] == ['.cfi_personality ' + personality],
            'reviewed worker unwind personality')
    bindings = [re.fullmatch(r'\.cfi_lsda (\d+), (\.?Lexception\d+)', line) for line in lines if line.startswith('.cfi_lsda ')]
    require(len(bindings) == 1 and bindings[0] is not None and
            int(bindings[0][1]) == (16 if apple else 28 if arm else 27), 'one target-correct LSDA binding')
    table = bindings[0][2]
    require(lines.count(table + ':') == 1, 'bound LSDA table exists exactly once')
    index = lines.index(table + ':') + 1
    header = lines[index:index + 7]
    require(len(header) == 7 and header[:2] == ['.byte 255', '.byte ' + ('156' if arm and not apple else '155')],
            'reviewed omitted landing-pad base and type encoding')
    types = re.fullmatch(r'\.uleb128 (\.?Lttbase\d+)-(\.?Lttbaseref\d+)', header[2])
    span = re.fullmatch(r'\.uleb128 (\.?Lcst_end\d+)-(\.?Lcst_begin\d+)', header[5])
    require(types is not None and header[3] == types[2] + ':' and header[4] == '.byte 1' and
            span is not None and header[6] == span[2] + ':', 'ULEB call-site header and table extent')
    require(lines.count(span[1] + ':') == 1 and lines.count(span[2] + ':') == 1 and
            lines.count(types[1] + ':') == 1 and lines.count(types[2] + ':') == 1,
            'unique LSDA extent/type labels')
    stop = lines.index(span[1] + ':')
    entries = lines[index + 7:stop]
    require(stop > index + 7 and len(entries) % 4 == 0, 'complete nonempty call-site records')
    begin = [name for name, pc in labels.items() if re.fullmatch(r'\.?Lfunc_begin\d+', name) and pc == 0]
    require(len(begin) == 1, 'original function base for LSDA offsets')
    begin = begin[0]
    endings = [line[:-1] for line in lines if re.fullmatch(r'\.?Lfunc_end\d+:', line)]
    require(len(endings) == 1 and labels.get(endings[0]) == len(code),
            'one exact machine function end for LSDA ranges')
    positions = labels
    records, covered, previous = [], {}, 0
    for offset in range(0, len(entries), 4):
        start, length, landing, action = entries[offset:offset + 4]
        first = re.fullmatch(r'\.uleb128 (' + machine.LABEL + ')-' + re.escape(begin), start)
        require(first is not None and first[1] in positions, 'call-site start is function-relative')
        last = re.fullmatch(r'\.uleb128 (' + machine.LABEL + ')-' + re.escape(first[1]), length)
        require(last is not None and last[1] in positions, 'call-site length matches its start')
        left, right = positions[first[1]], positions[last[1]]
        require(previous <= left < right <= len(code), 'ordered nonoverlapping nonempty call-site ranges')
        previous = right
        require(action in ('.byte 0', '.byte 1', '.byte 5'), 'reviewed action-table index')
        if landing == '.byte 0':
            require(action == '.byte 0', 'absent landing pad has no action')
            pad = None
        else:
            match = re.fullmatch(r'\.uleb128 (' + machine.LABEL + ')-' + re.escape(begin), landing)
            require(match is not None and match[1] in labels and labels[match[1]] < len(code),
                    'landing pad is executable and function-relative')
            pad = labels[match[1]]
        records.append((left, right, pad, offset // 4))
        for pc in range(left, right):
            if code[pc][0] in ('bl', 'blr', 'callq'):
                covered[pc] = pad
    expected = ['.byte 127', '.byte 0', '.byte 0', '.byte 0', '.byte 1', '.byte 125',
                '.p2align 2, 0x0', '.xword 0' if arm and not apple else '.long 0',
                types[1] + ':', '.byte 0', '.p2align 2, 0x0']
    require(lines[stop + 1:stop + 1 + len(expected)] == expected, 'reviewed action/type table bytes')
    return code, labels, raw, covered, records
