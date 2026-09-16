"""Closed uses of the memory-backed coordinator Storage header.

Compiler-specific Vec layout, not a Rust ABI promise. The original header must
not escape; only reviewed allocation helpers may mutate it before worker entry.
This does not prove allocator internals, backing-buffer aliases or worker joins.
"""
import re

import batch_worker_cfg as cfg
from batch_cleanup_flow import require

V = cfg.VALUE
ATOM = '(?:' + V + r'|-?\d+|null|inttoptr \(i64 1 to ptr\))'
GROW = (r'_RNvMs2_NtCs\w+_5alloc7raw_vecNtB5_11RawVecInner10grow_exactCs\w+_24brynja_hash_parallel_std',
        r'_RINvNvMs2_NtCs\w+_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handle'
        r'NtNtBa_5alloc6GlobalECs\w+_24brynja_hash_parallel_std')


def header(blocks):
    roots = [(block, m[1]) for block, lines in blocks.items() for line in lines
             if (m := re.fullmatch(r'(%storage(?:\.[\w.]+)?) = alloca \[24 x i8\], align 8', line))]
    require(len(roots) == 1 and roots[0][0] == 'start', 'one original entry-block Storage header')
    root = roots[0][1]
    fields = {root: 0}
    for lines in blocks.values():
        for line in lines:
            match = re.fullmatch('(' + V + r') = getelementptr inbounds(?: nuw)? i8, ptr ' +
                                 re.escape(root) + r', i64 (8|16)', line)
            if match:
                fields[match[1]] = int(match[2])
    require(set(fields.values()) == {0, 8, 16}, 'complete Storage field addresses')
    return root, fields


def uses(line, root, fields, drop):
    """Classify ALL uses of header addresses, rejecting unknown alias/escape paths."""
    operation = cfg.operation(line)
    refs = set(re.findall(V, operation)) & fields.keys()
    symbol = cfg.callee(line)
    if drop is not None and symbol == drop:
        require(re.search(r'\(ptr (?:[\w()]+ )*' + re.escape(root) + r'\)(?: #\d+)?(?: to label .*)?$',
                          operation) is not None and refs == {root}, 'drop receives original header')
        return 'drop', None
    if not refs:
        return None, None
    if re.fullmatch(r'getelementptr inbounds(?: nuw)? i8, ptr ' + re.escape(root) + r', i64 (8|16)', operation):
        return 'address', None
    load = re.fullmatch(r'load (ptr|i64), ptr (' + V + r'), align 8', operation)
    if load:
        field = fields[load[2]]
        require(load[1] == ('ptr' if field == 8 else 'i64'), 'correct header load width')
        return 'load', field
    store = re.fullmatch(r'store (ptr|i64) (' + ATOM + r'), ptr (' + V + r'), align 8', operation)
    if store:
        require(store[3] in fields and store[2] not in fields, 'no header address stored/escaped')
        field = fields[store[3]]
        require(store[1] == ('ptr' if field == 8 else 'i64'), 'correct header store width')
        return 'store', (field, store[2])
    if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
        require(re.fullmatch(r'call void @llvm.lifetime.(?:start|end).p0\((?:i64 24, )?ptr nonnull ' +
                             re.escape(root) + r'\)', operation) is not None, 'exact header lifetime extent')
        return ('start' if '.start.' in symbol else 'end'), None
    if symbol and any(re.fullmatch(pattern, symbol) for pattern in GROW):
        require(refs == {root} and re.search(r'\(ptr (?:[\w()]+ )*' + re.escape(root) +
                r', (?:i64 noundef ' + ATOM + r', ){2}i64 noundef 256\)(?: #\d+)?(?: to label .*)?$', operation),
                'reviewed Vec reservation receives only original header and slot size')
        return 'grow', None
    raise ValueError('worker header address escaped or has unreviewed use: ' + line)


def clear_arguments(line, symbol):
    match = re.fullmatch(r'(?:tail )?(?:call|invoke) fastcc void @' + re.escape(symbol) +
                         r'\(ptr nonnull (' + ATOM + r'), i64 (' + ATOM +
                         r')\)(?: #\d+)?(?: to label .*)?', cfg.operation(line))
    require(match is not None, 'exact two-argument worker clear call')
    return match.groups()
