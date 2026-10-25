"""Typed host inputs, private Input construction and BitString Result geometry."""
import re

import legacy_hmac_hosted_md5_report_layout as layout

syntax, flow, require, V = layout.syntax, layout.flow, layout.require, layout.V
FIELDS = {'key_pointer': (0, 'ptr'), 'key_length': (8, 'i64'),
          'message_pointer': (16, 'ptr'), 'message_length': (24, 'i64'), 'valid_bits': (32, 'i8')}


def probe(population, name):
    definitions, aliases, names = population
    wanted = 'brynja_legacy_hmac_hosted_cleanup::lane::' + name
    symbols = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
    require(len(symbols) == 1, 'missing/ambiguous typed MD5 lane probe')
    arguments, body = flow.resolve(symbols[0], definitions, aliases)
    blocks = flow.blocks(body)
    require(len(blocks) == 1, 'conditional typed MD5 lane probe')
    return arguments, layout.checked.Cursor(next(iter(blocks.values())), names)


def validate(population):
    for name, (offset, kind) in FIELDS.items():
        arguments, cursor = probe(population, name)
        value = layout.field(arguments, cursor, offset, kind, 40)
        cursor.take('ret ' + kind + ' ' + re.escape(value))
        cursor.end()
    arguments, cursor = probe(population, 'present')
    value = layout.field(arguments, cursor, 0, 'ptr', 48)
    present, = cursor.take('(' + V + ') = icmp ne ptr ' + re.escape(value) + ', null')
    cursor.take('ret i1 ' + re.escape(present))
    cursor.end()
    arguments, cursor = probe(population, 'bit_result')
    value = layout.field(arguments, cursor, 0, 'ptr', 32)
    root = syntax.operand(syntax.parameters(arguments)[0])
    failed, = cursor.take('(' + V + ') = icmp eq ptr ' + re.escape(value) + ', null')
    projected, = cursor.take('(' + V + ') = select i1 ' + re.escape(failed) + ', ptr null, ptr ' + re.escape(root))
    cursor.take('ret ptr ' + re.escape(projected))
    cursor.end()
    arguments, cursor = probe(population, 'inactive')
    args = syntax.parameters(arguments)
    require(len(args) == 1 and 'sret([384 x i8])' in args[0], 'MD5 lane-array extent changed')
    dest = syntax.operand(args[0])
    clear = cursor.call('llvm.memset.p0.i64')
    require(len(clear) == 4 and syntax.operand(clear[0]) == dest
            and clear[1:] == ['i8 0', 'i64 384', 'i1 false'], 'MD5 inactive initialization changed')
    cursor.take('ret void')
    cursor.end()
    arguments, cursor = probe(population, 'input')
    args = syntax.parameters(arguments)
    require(len(args) == 4 and 'sret([48 x i8])' in args[0] and args[1].startswith('ptr ')
            and args[2].startswith('i64 ') and 'dereferenceable(32)' in args[3], 'MD5 Input constructor ABI changed')
    dest, key, length, message = (arg.split()[-1] for arg in args)
    cursor.take('store ptr ' + re.escape(key) + ', ptr ' + re.escape(dest) + ', align 8')
    address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + re.escape(dest) + ', i64 8')
    cursor.take('store i64 ' + re.escape(length) + ', ptr ' + re.escape(address) + ', align 8')
    address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + re.escape(dest) + ', i64 16')
    copy = cursor.call('llvm.memcpy.p0.p0.i64')
    require(len(copy) == 4 and [syntax.operand(arg) for arg in copy[:2]] == [address, message]
            and copy[2:] == ['i64 32', 'i1 false'], 'MD5 Input descriptor transfer changed')
    cursor.take('ret void')
    cursor.end()
