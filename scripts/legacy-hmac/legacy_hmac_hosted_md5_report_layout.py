"""Independent typed field/slot probes for the hosted report admission model."""
import re

import legacy_hmac_hosted_md5_checkpoint as checked

require, syntax, flow, V = checked.require, checked.syntax, checked.flow, checked.V
FIELDS = {'backend': (80, 'i8'), 'width': (0, 'i64'), 'inner_active': (32, 'i64'),
          'outer_active': (56, 'i64'), 'inner_vector': (48, 'i64'), 'outer_vector': (72, 'i64')}


def probe(population, name):
    definitions, aliases, names = population
    wanted = 'brynja_legacy_hmac_hosted_cleanup::report::' + name
    symbols = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
    require(len(symbols) == 1, 'missing/ambiguous typed MD5 report probe: ' + name)
    arguments, body = flow.resolve(symbols[0], definitions, aliases)
    graph = flow.blocks(body)
    require(len(graph) == 1, 'conditional typed MD5 report probe')
    return arguments, checked.Cursor(next(iter(graph.values())), names)


def field(arguments, cursor, offset, kind, extent):
    args = syntax.parameters(arguments)
    require(len(args) == 1 and 'dereferenceable(' + str(extent) + ')' in args[0], 'MD5 probe extent changed')
    root = syntax.operand(args[0])
    address = root
    if offset:
        address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                               + re.escape(root) + ', i64 ' + str(offset))
    value, = cursor.take('(' + V + ') = load ' + kind + ', ptr ' + re.escape(address) + ', align 8')
    return value


def validate(population):
    for name, (offset, kind) in FIELDS.items():
        arguments, cursor = probe(population, name)
        value = field(arguments, cursor, offset, kind, 88)
        if name == 'backend':
            value, = cursor.take('(' + V + ') = trunc(?: nuw)? i8 ' + re.escape(value) + ' to i1')
            kind = 'i1'
        cursor.take('ret ' + kind + ' ' + re.escape(value))
        cursor.end()
    arguments, cursor = probe(population, 'backend_width')
    args = syntax.parameters(arguments)
    require(len(args) == 1 and args[0].startswith('i1 '), 'MD5 backend domain changed')
    value, = cursor.take('(' + V + ') = select i1 ' + re.escape(args[0].split()[-1]) + ', i64 4, i64 8')
    cursor.take('ret i64 ' + re.escape(value))
    cursor.end()
    for index in range(8):
        arguments, cursor = probe(population, 'slot' + str(index))
        value = field(arguments, cursor, index * 40, 'ptr', 320)
        condition, = cursor.take('(' + V + ') = icmp ne ptr ' + re.escape(value) + ', null')
        cursor.take('ret i1 ' + re.escape(condition))
        cursor.end()
