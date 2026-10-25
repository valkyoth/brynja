"""Typed projections bind the consumer Result niches and report offsets."""
import re

import legacy_hmac_hosted_md5_report_layout as layout

syntax, flow, require, V = layout.syntax, layout.flow, layout.require, layout.V
LAYOUTS = {'verification': (96, 88, 8), 'authentication': (120, 0, 32)}


def validate(population):
    definitions, aliases, names = population
    for name, (extent, discriminator, report) in LAYOUTS.items():
        wanted = 'brynja_legacy_hmac_hosted_cleanup::report_result::' + name
        symbols = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
        require(len(symbols) == 1, 'missing/ambiguous typed MD5 Result projection')
        arguments, body = flow.resolve(symbols[0], definitions, aliases)
        blocks = flow.blocks(body)
        require(len(blocks) == 1, 'conditional MD5 Result projection')
        cursor = layout.checked.Cursor(next(iter(blocks.values())), names)
        value = layout.field(arguments, cursor, discriminator, 'i8', extent)
        condition, = cursor.take('(' + V + ') = icmp eq i8 ' + re.escape(value) + ', 2')
        root = syntax.operand(syntax.parameters(arguments)[0])
        if ' = select ' in cursor.rows[cursor.index]:
            root, = cursor.take('(' + V + ') = select i1 ' + re.escape(condition)
                                 + ', ptr null, ptr ' + re.escape(root))
        address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                               + re.escape(root) + ', i64 ' + str(report))
        selected, = cursor.take('(' + V + ') = select i1 ' + re.escape(condition)
                                + ', ptr null, ptr ' + re.escape(address))
        cursor.take('ret ptr ' + re.escape(selected))
        cursor.end()
