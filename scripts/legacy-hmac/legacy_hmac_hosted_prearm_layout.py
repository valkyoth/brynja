"""Independent emitted getters for public request and limit metadata."""
import re

import legacy_hmac_hosted_md5_report_layout as layout

FIELDS = {
    'scalar_key_limit': (64, 40, 'i64'), 'batch_key_limit': (64, 40, 'i64'),
    'scalar_chunk_limit': (64, 48, 'i64'),
    'scalar_bit_limit': (64, 0, 'i128'), 'batch_bit_limit': (64, 0, 'i128'),
    'key_length': (56, 8, 'i64'), 'chunk_count': (56, 24, 'i64'),
    'tail_length': (56, 40, 'i64'), 'tail_bits': (56, 48, 'i8'),
    'scalar_width': (240, 64, 'i64'), 'compiled_width': (256, 64, 'i64'),
}


def validate(population):
    definitions, aliases, names = population
    for name, (extent, offset, kind) in FIELDS.items():
        wanted = 'brynja_legacy_hmac_hosted_cleanup::admission::' + name
        selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
        layout.require(len(selected) == 1, 'pre-arm typed probe missing/ambiguous: ' + name)
        args, body = layout.flow.resolve(selected[0], definitions, aliases)
        args = layout.syntax.parameters(args)
        graph = layout.flow.blocks(body)
        layout.require(len(args) == 1 and 'dereferenceable(' + str(extent) + ')' in args[0]
                       and len(graph) == 1, 'pre-arm typed probe ABI changed')
        cursor = layout.checked.Cursor(next(iter(graph.values())), names)
        address = layout.syntax.operand(args[0])
        if offset:
            address, = cursor.take('(' + layout.V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                   + re.escape(address) + ', i64 ' + str(offset))
        result, = cursor.take('(' + layout.V + ') = load ' + kind + ', ptr ' + re.escape(address) + ', align (?:8|16)')
        cursor.take('ret ' + kind + ' ' + re.escape(result))
        cursor.end()
