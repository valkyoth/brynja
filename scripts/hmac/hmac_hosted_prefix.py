"""Checked abstraction of an outlined fractional-prefix constructor.

After validating the entire emitted wrapper, its calls can be modeled as calls
to the exact underlying create function. This overapproximates outcomes: the
wrapper may reject before construction, never create more owners or read keys.
It is NOT an instruction-equivalence or timing claim. Other compiler shapes
fail closed until reviewed; no symbol-only allowlist authorizes this abstraction.
"""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as cleanup

require = common.require
SUFFIX = '>::from_static_with_tag_length'


def canonical(body):
    """Ignore SSA/label spelling and metadata, never instructions or constants."""
    graph = common.blocks(body)
    labels = {name: 'block' + str(index) for index, name in enumerate(graph)}
    values = {}
    lines = []
    for label, instructions in graph.items():
        lines.append(labels[label] + ':')
        for line in instructions:
            line = line.split(', !', 1)[0]
            for old, new in sorted(labels.items(), key=lambda item: -len(item[0])):
                line = re.sub(r'(?<=%)' + re.escape(old) + r'(?![-\w.$])', new, line)
            def variable(match):
                value = match[0]
                if value in ('%_0', '%owner', '%key.0', '%key.1', '%tag_bytes') or value[1:] in labels.values():
                    return value
                if value not in values:
                    values[value] = '%v' + str(len(values))
                return values[value]
            lines.append(re.sub(syntax.VALUE, variable, line))
    return lines


def check(symbol, definitions, aliases, names, compiler):
    name = names[symbol]
    match = re.fullmatch(r'<brynja_mac_hmac::execution::Hmac<brynja_mac_hmac::general::Sha512T<(\d+)>>>'
                         + re.escape('::from_static_with_tag_length'), name)
    require(match and match[1] == '129' and compiler == '1.99.1',
            'unreviewed outlined prefix identity/compiler')
    shape = cleanup.layout('general129', 'static')
    arguments, body = common.resolve(symbol, definitions, aliases)
    formals = syntax.parameters(arguments)
    expected_formals = [('ptr', '%_0'), ('ptr', '%owner'), ('ptr', '%key.0'),
                        ('i64', '%key.1'), ('i64', '%tag_bytes')]
    require(len(formals) == 5 and all(re.fullmatch(kind + r' [^%]*' + re.escape(value), formal)
            for formal, (kind, value) in zip(formals, expected_formals)), 'prefix formal binding')
    calls = [syntax.call(line) for line in body.splitlines() if syntax.call(line)]
    require(len(calls) == 1, 'prefix callee population')
    target, args = calls[0]
    require(names.get(target) == name.removesuffix('from_static_with_tag_length') + 'create',
            'prefix constructor identity changed')
    require(len(args) == 5 and all(re.fullmatch(kind + r' [^%]*' + re.escape(value), arg)
            for arg, (kind, value) in zip(args, expected_formals)), 'prefix argument substitution')
    target_args, _ = common.resolve(target, definitions, aliases)
    target_formals = syntax.parameters(target_args)
    require(len(target_formals) == 5 and all(re.fullmatch(kind + r' [^%]*' + re.escape(value), formal)
            for formal, (kind, value) in zip(target_formals, expected_formals)), 'prefix callee formal binding')
    # Inspect every instruction, including all stores and branches. The complete
    # u64 domain is bounded structurally: overflow rejects; the second guard
    # accepts exactly 16 (and-mask equality plus unsigned <= 16). No key/owner
    # access is permitted before the sole constructor call. Error writes set
    # the known Err niche, not any live-owner representation.
    lines = canonical(body)
    call_lines = [line for line in lines if syntax.call(line)]
    require(len(call_lines) == 1 and re.fullmatch(r'tail call fastcc void @[^\s(]+\(.*\)(?: #\d+)?', call_lines[0]),
            'prefix call convention/unwind changed')
    lines[lines.index(call_lines[0])] = 'CREATE'
    require(lines == [
        'block0:', '%v0 = icmp ugt i64 %tag_bytes, 2305843009213693951',
        'br i1 %v0, label %block2, label %block1',
        'block1:', '%v1 = and i64 %tag_bytes, 2305843009213693950',
        '%v2 = icmp ne i64 %v1, 16', '%v3 = icmp samesign ugt i64 %tag_bytes, 16',
        '%v4 = or i1 %v2, %v3', 'br i1 %v4, label %block2, label %block3',
        'block2:', 'store i8 8, ptr %_0, align 16',
        f'%v5 = getelementptr inbounds nuw i8, ptr %_0, i64 {shape.discriminator}',
        'store i8 -1, ptr %v5, align 1', 'br label %block4',
        'block3:', 'CREATE', 'br label %block4', 'block4:', 'ret void',
    ], 'unreviewed prefix admission/transfer body')
    return target


def abstract(definitions, aliases, names, compiler):
    wrappers = {symbol: check(symbol, definitions, aliases, names, compiler)
                for symbol in (*definitions, *aliases) if names[symbol].endswith(SUFFIX)}
    if not wrappers:
        return definitions
    result = dict(definitions)
    for symbol, (arguments, body) in definitions.items():
        if symbol in wrappers:
            continue  # Retain the real, validated wrapper as evidence.
        for wrapper, target in wrappers.items():
            # Change only a direct call/invoke symbol. Caller arguments and
            # normal/unwind edges stay byte-for-byte intact for the other models.
            body = re.sub(r'(\b(?:call|invoke)\b[^\n@]*@)' + re.escape(wrapper) + r'(?=\()',
                          lambda m: m[1] + target, body)
        result[symbol] = arguments, body
    return result
