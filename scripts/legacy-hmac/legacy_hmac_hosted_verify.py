"""Exact public verification result propagation, including compiled forwarding."""
import re

import legacy_hmac_hosted_batch_flow as flow
from legacy_hmac_hosted_loans import formals

require = flow.require


def typed(population, compiler):
    definitions, aliases, names = population
    ok = 255 if compiler == '1.99.1' else 10
    for name, expected in (('rejected_tag', ok), ('accepted_tag', ok | 256), ('invalid_result', 8)):
        selected = [s for s in (*definitions, *aliases)
                    if names.get(s) == 'brynja_legacy_hmac_hosted_cleanup::verification::' + name]
        require(len(selected) == 1, 'public verification typed probe missing/ambiguous')
        signature, body = flow.common.resolve(selected[0], definitions, aliases)
        graph = flow.common.blocks(body)
        require(not signature and len(graph) == 1, 'public verification typed probe signature changed')
        lines = next(iter(graph.values()))
        require(len(lines) == 1, 'public verification typed probe gained effects')
        returned = re.fullmatch(r'ret i16 (\d+)', lines[0])
        require(returned and (int(returned[1]) & (255 if name == 'invalid_result' else 65535)) == expected,
                'public verification Result ABI changed')


def check(signature, body, names, target, compiler, identity, executor, forwarding=False):
    kinds = ('ptr', 'ptr', 'ptr', 'ptr') if identity == 'md5_compiled' else ('ptr', 'ptr', 'ptr', 'i64', 'ptr')
    _, params = formals(signature, kinds)
    ok = 255 if compiler == '1.99.1' else 10
    resources = 14 if target == 'aarch64-apple-darwin' else 13
    cases = [(ok, n) for n in range(2 if forwarding else 3)]
    cases += [(tag, payload) for tag in range(10)
              for payload in {0: range(resources), 7: range(8)}.get(tag, range(256))]
    reached = set()
    for category, payload in cases:
        actual = tuple(('arg-' + str(i), 0) if kind == 'ptr' else 17 for i, kind in enumerate(kinds))
        initial, calls = dict(zip(params, actual)), []
        # Exhaust every padding byte for unit errors. It may be returned but
        # must not select a different public category or verification decision.
        encoded = category | (payload << 8)

        def call(symbol, operands, value):
            require(names.get(symbol) == executor and not calls
                    and tuple(map(value, operands)) == actual, 'public verify dispatch/operands changed')
            calls.append(symbol)
            return 'return', encoded

        outcome, result, visited = flow.run(body, initial, {}, call)
        require(outcome == 'return' and len(calls) == 1, 'public verify bypassed execution')
        expected = 8 if not forwarding and category == ok and payload == 2 else category
        require(flow.expressions.integer(result, 8) == expected, 'public verify changed success/error category')
        if category in (0, 7, ok) and expected != 8:
            require(flow.expressions.integer(result, 16) >> 8 == payload, 'public verify changed decision/error payload')
        reached |= visited
    require(reached == set(flow.common.blocks(body)), 'public verify has unreviewed path')
    return len(cases)
