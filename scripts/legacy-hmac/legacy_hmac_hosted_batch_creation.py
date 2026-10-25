"""Bind the public MD5 batch Result to the joined executor and eight inputs."""
import itertools
from functools import lru_cache

import legacy_hmac_hosted_loans as loans

flow, require = loans.flow, loans.require


def creation(arguments, body, names, target, compiler, executor):
    return _creation(arguments, body, tuple(sorted(names.items())), target, compiler, executor)


@lru_cache(maxsize=16)
def _creation(arguments, body, symbol_names, target, compiler, executor):
    # Only successful, exact in-process projections are reused. All input
    # identities participate; there is no persistent evidence/approval cache.
    names = dict(symbol_names)
    args, params = loans.formals(arguments, ('ptr', 'ptr', 'ptr', 'ptr'))
    require('sret([24 x i8])' in args[0] and 'dereferenceable(24)' in args[0]
            and 'dereferenceable(256)' in args[1] and 'dereferenceable(320)' in args[2],
            'batch loan Result/session/input extent changed')
    ok = 255 if compiler == '1.99.1' else 10
    resources = 14 if target == 'aarch64-apple-darwin' else 13
    cases = [(ok, 2, mask, width) for mask, width in itertools.product(range(256), range(10, 17))]
    cases += [(tag, payload, 0, 10) for tag in range(10)
              for payload in {0: range(resources), 7: range(8)}.get(tag, (None,))]
    reached = set()
    for category, payload, mask, width in cases:
        output, calls, reads = {}, [], set()
        memory = {('inputs', lane * 40): ('input-' + str(lane), 0) if mask & (1 << lane) else None
                  for lane in range(8)}
        memory['session', 64] = width
        encoded = category | payload << 8 if payload is not None else flow.expressions.Unknown(category, 255)

        def call(symbol, operands, value):
            require(names.get(symbol) == executor and len(operands) == 4 and not calls
                    and [value(arg) for arg in operands] == [('session', 0), ('inputs', 0), None, ('cancel', 0)],
                    'batch loan executor provenance changed')
            calls.append('execute')
            return 'return', encoded

        def load(address, kind):
            require(calls and category == ok and address not in reads
                    and kind == ('i64' if address == ('session', 64) else 'ptr'),
                    'batch loan metadata read before admission/wrong type')
            reads.add(address)

        def store(address, kind, value):
            require(calls and address[0] == 'result', 'batch loan write outside admitted Result')
            offset = address[1]
            require((offset, kind) in ((0, 'i8'), (1, 'i8'), (2, 'i8'), (1, 'i16'),
                                      (0, 'i64'), (8, 'ptr'), (16, 'i64')), 'batch loan Result field width')
            slots = list(range(8)) if (offset, kind) == (0, 'i64') else ([1, 2] if kind == 'i16' else [offset])
            require(not any(slot in output for slot in slots), 'batch loan field overwritten')
            if len(slots) > 1:
                number, known = flow.expressions.parts(value)
                require(type(number) is int, 'batch loan packed field is not integer')
                for i, slot in enumerate(slots):
                    output[slot] = flow.expressions.Unknown((number >> (i * 8)) & 255, (known >> (i * 8)) & 255)
            else:
                output[offset] = value

        initial = dict(zip(params, (('result', 0), ('session', 0), ('inputs', 0), ('cancel', 0))))
        outcome, result, visited = flow.run(body, initial, memory, call, store, load)
        require(outcome == 'return' and result is None and calls == ['execute'], 'batch loan factory exit')
        if category == ok:
            require(set(output) == {*range(8), 8, 16} and output[8] == ('session', 184) and output[16] == width
                    and reads == set(memory), 'batch loan storage/width/input population changed')
            require(all(flow.expressions.integer(output[lane], 8) == ((mask >> lane) & 1) for lane in range(8)),
                    'batch loan activity is not the matching input lane')
        else:
            require(not reads and set(output) == {0, 1, 2} and output[0] == 2
                    and flow.expressions.integer(output[1], 8) == category, 'batch loan error admits output/changes category')
            if payload is not None:
                require(flow.expressions.integer(output[2], 8) == payload, 'batch loan error payload changed')
        reached |= visited
    require(reached == set(flow.common.blocks(body)), 'batch loan factory has unreviewed paths')
    return len(cases)
