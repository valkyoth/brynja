"""Bind successful compute Results to the session's retained output and width."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_loan_flow as flow
import hmac_hosted_loans as loans
import hmac_hosted_lifecycle as lifecycle

require = common.require


def check(arguments, body, names, target, compiler, identity, compiled):
    loans.formals(arguments, [('ptr', '%_0'), ('ptr', '%session'), ('ptr', '%request'), ('ptr', '%cancel')])
    formals = syntax.parameters(arguments)
    require('sret([16 x i8])' in formals[0] and 'dereferenceable(16)' in formals[0]
            and 'dereferenceable(' + ('272' if compiled else '256') + ')' in formals[1],
            'compute Result/session extent changed')
    owner, _ = lifecycle.profile(target)
    algorithm = ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                 else 'algorithms::Sha' + identity[3:])
    expected = '<' + owner + '::' + ('compiled::CompiledSession' if compiled else 'Session')
    expected += '<brynja_mac_hmac::' + algorithm + '>>::execute'
    ok = 255 if compiler == '1.99.1' else 11
    # Match the already-checked execute Result domain; unit-error padding stays
    # unknown rather than being used to justify admission or a pointer.
    results = [(ok, 2)]
    domains = {0: range(14), 7: range(10), 9: range(7)}
    results += [(category, payload) for category in range(11)
                for payload in domains.get(category, (None,))]
    visited = set()
    for category, payload in results:
        encoded = category | payload << 8 if payload is not None else flow.expressions.Unknown(category, 255)
        output, calls = {}, []
        initial = {'%_0': ('result', 0), '%session': ('session', 0),
                   '%request': ('request', 0), '%cancel': ('cancel', 0)}
        memory = {('session', 248): 'selected-bits'}

        def call(symbol, args, value):
            require(names.get(symbol) == expected and len(args) == 5 and not calls
                    and value(args[0]) == ('session', 0) and value(args[1]) == ('request', 0)
                    and value(args[2]) is None and isinstance(value(args[3]), flow.expressions.Unknown)
                    and value(args[4]) == ('cancel', 0), 'compute executor identity/arguments changed')
            calls.append('execute')
            return 'return', encoded

        def store(address, kind, value):
            require(calls and address[0] == 'result', 'compute writes before execution/outside Result')
            offset = address[1]
            require((offset, kind) in ((0, 'ptr'), (8, 'i8'), (9, 'i8'), (8, 'i16'), (8, 'i64')),
                    'compute Result write shape changed')
            slots = (8, 9) if kind == 'i16' else (offset,)
            require(not any(slot in output for slot in slots), 'compute overwrites Result field')
            if kind == 'i16':
                number, known = flow.expressions.parts(value)
                require(type(number) is int, 'compute error payload is not integer')
                output[8] = flow.expressions.Unknown(number & 255, known & 255)
                output[9] = flow.expressions.Unknown((number >> 8) & 255, (known >> 8) & 255)
            else:
                output[offset] = value

        def load(address, kind):
            require(calls and category == ok and address == ('session', 248) and kind == 'i64',
                    'compute reads output metadata before successful execution')

        outcome, result, reached = flow.run(body, initial, memory, call, store, load)
        require(outcome == 'return' and result is None and len(calls) == 1, 'compute loan exit changed')
        if category == ok:
            require(output == {0: ('session', 192), 8: 'selected-bits'},
                    'compute returned wrong output loan/selected width')
        else:
            require(set(output) == {0, 8, 9} and output[0] is None
                    and flow.expressions.integer(output[8], 8) == category,
                    'compute admits a loan or changes an error')
            if payload is not None:
                require(flow.expressions.integer(output[9], 8) == payload, 'compute changes error payload')
        visited |= reached
    require(visited == set(common.blocks(body)), 'unreviewed compute loan construction path')


def validate(definitions, aliases, names, target, compiler):
    for identity in common.IDENTITIES:
        for compiled, operation in ((False, 'compute'), (True, 'compiled_compute')):
            expected = 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + operation
            selected = [symbol for symbol in (*definitions, *aliases) if names[symbol] == expected]
            require(len(selected) == 1, 'missing/ambiguous compute loan constructor')
            check(*common.resolve(selected[0], definitions, aliases), names, target, compiler, identity, compiled)
