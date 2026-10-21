"""Bind public verification arguments and decisions to the checked executor.

The executor and its worker comparison are checked separately. This bridge
must preserve their boolean/error result, not merely call a correctly named
executor and then return a substituted decision.
"""
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_loan_flow as flow
import hmac_hosted_loans as loans

require = common.require


def results(compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unknown public verify compiler')
    ok = 255 if compiler == '1.99.1' else 11
    yield from ((ok, payload, True) for payload in (0, 1, 2))
    # Exhaust the padding byte of unit errors rather than assign it a value
    # which could accidentally make a forged success branch appear valid.
    domains = {0: range(14), 7: range(10), 9: range(7)}
    for category in range(11):
        yield from ((category, payload, category in domains)
                    for payload in domains.get(category, range(256)))


def check(arguments, body, names, target, compiler, identity, compiled):
    loans.formals(arguments, [('ptr', '%session'), ('ptr', '%request'), ('ptr', '%candidate.0'),
                              ('i64', '%candidate.1'), ('ptr', '%cancel')])
    formals = syntax.parameters(arguments)
    require('dereferenceable(' + ('272' if compiled else '256') + ')' in formals[0]
            and 'dereferenceable(56)' in formals[1], 'public verify session/request extent changed')
    owner, _ = lifecycle.profile(target)
    algorithm = ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                 else 'algorithms::Sha' + identity[3:])
    expected = '<' + owner + '::' + ('compiled::CompiledSession' if compiled else 'Session')
    expected += '<brynja_mac_hmac::' + algorithm + '>>::execute'
    ok = 255 if compiler == '1.99.1' else 11
    initial = {'%session': ('session', 0), '%request': ('request', 0),
               '%candidate.0': ('candidate', 0), '%candidate.1': 'candidate-length',
               '%cancel': ('cancel', 0)}
    visited = set()
    for category, payload, meaningful in results(compiler):
        calls = []

        def call(symbol, args, value):
            require(names.get(symbol) == expected and len(args) == 5 and not calls
                    and tuple(value(arg) for arg in args) == tuple(initial.values()),
                    'public verify executor identity/arguments changed')
            calls.append(symbol)
            return 'return', category | payload << 8

        outcome, result, reached = flow.run(body, initial, {}, call)
        require(outcome == 'return' and len(calls) == 1, 'public verify exit/execution changed')
        encoded = flow.expressions.integer(result, 16)
        expected_category = (10 if payload == 2 else ok) if category == ok else category
        require(encoded & 255 == expected_category, 'public verify result category changed')
        if meaningful and not (category == ok and payload == 2):
            require(encoded >> 8 == payload, 'public verify decision/error payload changed')
        visited |= reached
    require(visited == set(common.blocks(body)), 'unreviewed public verify path')


def validate(definitions, aliases, names, target, compiler):
    for identity in common.IDENTITIES:
        for compiled, method in ((False, 'verify'), (True, 'compiled_verify')):
            expected = 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method
            selected = [symbol for symbol in (*definitions, *aliases) if names[symbol] == expected]
            require(len(selected) == 1, 'missing/ambiguous public verify probe')
            check(*common.resolve(selected[0], definitions, aliases), names, target, compiler, identity, compiled)
