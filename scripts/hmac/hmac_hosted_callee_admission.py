"""Reuse constructor authority admission against the actual hosted callees, not a lookalike fixture."""
import re

import hmac_engine_final as syntax
import hmac_engine_codegen as common
import hmac_execution_admission as admission


def resolve(model, identity, definitions, aliases):
    common.require(model.compiled, 'callee authority admission requires a compiled worker')
    algorithm = ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                 else 'brynja_mac_hmac::algorithms::Sha' + identity[3:])
    expected = '<brynja_mac_hmac::execution::Hmac<' + algorithm + '>>::create'
    symbols = {symbol for symbol, _, point in model.calls if point in model.factories}
    common.require(len(symbols) == 1, 'hosted constructor callee population changed')
    symbol = symbols.pop()
    common.require(model.names.get(symbol) == expected, 'hosted authority constructor identity changed')
    arguments, body = common.resolve(symbol, definitions, aliases)
    formals = syntax.parameters(arguments)
    expected_formals = (('ptr', '%_0'), ('ptr', '%owner'), ('ptr', '%key.0'), ('i64', '%key.1'), ('i64', '%tag_bytes'))
    common.require(len(formals) == len(expected_formals) and all(
        re.fullmatch(kind + r' [^%]*' + re.escape(name), formal)
        for formal, (kind, name) in zip(formals, expected_formals)), 'hosted constructor formal binding changed')
    return symbol, body


def check(model, identity, definitions, aliases, compiler, panic):
    symbol, body = resolve(model, identity, definitions, aliases)
    # This is the existing static pre-key admission proof, now applied to the
    # exact function referenced by this worker. It binds all three hash factories
    # (and three Source::sha2 sessions for general SHA-512/t) to %owner, with
    # success/failure/unwind ownership, before any key-byte access.
    for route in range(8):
        for long_key in (False, True):
            admission.check(body, identity, definitions, aliases, compiler, panic, route, long_key, 'static')
    return symbol
