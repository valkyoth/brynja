"""Actual hosted constructor admission, scratch and post-admission transfers.

The source-bound typed hash factory/update/finalizer contracts are still callee
premises. This is logical owner and explicit scratch cleanup, not a claim about
compiler-generated copies or arbitrary caller frames.
"""
import hmac_hosted_callee_admission as admission
import hmac_execution_construct as construct
import hmac_execution_scratch as scratch
import hmac_engine_construct as scalar_construct
import hmac_engine_scratch as scalar_scratch
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import re


def check(model, identity, definitions, aliases, compiler, panic, types):
    symbol, body = admission.resolve(model, identity, definitions, aliases)
    scratch.check_body(body, 'construct_static', definitions, aliases)
    for route in range(8):
        for long_key in (False, True):
            construct.check(body, identity, definitions, aliases, compiler, panic,
                            route, long_key, types, profile='static', dynamic_tag=True)
    return symbol


def scalar(model, identity, definitions, aliases, panic):
    common.require(not model.compiled, 'scalar constructor requires scalar worker')
    algorithm = ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                 else 'brynja_mac_hmac::algorithms::Sha' + identity[3:])
    expected = ('<brynja_mac_hmac::engine::Engine<' + algorithm + '>>::new_with::<'
                + '<' + algorithm + ' as brynja_mac_hmac::algorithms::sealed::Hash>::start>')
    symbols = {symbol for symbol, _, point in model.calls if point in model.factories}
    common.require(len(symbols) == 1, 'scalar constructor callee population changed')
    symbol = symbols.pop()
    common.require(model.names.get(symbol) == expected, 'scalar constructor callee identity changed')
    arguments, body = common.resolve(symbol, definitions, aliases)
    formals = syntax.parameters(arguments)
    expected_formals = (('ptr', '%_0'), ('ptr', '%key.0'), ('i64', '%key.1'), ('i64', '%tag_bytes'))
    common.require(len(formals) == len(expected_formals) and all(
        re.fullmatch(kind + r' [^%]*' + re.escape(name), formal)
        for formal, (kind, name) in zip(formals, expected_formals)), 'scalar constructor formal binding changed')
    scalar_scratch.check(body, 'construct')
    scalar_construct.check(body, identity, panic, dynamic_tag=True)
    return symbol
