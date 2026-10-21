"""Bind scalar hosted terminal handoffs to their actual consuming Engine bodies.

This checks logical owner consumption and explicit scratch clear dispatch on
normal/error/unwind paths. Hash implementation contracts remain premises; this
does not establish erasure of compiler copies or arbitrary caller frames.
"""
import re

import hmac_engine_codegen as common
import hmac_engine_final as final
import hmac_engine_scratch as scratch


def scalar(model, identity, definitions, aliases, panic):
    common.require(not model.compiled, 'scalar consuming proof requires scalar worker')
    algorithm = ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                 else 'brynja_mac_hmac::algorithms::Sha' + identity[3:])
    prefix = '<brynja_mac_hmac::engine::Engine<' + algorithm + '>>::'
    checked = set()
    for _, point, _ in model.terminals:
        symbol, _ = model.call_map[point]
        method = model.names.get(symbol, '').removeprefix(prefix)
        common.require(method in ('secret', 'verify') and method not in checked,
                       'scalar consumer method identity/population changed')
        arguments, body = common.resolve(symbol, definitions, aliases)
        expected = ((('ptr', '%_0'),) if method == 'secret' else ()) + (
            ('ptr', '%self'), ('ptr', '%input'),
            ('ptr', '%destination.0' if method == 'secret' else '%0'),
            ('i64', '%destination.1' if method == 'secret' else '%1'))
        formals = final.parameters(arguments)
        common.require(len(formals) == len(expected) and all(
            re.fullmatch(kind + r' [^%]*' + re.escape(name), formal)
            for formal, (kind, name) in zip(formals, expected)), 'scalar consumer formal binding changed')
        scratch.check(body, method)
        final.check(body, identity, definitions, aliases, panic)
        checked.add(method)
    common.require(checked == {'secret', 'verify'}, 'scalar consuming proof incomplete')
