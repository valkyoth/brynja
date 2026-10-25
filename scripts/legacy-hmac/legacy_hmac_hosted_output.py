"""Streaming legacy output descriptor, copy, and cleanup on the worker CFG.

Constructor scratch calls are handled by their separate prefix proof. Only
prefix-only copies/destructors are excluded from output callee selection; all
instructions, writes, lifetime edges and calls remain in its CFG/call map.
"""
import copy

import legacy_hmac_engine_codegen as legacy

shared = legacy.load('hmac_hosted_output')
require = legacy.require


def check(model, arguments, panic):
    require(model.identity in ('sha1', 'md5', 'sha1_compiled'), 'unreviewed legacy output identity')
    projected = copy.copy(model)
    projected.calls = [row for row in model.calls
                       if model.names.get(row[0]) not in (shared.COPY, shared.DROP)
                       or model.can_precede(model.cut, row[2])]
    projected.names = dict(model.names)
    terminals = {point for _, point, _ in model.terminals}
    for symbol, _, point in projected.calls:
        if point in terminals:
            name = model.names[symbol]
            require(name.startswith('<brynja_legacy_hmac::'), 'legacy output terminal identity changed')
            # Match only the already bound terminal, without altering LLVM or
            # widening accepted callees for any other route.
            projected.names[symbol] = name.replace('<brynja_legacy_hmac::', '<brynja_mac_hmac::', 1)
    return shared.check(projected, arguments, panic)
