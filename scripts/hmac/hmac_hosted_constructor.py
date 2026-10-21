"""Actual hosted constructor admission, scratch and post-admission transfers.

The source-bound typed hash factory/update/finalizer contracts are still callee
premises. This is logical owner and explicit scratch cleanup, not a claim about
compiler-generated copies or arbitrary caller frames.
"""
import hmac_hosted_callee_admission as admission
import hmac_execution_construct as construct
import hmac_execution_scratch as scratch


def check(model, identity, definitions, aliases, compiler, panic, types):
    symbol, body = admission.resolve(model, identity, definitions, aliases)
    scratch.check_body(body, 'construct_static', definitions, aliases)
    for route in range(8):
        for long_key in (False, True):
            construct.check(body, identity, definitions, aliases, compiler, panic,
                            route, long_key, types, profile='static', dynamic_tag=True)
    return symbol
