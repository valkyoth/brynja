"""Static-only inlined constructor entry, scratch and owner-transfer checks."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_construct as construct
import hmac_execution_scratch as scratch


def entry(identity, definitions, aliases):
    suffix = ("29brynja_hmac_execution_cleanup" + str(len(identity)) + identity
              + "16construct_static")
    names = [name for name in (*definitions, *aliases)
             if re.search(suffix + r"(?:17h\w+E)?$", name)]
    common.require(len(names) == 1, "missing/ambiguous static constructor entry")
    arguments, body = common.resolve(names[0], definitions, aliases)
    formals = syntax.parameters(arguments)
    expected = (("ptr", "%_0"), ("ptr", "%owner"), ("ptr", "%key.0"), ("i64", "%key.1"))
    common.require(len(formals) == len(expected) and all(
        re.fullmatch(kind + r" [^%]*" + re.escape(name), formal)
        for formal, (kind, name) in zip(formals, expected)), "static constructor formal binding")
    # The reviewed matrices inline create here. Do not silently follow a new
    # outline edge without validating its forwarding and formal contracts.
    construct.layout.roles(body, "static")
    return body


def validate(llvm, definitions, aliases, compiler, panic):
    types = construct.iterator.array_types(llvm, "static")
    for identity in common.IDENTITIES:
        body = entry(identity, definitions, aliases)
        scratch.check_body(body, "construct_static", definitions, aliases)
        for population in range(8):
            for long_key in (False, True):
                construct.check(body, identity, definitions, aliases, compiler, panic,
                                population, long_key, types, profile="static")
