"""Accelerated constructor/finalizer scratch dispatch, not hash-owner transfer."""
import re

import hmac_engine_codegen as common
import hmac_engine_scratch as scratch
from hmac_callee_identity import CONTEXT
from hmac_engine_final import call as parsed_call, operand, parameters

OPERATIONS = ("construct_static", "construct_runtime", "public", "secret", "verify",
              "public_bits", "secret_bits", "verify_bits")


def method(operation):
    return "construct" if operation.startswith("construct_") else operation


def constructor_forwarding(body, operation):
    """Bind the public wrapper to its actual authority, key and route selector."""
    graph = common.blocks(body)
    common.require(len(graph) == 1, "unexpected constructor wrapper graph")
    lines = next(iter(graph.values()))
    common.require(len(lines) == 2 and lines[-1] == "ret void",
                   "unexpected constructor wrapper instructions")
    invocation = parsed_call(lines[0])
    common.require(invocation is not None, "missing constructor forwarding call")
    _, args = invocation
    common.require(len(args) == 5, "constructor forwarding arity changed")
    route = 0 if operation == "construct_static" else 1
    common.require(operand(args[0]) == "%_0" and operand(args[2]) == "%owner"
                   and operand(args[3]) == "%key.0"
                   and re.fullmatch(r"i(?:8|64) (?:noundef )?" + str(route), args[1])
                   and re.fullmatch(r"i64 (?:noundef )?%key\.1", args[4]),
                   "constructor authority/key/route forwarding changed")


def consumer(body, operation, definitions, aliases):
    """Follow one exact typed implementation edge, never a marker search."""
    kind = method(operation)
    if kind == "construct":
        constructor_forwarding(body, operation)
    if any(re.search(r"%" + role + r"(?:\.[-\w]+)* = alloca", body)
           for role in scratch.SCRATCH[kind]):
        scratch.allocations(body, kind)
        return body
    calls = re.findall(r'\b(?:call|invoke)\b[^\n]*@("[^"]+"|\w+)\(', body)
    calls = [name.strip('"') for name in calls if "15brynja_mac_hmac" in name]
    common.require(len(calls) == 1, "missing/ambiguous accelerated scratch method")
    symbol = calls[0]
    if kind == "construct":
        prefix = (r"_RNvMs_NtCs\w+_15brynja_mac_hmac9executionI\w+"
                  r"|_ZN15brynja_mac_hmac9execution13Hmac\$LT\$A\$GT\$")
        expected = "6create"
    else:
        prefix = (r"_RNvMNtCs\w+_15brynja_mac_hmac6engineI\w+"
                  r"|_ZN15brynja_mac_hmac6engine15Engine\$LT\$A\$GT\$")
        base = kind.removesuffix("_bits")
        expected = str(len(base)) + base
    common.require(re.fullmatch("(?:" + prefix + ")" + expected
                                + r"(?:17h[0-9a-f]+E|Cs\w+_"
                                r"29brynja_hmac_execution_cleanup)", symbol),
                   "unexpected accelerated scratch method identity")
    arguments, outlined = common.resolve(symbol, definitions, aliases)
    if kind == "construct":
        formals = parameters(arguments)
        expected = (("ptr", "%_0"), ("i64", "%0"), ("ptr", "%1"),
                    ("ptr", "%key.0"), ("i64", "%key.1"))
        common.require(len(formals) == len(expected) and all(
            re.fullmatch(typ + r" [^%]*" + re.escape(name), formal)
            for formal, (typ, name) in zip(formals, expected)),
            "constructor formal authority/key binding changed")
    scratch.allocations(outlined, kind)
    return outlined


def independent_iterator(body, line, definitions, aliases):
    """Safe typed iterator destruction cannot write distinct local pad storage.

    This is a non-aliasing premise, NOT proof of the iterator's owner cleanup.
    Require the actual emitted helper, one pointer to the exact separate states
    allocation, and its complete allocation extent. Unknown calls stay dirtying.
    """
    call = re.search(r'\b(?:call|invoke)\b[^@]*@("[^"]+"|\w+)\((.*)\)', line)
    if not call:
        return False
    symbol = call[1].strip('"')
    if not ("Flatten" in symbol and "IntoIter" in symbol and "drop_" in symbol):
        return False
    v0 = (r"_RINvNtCs\w+_4core3ptr(?:9drop_glue|13drop_in_place)INtNtNtNtB\w+_4iter8adapters7flatten7Flatten"
          r"INtNtNtB\w+_5array4iter8IntoIterINtNtB\w+_6option6Option"
          r"(?:NtNtNtCs\w+_16brynja_hash_sha218hardened_execution"
          r"(?:5named(?:6Sha224|6Sha256|6Sha384|6Sha512|10Sha512_224|10Sha512_256)|7general7Sha512T)"
          r"|NtNtNtNtCs\w+_16brynja_hash_sha38hardened11accelerated5fixed8Sha3_(?:224|256|384|512))"
          r"EKj3_EEECs\w+_" + CONTEXT)
    legacy = (r"_ZN4core3ptr\d+drop_in_place\$LT\$core\.\.iter\.\.adapters\.\.flatten\.\.Flatten"
              r"\$LT\$core\.\.array\.\.iter\.\.IntoIter\$LT\$core\.\.option\.\.Option\$LT\$"
              r"(?:brynja_hash_sha2\.\.hardened_execution\.\.(?:named\.\.Sha(?:224|256|384|512|512_224|512_256)"
              r"|general\.\.Sha512T)|brynja_hash_sha3\.\.hardened\.\.accelerated\.\.fixed\.\.Sha3_(?:224|256|384|512))"
              r"\$GT\$\$C\$3_usize\$GT\$\$GT\$\$GT\$17h[0-9a-f]+E")
    common.require(re.fullmatch(v0 + "|" + legacy, symbol),
                   "unrecognized iterator drop symbol")
    arguments = parameters(call[2])
    common.require(len(arguments) == 1, "iterator destruction arity changed")
    argument = re.fullmatch(r"ptr (?:[-\w()., ]+ )?(%states(?:\.[-\w]+)*)", arguments[0])
    common.require(argument, "iterator destruction storage changed")
    allocation = re.findall(re.escape(argument[1]) + r" = alloca \[(\d+) x i8\]", body)
    common.require(len(allocation) == 1, "missing distinct iterator allocation")
    common.require(re.search(r"\bdereferenceable\(" + allocation[0] + r"\)", arguments[0]),
                   "iterator destruction extent changed")
    args, _ = common.resolve(symbol, definitions, aliases)
    common.require(len(parameters(args)) == 1, "iterator helper signature changed")
    return True


def check_body(body, operation, definitions, aliases):
    scratch.check(body, method(operation), lambda line: independent_iterator(
        body, line, definitions, aliases))


def check(body, operation, definitions, aliases):
    resolved = consumer(body, operation, definitions, aliases)
    check_body(resolved, operation, definitions, aliases)
    return resolved
