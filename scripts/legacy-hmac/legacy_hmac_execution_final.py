"""Accelerated finalizer cores and scratch; outer retained moves are separate.

Resolve the actual cores called by the public byte/bit methods. Transfer from
the optional retained engine is checked separately by execution_handoff.
"""
from functools import lru_cache
import re
from types import SimpleNamespace

import legacy_hmac_engine_codegen as shared
import legacy_hmac_engine_scratch as scratch
import legacy_hmac_execution_state as model

require, flow = shared.require, shared.flow


def stream_finalizer(symbol, identity):
    require(identity == "sha1", "unknown accelerated finalizer identity")
    return bool(re.fullmatch(
        r"(?:_RNvM(?:\w*_)?NtNtCs\w+_18brynja_legacy_sha118hardened_execution6streamNtB\w+_6Stream|"
        r"_ZN18brynja_legacy_sha118hardened_execution6stream6Stream)"
        r"(?:15finalize_secret|20finalize_bits_secret)(?:17h[0-9a-f]+E)?", symbol))


@lru_cache(maxsize=2)
def interpreter(panic):
    require(panic in ("abort", "unwind"), "unknown finalizer panic profile")
    module = shared.load("hmac_engine_final", "legacy_execution_final_" + panic)
    module.codegen = SimpleNamespace(
        IDENTITIES=("sha1",), owner_drop=shared.owner_drop, blocks=flow.blocks,
        resolve=flow.resolve, panic_cleanup=flow.panic_cleanup,
        fatal_cleanup_block=flow.fatal_cleanup_block)
    module.geometry = lambda identity: (448, 8, (8, 456))
    module.hash_finalizer = stream_finalizer
    module.adapter_update = model.stream_update
    module.finish_closure = lambda symbol: False

    def helper(symbol, identity, definitions, aliases):
        require(model.helper(symbol) and "Sha1Adapter" in symbol and "Guard" not in symbol,
                "unknown accelerated Engine destructor")
        signature, body = flow.resolve(symbol, definitions, aliases)
        params = re.findall(model.SSA, signature)
        require(len(params) == 1, "unexpected Engine destructor signature")
        body = re.sub(re.escape(params[0]) + r"(?![-\w.])", "%self", body)
        require(not any("drop_glue" in line or "drop_in_place" in line
                        for line in body.splitlines() if re.search(r"\b(?:call|invoke)\b", line)),
                "nested Engine destructor helper")
        module.check(body, identity, definitions, aliases, panic)

    module.update = SimpleNamespace(helper=helper)
    return module


def method(definitions, aliases, operation):
    matches = [name for name in (*definitions, *aliases) if model.method(name, operation)]
    require(len(matches) == 1, "missing/ambiguous accelerated method " + operation)
    return matches[0], flow.resolve(matches[0], definitions, aliases)


def bodies(llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    selected = {}
    for operation, callers in (("public", ("finalize_tag", "finalize_bits_tag")),
                               ("verify", ("verify", "verify_bits"))):
        targets = set()
        for caller in callers:
            _, (_, body) = method(definitions, aliases, caller)
            calls = [invocation[0] for line in body.splitlines()
                     if (invocation := model.final.call(line)) and "6engine" in invocation[0]]
            require(len(calls) == 1, "missing/ambiguous actual Engine finalizer call")
            targets.update(calls)
        require(len(targets) == 1, "byte/bit finalizer cores diverged")
        symbol = next(iter(targets))
        require(re.fullmatch(
            r"(?:_RNvMNtCs\w+_18brynja_legacy_hmac6engineINtB\w+_6EngineNtNtNtB\w+_9execution7adapter11Sha1AdapterE6"
            + operation + r"B\w+_|_ZN18brynja_legacy_hmac6engine15Engine\$LT\$A\$GT\$6"
            + operation + r"17h[0-9a-f]+E)", symbol), "wrong Engine finalizer identity")
        signature, body = flow.resolve(symbol, definitions, aliases)
        require(re.search(r"dereferenceable\(904\) %self(?:,|$)", signature), "Engine finalizer owner geometry changed")
        selected[operation] = body
    secret, (_, selected["secret"]) = method(definitions, aliases, "secret")
    for caller in ("finalize_secret", "finalize_bits_secret"):
        _, (_, body) = method(definitions, aliases, caller)
        calls = [invocation[0] for line in body.splitlines() if (invocation := model.final.call(line))
                 and invocation[0] not in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0")]
        require(calls == [secret], "secret finalizer no longer calls reviewed body")
    return selected, definitions, aliases


def check(llvm, panic):
    selected, definitions, aliases = bodies(llvm)
    for operation, body in selected.items():
        scratch.check(body, operation)
        if operation != "secret":
            interpreter(panic).check(body, "sha1", definitions, aliases, panic)
