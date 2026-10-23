"""Exact legacy SHA-1 iterator destruction and distinct constructor scratch.

The independent helper population covers each cursor and optional third stream.
The separate execution_construct walker binds post-admission caller metadata.
"""
import itertools
import re
from types import SimpleNamespace

import legacy_hmac_engine_codegen as shared
import legacy_hmac_engine_scratch as scratch
import legacy_hmac_execution_admission_contracts as contracts

for dependency in ("hmac_callee_identity", "hmac_execution_drop", "hmac_execution_final_contracts",
                   "hmac_execution_admission_contracts"):
    shared.load(dependency)
walker = shared.load("hmac_execution_iterator", "legacy_sha1_iterator_walk")
require, flow, syntax = contracts.require, contracts.flow, contracts.syntax


def helper(symbol, definitions, aliases):
    require(("drop_glue" in symbol or "drop_in_place" in symbol)
            and "brynja_legacy_sha1" in symbol and "Stream" in symbol,
            "unrecognized legacy iterator helper")
    signature, body = flow.resolve(symbol, definitions, aliases)
    parameters = syntax.parameters(signature)
    require(len(parameters) == 1, "legacy iterator helper arity")
    return syntax.operand(parameters[0]), body


walker.cleanup = SimpleNamespace(leaf=lambda name: "sha1" if shared.owner_drop(name, "sha1") else None,
                                 helper=helper)


def selected(body, definitions, aliases):
    calls = [item for line in body.splitlines() if (item := syntax.call(line)) and "Flatten" in item[0]]
    require(calls and len({symbol for symbol, _ in calls}) == 1, "missing/ambiguous constructor iterator cleanup")
    symbol = calls[0][0]
    v0 = (r"_RINvNtCs\w+_4core3ptr(?:9drop_glue|13drop_in_place)INtNtNtNtB\w+_4iter8adapters7flatten7Flatten"
          r"INtNtNtB\w+_5array4iter8IntoIterINtNtB\w+_6option6Option"
          r"NtNtNtCs\w+_18brynja_legacy_sha118hardened_execution6stream6StreamEKj3_EEECs\w+_18brynja_legacy_hmac")
    old = (r"_ZN4core3ptr\d+drop_in_place\$LT\$core\.\.iter\.\.adapters\.\.flatten\.\.Flatten"
           r"\$LT\$core\.\.array\.\.iter\.\.IntoIter\$LT\$core\.\.option\.\.Option\$LT\$"
           r"brynja_legacy_sha1\.\.hardened_execution\.\.stream\.\.Stream"
           r"\$GT\$\$C\$3_usize\$GT\$\$GT\$\$GT\$17h[0-9a-f]+E")
    require(re.fullmatch(v0 + "|" + old, symbol), "wrong legacy constructor iterator identity")
    require(len(re.findall(r"%streams = alloca \[2264 x i8\],", body)) == 1, "iterator allocation changed")
    for _, args in calls:
        require(len(args) == 1 and syntax.operand(args[0]) == "%streams"
                and "dereferenceable(2264)" in args[0], "iterator call storage/extent changed")
    return symbol, helper(symbol, definitions, aliases)


def check(body, llvm, definitions, aliases, panic, cache_niche):
    if not any((item := syntax.call(line)) and "Flatten" in item[0] for line in body.splitlines()):
        require(panic == "abort", "missing unwind iterator helper")
        # LLVM inlines the abort-profile iterator cleanup into the constructor.
        # Scratch remains checked, but the inlined owner paths are NOT qualified
        # by this isolated-helper model. execution_construct checks those paths.
        scratch.flow.check(body, "construct")
        return 0
    symbol, (parameter, nested) = selected(body, definitions, aliases)
    types = walker.array_types(llvm, "static")
    # Independent boolean niches for three array slots and two caches.
    for count, cursor, niches, caches in itertools.product((2, 3), range(4), range(32), range(4)):
        memory = {(0, 8): 1, (8, 8): cursor, (16, 8): 3,
                  (1809, 1): (niches >> 3) & 1 if caches & 1 else cache_niche,
                  (2257, 1): (niches >> 4) & 1 if caches & 2 else cache_niche}
        memory.update({(24 + token * 448 + 441, 1): (niches >> token) & 1 if token < count else 2
                       for token in range(3)})
        expected = frozenset(("sha1", 24 + token * 448 + 8) for token in range(cursor, count))
        expected |= frozenset(("sha1", offset) for bit, offset in ((1, 1376), (2, 1824)) if caches & bit)
        for exceptional in (False, True):
            outcomes = walker.walk(nested, parameter, 0, memory, definitions, aliases, panic,
                                   unwinding=exceptional, types=types)
            require(outcomes and all(events == expected for _, events in outcomes),
                    "incomplete/wrong remaining iterator destruction")
    # Safe Rust separates this typed iterator allocation from pad/digest. The
    # resolved helper above is not excused from its own cleanup qualification.
    def independent(line):
        match = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
        return bool(match and match[1].strip('"') == symbol)
    scratch.flow.check(body, "construct", independent)
    return 1
