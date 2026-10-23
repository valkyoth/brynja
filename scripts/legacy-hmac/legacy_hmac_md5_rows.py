"""Actual MD5 HMAC row lifetime/clear dispatch, not whole-caller qualification."""
import re

import legacy_hmac_engine_codegen as shared
import legacy_hmac_execution_admission as common
import legacy_hmac_md5_row_contracts as contracts
from legacy_hmac_md5_row_origins import Origins

flow, syntax, require = shared.flow, common.syntax, shared.require
scratch = shared.load("hmac_engine_scratch", "legacy_md5_row_scratch")
scratch.SCRATCH = {
    "rows": {"pad": 512, "inner": 128, "final_tags": 128, "truncated": 128},
    "normalization": {"normalized": 128},
    "comparison": {"difference": 1},
}
# The default helper binds a different crate's guard name. Here region Drop
# classification below is exact and source-bound, and grants no row-clear credit.
scratch.output_guard_drop = lambda line, body: False


def method(definitions, aliases, operation):
    prefix = (r"_RNvMs_NtCs\w+_18brynja_legacy_hmac9md5_batchNtB\w+_8Md5Batch|"
              r"_ZN18brynja_legacy_hmac9md5_batch8Md5Batch")
    matches = [name for name in (*definitions, *aliases)
               if re.fullmatch("(?:" + prefix + ")" + str(len(operation)) + operation + r"(?:17h[0-9a-f]+E)?", name)]
    require(len(matches) == 1, "missing/ambiguous MD5 operation: " + operation)
    return matches[0], flow.resolve(matches[0], definitions, aliases)


def check(signature, body, operation, definitions, aliases, panic, llvm):
    owners = scratch.allocations(body, operation)
    origins = Origins(signature, body, owners)
    qualified = set()
    for line in body.splitlines():
        invocation = syntax.call(line)
        if invocation and "clear_owned_region" in invocation[0]:
            require(re.fullmatch(r"_RNvNtCs\w+_11brynja_core13secret_memory18clear_owned_region|"
                                 r"_ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E", invocation[0]),
                    "unrecognized MD5 row clear identity")

    def independent(line):
        if origins.disjoint_store(line):
            return True
        invocation = syntax.call(line)
        if not invocation:
            return False
        symbol, args = invocation
        if contracts.workspace_drop(symbol):
            require(len(args) == 1, "workspace cleanup arity changed")
            roots = origins.roots(syntax.operand(args[0]))
            require(len(roots) == 1 and not roots & set(owners), "workspace cleanup aliases HMAC rows")
            root = next(iter(roots))
            require(re.fullmatch(r"%workspace(?:\.[-\w]+)*", root)
                    and re.search(re.escape(root) + r" = alloca \[912 x i8\],", body), "workspace storage changed")
            if symbol not in qualified:
                contracts.workspace(symbol, definitions, aliases, panic, llvm)
                qualified.add(symbol)
            return True
        if shared.owner_drop(symbol, "md5") or contracts.region_drop(symbol):
            require(len(args) == 1, "non-refilling destructor arity changed")
            return True
        return False

    scratch.check(body, operation, independent)


def validate(llvm, panic):
    contracts.validate()
    definitions, aliases = flow.definitions_and_aliases(llvm)
    pads = set()
    comparisons = set()
    for operation in ("authenticate", "authenticate_secret", "verify"):
        _, (signature, body) = method(definitions, aliases, operation)
        check(signature, body, "rows", definitions, aliases, panic, llvm)
        for line in body.splitlines():
            invocation = syntax.call(line)
            if invocation and re.fullmatch(
                    r"_RNvNtNtCs\w+_18brynja_legacy_hmac9md5_batch6engine4pads|"
                    r"_ZN18brynja_legacy_hmac9md5_batch6engine4pads17h[0-9a-f]+E", invocation[0]):
                pads.add(invocation[0])
            if invocation and re.fullmatch(
                    r"_RNCNvMs_NtCs\w+_18brynja_legacy_hmac9md5_batchNtB\w+_8Md5Batch6verify0B\w+_|"
                    r"_ZN18brynja_legacy_hmac9md5_batch8Md5Batch6verify28_\$u7b\$\$u7b\$closure\$u7d\$\$u7d\$17h[0-9a-f]+E",
                    invocation[0]) and operation == "verify":
                comparisons.add(invocation[0])
    require(len(pads) == 1, "missing/ambiguous actual normalization call")
    signature, body = flow.resolve(next(iter(pads)), definitions, aliases)
    check(signature, body, "normalization", definitions, aliases, panic, llvm)
    require(len(comparisons) == 1, "missing/ambiguous actual comparison closure")
    signature, body = flow.resolve(next(iter(comparisons)), definitions, aliases)
    check(signature, body, "comparison", definitions, aliases, panic, llvm)
    return 5
