"""HKDF local-scratch dispatch graphs; not whole-frame or callee-erasure proof."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hmac"))
import hmac_engine_codegen as graph
import hmac_engine_scratch as scratch

IDENTITIES = ("sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256")
ROLES = {"extract": {"block": 64}, "expand": {"block": 64, "previous": 64},
         "expand_parts": {"block": 64, "previous": 64},
         "label": {"encoded": 514}}


def require(condition, message):
    if not condition:
        raise ValueError("HKDF operation scratch: " + message)


def roles(operation, family):
    return {role: 20 if family == "legacy" else size for role, size in ROLES[operation].items()}


def check_body(body, operation, family):
    # Extend only this process's operation map. No shared checker source changes
    # and no HMAC checks are selected or executed by this driver.
    scratch.SCRATCH["hkdf-" + operation] = roles(operation, family)
    scratch.check(body, "hkdf-" + operation)


def consumers(llvm, family):
    require(family in ("modern", "legacy"), "unknown family")
    require('target triple = "x86_64-unknown-linux-gnu"' in llvm, "unsupported layout")
    definitions, aliases = graph.definitions_and_aliases(llvm)
    result = {}
    if family == "legacy":
        for op in ("extract", "expand", "expand_parts"):
            names = [name for name in definitions if re.fullmatch(
                r"(?:_RNvMs\w*_Cs\w+_18brynja_legacy_hkdfNtB\w+_7Sha1Prk"
                + str(len(op)) + op + r"|_ZN18brynja_legacy_hkdf7Sha1Prk"
                + str(len(op)) + op + r"17h[0-9a-f]+E)", name)]
            require(len(names) == 1, "missing/ambiguous production SHA-1 " + op)
            body = definitions[names[0]][1]
            if op == "expand":
                body = operation_body(body, op, family, definitions, aliases)
            result["sha1", op] = body
        return result
    for identity in IDENTITIES:
        for op in ROLES:
            suffix = "29brynja_hkdf_operation_cleanup" + str(len(identity)) + identity + str(len(op)) + op
            names = [name for name in (*definitions, *aliases)
                     if re.search(suffix + r"(?:17h[0-9a-f]+E)?$", name)]
            require(len(names) == 1, "missing/ambiguous public consumer " + identity + "/" + op)
            body = graph.resolve(names[0], definitions, aliases)[1]
            result[identity, op] = operation_body(body, op, family, definitions, aliases)
    return result


def operation_body(body, operation, family, definitions, aliases):
    """Follow only the known production operation/delegation, never arbitrary calls."""
    role = next(iter(ROLES[operation]))
    methods = {"expand", "expand_parts"} if operation == "expand" else {
        "expand_label" if operation == "label" else operation}
    seen = set()
    while not re.search("%" + role + r"(?:\.[-\w]+)* = alloca", body):
        calls = re.findall(r'\b(?:call|invoke)\b[^\n]*@("[^"]+"|\w+)\(', body)
        prefix = "18brynja_legacy_hkdf" if family == "legacy" else "13brynja_crypto4hkdf6derive"
        calls = [name.strip('"') for name in calls]
        calls = [name for name in calls if prefix in name and any(
            re.search(str(len(method)) + method +
                      r"(?:17h[0-9a-f]+E|Cs\w+_29brynja_hkdf_operation_cleanup)?$", name)
            for method in methods)]
        require(len(calls) == 1, "consumer lacks exact production operation")
        require(calls[0] not in seen, "cyclic operation delegation")
        seen.add(calls[0])
        body = graph.resolve(calls[0], definitions, aliases)[1]
    return body


def check(llvm, family, panic):
    require(panic in ("abort", "unwind"), "unknown panic profile")
    bodies = consumers(llvm, family)
    for (_, op), body in bodies.items():
        require(("landingpad " in body) == (panic == "unwind"), "panic profile changed")
        check_body(body, op, family)
    return bodies


def negative_controls(bodies, family):
    """Every body and every named scratch role must reject broken cleanup."""
    rejected = 0
    for (identity, op), body in bodies.items():
        scratch.SCRATCH["hkdf-" + op] = roles(op, family)
        owners = scratch.allocations(body, "hkdf-" + op)
        for pointer, size in owners.items():
            # Preserve the CFG/callee but pass an unrelated/null region or a
            # shorter extent. Removing only a call cannot hide an unwind edge.
            clear = r"([^\n]*clear_owned_region[^\n]*?)" + re.escape(pointer) + r", i64(?: noundef)? " + str(size) + r"\)"
            mutations = {
                "short clear": re.sub(clear, lambda m: m[1] + pointer + ", i64 " + str(size - 1) + ")", body),
                "wrong pointer": re.sub(clear, lambda m: m[1] + "null, i64 " + str(size) + ")", body),
                "wrong callee": re.sub(clear, lambda m: m[0].replace("clear_owned_region", "other_owned_region"), body),
                "early exit": re.sub(r"([^\n]*@llvm.lifetime.start.p0\([^\n]*" + re.escape(pointer)
                                     + r"\)[^\n]*\n)", r"\1  ret void\n", body),
                "write after clear": re.sub(clear + r"[^\n]*\n", lambda m: m[0] +
                                            "  store i8 1, ptr " + pointer + ", align 1\n", body),
            }
            for name, mutant in mutations.items():
                require(mutant != body, "vacuous negative control " + identity + "/" + op + "/" + name)
                try:
                    check_body(mutant, op, family)
                except ValueError:
                    rejected += 1
                    continue
                require(False, "accepted broken " + identity + "/" + op + "/" + name)
    return rejected
