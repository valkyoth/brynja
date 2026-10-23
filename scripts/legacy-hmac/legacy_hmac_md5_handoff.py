"""Final readiness success edge must guard all three actual row consumers.

This is a handoff-order check, not full output ownership/return provenance or
proof of the preceding HMAC computation. The called readiness helper is walked
separately; its primitive ready/clear/Scope contracts remain explicit premises.
"""
import re

import legacy_hmac_md5_fence as fence

rows, flow, syntax, require, VALUE = fence.rows, fence.flow, fence.syntax, fence.require, fence.VALUE


def closure(symbol, method):
    return bool(re.fullmatch(
        r"_RNCNvMs_NtCs\w+_18brynja_legacy_hmac9md5_batchNtB\w+_8Md5Batch" + str(len(method)) + method + r"0B\w+_|"
        r"_ZN18brynja_legacy_hmac9md5_batch8Md5Batch" + str(len(method)) + method
        + r"28_\$u7b\$\$u7b\$closure\$u7d\$\$u7d\$17h[0-9a-f]+E", symbol))


def copy_region(symbol):
    return bool(re.fullmatch(r"_RNvNtCs\w+_11brynja_core13secret_memory18copy_secret_region|"
                            r"_ZN11brynja_core13secret_memory18copy_secret_region17h[0-9a-f]+E", symbol))


def reachable(graph, start, omit=None):
    visited, pending = set(), [start]
    while pending:
        node = pending.pop()
        require(node in graph, "unknown MD5 handoff edge")
        if node in visited:
            continue
        visited.add(node)
        for child in re.findall("label %" + flow.LABEL, "\n".join(graph[node])):
            if (node, child) != omit:
                pending.append(child)
    return visited


def check(signature, body, operation, definitions, aliases, ok):
    graph = flow.blocks(body)
    params = syntax.parameters(signature)
    require(len(params) == 5, "MD5 handoff signature changed")
    output = syntax.operand(params[3])
    truncated = next(name for name in rows.scratch.allocations(body, "rows") if name.startswith("%truncated"))
    allocs = dict((name, int(size)) for name, size in re.findall(rf"({VALUE}) = alloca \[(\d+) x i8\],", body))
    fences, releases = [], []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            invocation = syntax.call(line)
            if not invocation:
                continue
            symbol, args = invocation
            if fence.helper(symbol) and len(args) == 1:
                workspace = syntax.operand(args[0])
                require(re.fullmatch(r"%workspace(?:\.[-\w]+)*", workspace) and allocs.get(workspace) == 912,
                        "final readiness uses a different workspace")
                fences.append((label, index, symbol))
            if operation == "authenticate":
                selected = copy_region(symbol) and len(args) == 4 and syntax.operand(args[0]) == output
            else:
                selected = closure(symbol, operation)
            if selected:
                releases.append((label, index, symbol, args))
    require(len(fences) == len(releases) == 1, "missing/repeated readiness or final row consumer")
    label, index, helper = fences[0]
    release, release_index, symbol, args = releases[0]
    line = graph[label][index]
    result = re.match(rf"({VALUE}) = (?:tail )?(?:call|invoke) ", line)
    require(result, "unused final readiness result")
    if "invoke " in line:
        edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                             + r"(?:, ![-\w.]+ !\d+)*", graph[label][index + 1])
        require(edges and index + 2 == len(graph[label]), "unparsed final readiness invoke")
        checked_label, failed = edges[1], [edges[2]]
        checked = graph[checked_label]
    else:
        checked_label, failed = label, []
        checked = graph[label][index + 1:]
    extract = re.fullmatch(rf"({VALUE}) = extractvalue \{{ i8, i8 \}} {re.escape(result[1])}, 0", checked[0])
    require(extract and len(checked) >= 4 and checked[-1] == "]", "final readiness discriminant not checked")
    switch = re.fullmatch(rf"switch i8 {re.escape(extract[1])}, label %" + flow.LABEL + r" \[", checked[1])
    require(switch, "final readiness switch detached from result")
    failed.append(switch[1])
    seen, accepted = set(), None
    for case in checked[2:-1]:
        match = re.fullmatch(r"i8 (-?\d+), label %" + flow.LABEL, case)
        require(match and int(match[1]) not in seen, "malformed readiness case")
        seen.add(int(match[1]))
        if int(match[1]) == ok:
            accepted = match[2]
        else:
            failed.append(match[2])
    require(accepted == release, "successful readiness does not directly enter consumer")
    start = next(iter(graph))
    require(label in reachable(graph, start) and release in reachable(graph, start), "unreachable readiness/handoff")
    require(release not in reachable(graph, start, (checked_label, accepted)), "handoff bypasses readiness success edge")
    require(all(release not in reachable(graph, edge) for edge in failed), "readiness failure/unwind reaches consumer")

    # The success block may only move the secret-output initialization capture
    # before consumption. No callback, computation or metadata store is allowed.
    prefix = graph[release][:release_index]
    if operation == "authenticate":
        require(not prefix and len(args) == 4 and syntax.operand(args[0]) == output
                and args[1] == args[3] == "i64 noundef 128"
                and syntax.operand(args[2]) == truncated, "public handoff pointer/extent changed")
    else:
        flow.resolve(symbol, definitions, aliases)  # Not an unbound marker/callee.
        require(len(args) == 3 and syntax.operand(args[-1]) == truncated, "row consumer pointer changed")
        if operation == "verify":
            require(not prefix and syntax.operand(args[0]) == output, "verification candidate binding changed")
            width = re.fullmatch(r"i64(?: noundef)? (" + VALUE + ")", args[1])
            pointer_map = syntax.pointers(body, ("%self",))
            load = re.search(re.escape(width[1]) + rf" = load i64, ptr ({VALUE}),", body) if width else None
            require(load and pointer_map.get(load[1]) == ("%self", 8), "verification tag selection changed")
        else:
            destination, capture = syntax.operand(args[0]), syntax.operand(args[1])
            require(allocs.get(destination) == allocs.get(capture) == 24 and destination != capture and len(prefix) == 3,
                    "secret handoff record geometry changed")
            for item, expected in zip(prefix[:2], (destination, capture)):
                call = syntax.call(item)
                require(call and call[0] == "llvm.lifetime.start.p0" and len(call[1]) in (1, 2)
                        and syntax.operand(call[1][-1]) == expected
                        and (len(call[1]) == 1 or call[1][0] == "i64 24"), "secret handoff gained intermediate effects")
            call = syntax.call(prefix[2])
            require(call and call[0] == "llvm.memcpy.p0.p0.i64" and len(call[1]) == 4
                    and syntax.operand(call[1][0]) == capture
                    and allocs.get(syntax.operand(call[1][1])) == 24 and call[1][2:] == ["i64 24", "i1 false"],
                    "secret handoff capture move changed")
    return helper


def validate(fixture, llvm, panic):
    ok = fence.success(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    qualified = set()
    for operation in ("authenticate", "authenticate_secret", "verify"):
        _, (signature, body) = rows.method(definitions, aliases, operation)
        helper = check(signature, body, operation, definitions, aliases, ok)
        if helper not in qualified:
            signature, body = flow.resolve(helper, definitions, aliases)
            fence.validate(signature, body, llvm, ok, panic)
            qualified.add(helper)
