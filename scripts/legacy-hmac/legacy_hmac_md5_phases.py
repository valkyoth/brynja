"""Bind MD5 normalization/inner/outer call arguments and closure transport.

This checks pointer identities, allocation extents and call dominance in emitted
LLVM, not the contents of per-lane descriptors/prefixes, helper result ownership,
inner-result success propagation, or the complete lifetime of the executor
stored inside the workspace.
"""
import re

import legacy_hmac_md5_handoff as handoff

rows, flow, syntax, require = handoff.rows, handoff.flow, handoff.syntax, handoff.require
VALUE = handoff.VALUE


def identity(symbol, role):
    paths = {
        "new": (r"Ms_NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_9Workspace3new",
                "17brynja_legacy_md55batch18hardened_execution8in_place9Workspace3new"),
        "pads": (r"NtNtCs\w+_18brynja_legacy_hmac9md5_batch6engine4pads",
                 "18brynja_legacy_hmac9md5_batch6engine4pads"),
        "digest": (r"Ms0_NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_5Batch22digest_prefixed_secret",
                   "17brynja_legacy_md55batch18hardened_execution8in_place5Batch22digest_prefixed_secret"),
    }
    if role == "outer":
        return bool(re.fullmatch(
            r"_RINvMs_NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_9Workspace4withI\w+_|"
            r"_ZN17brynja_legacy_md55batch18hardened_execution8in_place9Workspace4with17h[0-9a-f]+E", symbol))
    new, old = paths[role]
    return bool(re.fullmatch(r"_RNv" + new + "|_ZN" + old + r"17h[0-9a-f]+E", symbol))


def calls(body, predicate):
    found = []
    for label, lines in flow.blocks(body).items():
        for index, line in enumerate(lines):
            call = syntax.call(line)
            if call and predicate(*call):
                found.append((label, index, call[0], call[1]))
    return found


def one(body, predicate, description):
    found = calls(body, predicate)
    require(len(found) == 1, "missing/repeated MD5 phase: " + description)
    return found[0]


def dominates(graph, before, after):
    """All paths (including exceptional edges) to after must pass before."""
    start = next(iter(graph))
    require(before[0] in handoff.reachable(graph, start) and after[0] in handoff.reachable(graph, start),
            "unreachable MD5 phase")
    if before[0] == after[0]:
        require(before[1] < after[1], "reordered MD5 phases")
        return
    visited, pending = set(), [start]
    while pending:
        label = pending.pop()
        require(label in graph, "unknown MD5 phase edge")
        if label in visited or label == before[0]:
            continue
        require(label != after[0], "MD5 phase bypass")
        visited.add(label)
        pending.extend(re.findall("label %" + flow.LABEL, "\n".join(graph[label])))


def allocations(body):
    return {name: int(size) for name, size in re.findall(rf"({VALUE}) = alloca \[(\d+) x i8\],", body)}


def owner(allocs, name, size):
    found = [value for value in allocs if re.fullmatch("%" + name + r"(?:\.[-\w]+)*", value)]
    require(len(found) == 1 and allocs[found[0]] == size, "MD5 phase allocation changed: " + name)
    return found[0]


def capture(body, site, root, expected, reading=False):
    """Allow only fixed GEPs and four pointer stores/loads, plus one dispatch.

    Every use of the capture or a derived address must be accounted for; casts,
    phi aliases, escapes, partial writes and additional uses fail closed. The
    four transfers must be in the dispatch block, with no intervening effects.
    """
    graph = flow.blocks(body)
    pointers = {name: origin for name, origin in syntax.pointers(body, (root,)).items() if origin[0] == root}
    names = set(pointers)
    accesses, permitted, starts = {}, set(), []
    dispatch = (site[0], site[1])
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            position = (label, index)
            if position == dispatch:
                continue
            uses = set(re.findall(VALUE, line)) & names
            if not uses:
                continue
            gep = re.match(rf"({VALUE}) = getelementptr (?:inbounds )?(?:nuw )?i8, ptr ({VALUE}), i64 (-?\d+)", line)
            if gep and gep[1] in pointers and gep[2] in pointers:
                require(pointers[gep[1]][1] in expected, "MD5 capture address out of bounds")
                permitted.add(position)
                continue
            if re.fullmatch(re.escape(root) + r" = alloca \[32 x i8\], align 8", line):
                require(not reading, "helper capture became local")
                continue
            call = syntax.call(line)
            if call and call[0] in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
                require(not reading and len(call[1]) in (1, 2) and syntax.operand(call[1][-1]) == root
                        and (len(call[1]) == 1 or call[1][0] == "i64 32"), "unexpected capture lifetime")
                if call[0] == "llvm.lifetime.start.p0":
                    starts.append(position)
                else:
                    require(label == site[0] and index > site[1] or
                            label != site[0] and site[0] not in handoff.reachable(graph, label),
                            "MD5 capture lifetime ends before dispatch")
                continue
            if reading:
                match = re.fullmatch(rf"({VALUE}) = load ptr, ptr ({VALUE}), align 8(?:, !.*)?", line)
                value, address = (match[1], match[2]) if match else (None, None)
            else:
                match = re.fullmatch(rf"store ptr ({VALUE}), ptr ({VALUE}), align 8(?:, !.*)?", line)
                value, address = (match[1], match[2]) if match else (None, None)
            require(match and address in pointers, "unparsed/escaping MD5 phase capture")
            base, offset = pointers[address]
            require(base == root and offset in expected and offset not in accesses
                    and value == expected[offset], "MD5 phase capture field changed/repeated")
            require(label == site[0] and index < site[1], "MD5 capture transfer outside dispatch block")
            accesses[offset] = index
            permitted.add(position)
    require(set(accesses) == set(expected), "incomplete MD5 phase capture")
    if not reading:
        require(len(starts) == 1 and starts[0][0] == site[0] and starts[0][1] < min(accesses.values()),
                "MD5 capture not live before field initialization")
    require(all((site[0], index) in permitted for index in range(min(accesses.values()), site[1])),
            "effect between MD5 capture transfer and dispatch")


def helper(signature, body):
    params = syntax.parameters(signature)
    require(len(params) == 3, "MD5 outer helper signature changed")
    workspace, record = (syntax.operand(arg) for arg in params[1:])
    site = one(body, lambda symbol, args: identity(symbol, "digest"), "outer digest")
    args = [syntax.operand(arg) for arg in site[3]]
    require(len(args) == 6 and args[1] == workspace and
            (allocations(body).get(args[0]) == 56 or
             args[0] == syntax.operand(params[0]) and "dereferenceable(56)" in params[0]),
            "MD5 outer helper workspace/result changed")
    require(len(set(args[2:])) == 4, "MD5 outer helper aliases capture values")
    capture(body, site, record, dict(zip((0, 8, 16, 24), args[2:])), reading=True)
    return site[2]


def check(signature, body, definitions, aliases):
    params = syntax.parameters(signature)
    require(len(params) == 5, "MD5 phase caller signature changed")
    selection, inputs, control = [syntax.operand(params[i]) for i in (1, 2, 4)]
    allocs = allocations(body)
    workspace, pad, messages, inner, outer_inputs, tags = [owner(allocs, name, size) for name, size in (
        ("workspace", 912), ("pad", 512), ("messages", 256), ("inner", 128),
        ("outer_inputs", 256), ("final_tags", 128))]
    new, pads, inner_site = [one(body, lambda symbol, args, role=role: identity(symbol, role), role)
                             for role in ("new", "pads", "digest")]
    outer = one(body, lambda symbol, args: identity(symbol, "outer") and len(args) == 3, "outer")
    final = one(body, lambda symbol, args: handoff.fence.helper(symbol) and len(args) == 1, "final")
    new_args = [syntax.operand(arg) for arg in new[3]]
    require(len(new_args) == 2 and new_args[0] == workspace, "MD5 workspace construction changed")
    pointers = syntax.pointers(body, (selection,))
    executor = re.search(re.escape(new_args[1]) + rf" = load ptr, ptr ({VALUE}),", body)
    require(executor and pointers.get(executor[1]) == (selection, 0), "MD5 workspace selection changed")
    require(len(pads[3]) == 6 and [syntax.operand(arg) for arg in pads[3][2:]] ==
            [inputs, pad, workspace, control], "MD5 normalization arguments changed")
    backend = re.fullmatch(rf"i8(?: noundef)? ({VALUE})", pads[3][1])
    load = re.search(re.escape(backend[1]) + rf" = load i8, ptr ({VALUE}),", body) if backend else None
    require(load and pointers.get(load[1]) == (selection, 16), "MD5 normalization backend changed")
    args = [syntax.operand(arg) for arg in inner_site[3]]
    require(len(args) == 6 and allocs.get(args[0]) == 56 and
            args[1:] == [workspace, pad, messages, inner, control], "MD5 inner phase arguments changed")
    args = [syntax.operand(arg) for arg in outer[3]]
    require(allocs.get(args[0]) == 56 and args[1] == workspace and allocs.get(args[2]) == 32,
            "MD5 outer phase result/workspace/capture changed")
    capture(body, outer, args[2], dict(zip((0, 8, 16, 24), (pad, outer_inputs, tags, control))))
    require(helper(*flow.resolve(outer[2], definitions, aliases)) == inner_site[2],
            "MD5 inner/outer primitive identity differs")
    require(syntax.operand(final[3][0]) == workspace, "MD5 final phase workspace changed")
    graph = flow.blocks(body)
    # Older compilers merge an inner-readiness error with the inner result using
    # phi/switch nodes. Plain CFG dominance cannot establish inner success before
    # outer entry; that result-propagation obligation is deliberately separate.
    for before, after in ((new, pads), (pads, inner_site), (pads, outer), (outer, final)):
        dominates(graph, before, after)


def validate(llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    for operation in ("authenticate", "authenticate_secret", "verify"):
        check(*rows.method(definitions, aliases, operation)[1], definitions, aliases)
