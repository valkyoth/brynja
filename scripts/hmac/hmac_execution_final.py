"""Logical accelerated finalizer ownership through actual emitted adapter bodies.

Copies preserve logical provenance, not erased source storage. Terminal hash
finalizers/leaf cleanup and safe-Rust non-aliasing are separate premises.
"""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as cleanup
import hmac_execution_final_contracts as contracts

require = common.require
VALUE = syntax.VALUE


def check(body, identity, definitions, aliases, panic="unwind", seed=None, depth=0, route=0,
          profile="runtime"):
    return _check(body, identity, definitions, aliases, panic, seed, depth, route, set(), profile)


def _check(body, identity, definitions, aliases, panic, seed, depth, route, checked, profile):
    require(depth < 4 and route in ((0, 1) if profile == "runtime" else range(16))
            and identity in common.IDENTITIES
            and panic in ("abort", "unwind"), "recursive/invalid accelerated finalizer")
    shape = cleanup.layout(identity, profile)
    width = shape.stride

    if seed is None:
        seed = (("%self", 0, 0), ("%self", width, 1))
    key = body, tuple(seed)
    if key in checked:
        return
    tokens = frozenset(row[2] for row in seed)
    obligation_table = {token: contracts.events(identity, token, profile, route) for token in tokens}
    metadata_table = {token: contracts.owner_metadata(identity, token, profile, route) for token in tokens}

    def obligations(token):
        require(token in obligation_table, "unknown finalizer obligation token")
        return obligation_table[token]

    expected = frozenset(event for token in tokens for event in obligations(token))
    allocs = {name: int(size) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    ptrs = syntax.pointers(body, (*allocs, *(row[0] for row in seed)))
    graph = common.blocks(body)
    queue = [(next(iter(graph)), frozenset(seed), frozenset(), (), False)]
    visited, exits = set(), 0

    def address(name):
        return ptrs.get(name, (name, 0))

    def intersect(memory, name, extent=1):
        root, offset = address(name)
        return {row for row in memory if row[0] == root
                and offset < row[1] + width and row[1] < offset + extent}

    def select(memory, name, kind=None):
        return contracts.select(memory, address(name), kind, shape, profile)

    def complete(done):
        require(done == expected, "accelerated finalizer exits with live/wrong owner: "
                + repr((done, expected)))

    while queue:
        label, memory, done, known, unwinding = queue.pop()
        state = label, memory, done, known, unwinding
        if state in visited:
            continue
        visited.add(state)
        require(label in graph and len(visited) < 30000, "invalid accelerated finalizer graph")
        values = dict(known)
        lines, terminal, outcomes = graph[label], False, None
        for index, line in enumerate(lines):
            definition = re.match("(" + VALUE + r") =", line)
            if definition:
                values.pop(definition[1], None)
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            if derived and any(row[0] == address(derived[2])[0] for row in memory):
                require(derived[1] in ptrs, "unresolved accelerated owner pointer")
            if re.search(r"= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)", line):
                referenced = re.findall(VALUE, line)[1:]
                require(not any(address(name)[0] == row[0] for row in memory for name in referenced),
                        "unsupported accelerated owner alias")
            load = re.match("(" + VALUE + r") = load (i8|i64|ptr), ptr (" + VALUE + "),", line)
            any_load = re.match("(" + VALUE + r") = load [^,]+, ptr (" + VALUE + "),", line)
            if any_load and intersect(memory, any_load[2]):
                root, offset = address(any_load[2])
                rows = [row for row in memory if row[0] == root and row[1] <= offset < row[1] + width]
                require(load and len(rows) == 1,
                        "unreviewed load from accelerated owner")
                token = rows[0][2]
                metadata = cleanup.metadata(metadata_table[token],
                                            offset - rows[0][1], load[2])
                # Static Portable/Cpu cleanup reads the null niche after core
                # destruction. This is still live enclosing metadata, not a
                # read after a consuming finalizer/adapter returned.
                require(not values.get("consumed:" + str(token))
                        and (not obligations(token) <= done or
                             profile == "static" and metadata == ("nonnull", False)),
                        "read after accelerated owner consumption")
                values[load[1]] = metadata
            compare = re.match("(" + VALUE + r") = icmp (eq|ne) (i8|i64|ptr) ("
                               + VALUE + r"), (-?\d+|null)", line)
            if compare and compare[4] in values:
                value = values[compare[4]]
                if compare[3] == "ptr":
                    require(isinstance(value, tuple) and value[0] == "nonnull"
                            and compare[5] == "null", "unknown finalizer pointer condition")
                    equal = not value[1]
                else:
                    require(isinstance(value, int) and compare[5] != "null",
                            "unknown finalizer metadata condition")
                    equal = value == int(compare[5])
                values[compare[1]] = equal if compare[2] == "eq" else not equal
            invocation = syntax.call(line)
            outcomes = None
            if invocation:
                symbol, args = invocation
                if symbol == "llvm.memcpy.p0.p0.i64":
                    dest, source = syntax.operand(args[0]), syntax.operand(args[1])
                    match = re.fullmatch(r"i64 (\d+)", args[2])
                    require(match, "variable accelerated owner copy")
                    size = int(match[1])
                    src_root, src_offset = address(source)
                    dst_root, dst_offset = address(dest)
                    rows = intersect(memory, source, size)
                    require(not intersect(memory, dest, size), "overwrite accelerated owner")
                    additions = set()
                    for _, start, token in rows:
                        require(src_offset <= start and start + width <= src_offset + size,
                                "partial accelerated owner copy")
                        require(not (obligations(token) & done),
                                "copy after accelerated consumption")
                        additions.add((dst_root, dst_offset + start - src_offset, token))
                    if additions:
                        require(dst_root in allocs and dst_offset >= 0
                                and dst_offset + size <= allocs[dst_root], "owner copy outside allocation")
                    memory = memory | additions
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown accelerated owner lifetime")
                    root, offset = address(syntax.operand(args[-1]))
                    require(offset == 0, "interior accelerated lifetime")
                    rows = {row for row in memory if row[0] == root}
                    if symbol == "llvm.lifetime.start.p0":
                        require(not rows, "restart live accelerated owner")
                    else:
                        memory = memory - rows
                        require(all(obligations(token) <= done
                                    or any(row[2] == token for row in memory)
                                    for _, _, token in rows), "last accelerated owner lost")
                elif contracts.hash_finalizer(symbol, identity):
                    token = select(memory, syntax.operand(args[1]))
                    consumed = obligations(token)
                    require(not consumed & done, "duplicate accelerated finalizer")
                    done |= consumed
                    values["consumed:" + str(token)] = True
                    outcomes = [("ret", done), ("resume", done)]
                elif cleanup.leaf(symbol):
                    kind = cleanup.leaf(symbol)
                    token = select(memory, syntax.operand(args[0]), kind)
                    require(kind in (shape.core_kind, shape.scratch_kind), "wrong cleanup owner kind")
                    event = (kind, token * width + (shape.core if kind == shape.core_kind else
                                                   contracts.scratch_offset(shape, profile)))
                    require(event in expected and event not in done, "wrong/duplicate accelerated destruction")
                    done |= {event}
                    outcomes = [("ret", done), ("resume", done)]
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    outcomes = contracts.destruction(
                        symbol, address(syntax.operand(args[0])), memory, done, identity,
                        definitions, aliases, route, panic, unwinding, profile)
                elif contracts.adapter(symbol):
                    formals, nested = common.resolve(symbol, definitions, aliases)
                    formals = syntax.parameters(formals)
                    require(len(formals) == len(args), "accelerated adapter signature changed")
                    nested_seed = []
                    for formal, actual in zip(formals, args):
                        if not actual.startswith("ptr "):
                            continue
                        root, offset = address(syntax.operand(actual))
                        extent = re.search(r"\bdereferenceable\((\d+)\)", formal)
                        rows = [row for row in memory if row[0] == root]
                        require(not rows or extent, "adapter owner lacks bounded parameter")
                        for base, start, token in memory:
                            if base == root and start < offset + int(extent[1]) and offset < start + width:
                                require(start >= offset and not obligations(token) & done,
                                        "wrong/consumed adapter owner")
                                require(start + width <= offset + int(extent[1]),
                                        "partial adapter owner parameter")
                                nested_seed.append((syntax.operand(formal), start - offset, token))
                    require(nested_seed and len({row[2] for row in nested_seed}) == len(nested_seed),
                            "missing/duplicate accelerated adapter owners")
                    _check(nested, identity, definitions, aliases, panic, tuple(nested_seed),
                           depth + 1, route, checked, profile)
                    done |= frozenset(event for _, _, token in nested_seed
                                      for event in obligations(token))
                    for _, _, token in nested_seed:
                        values["consumed:" + str(token)] = True
                    outcomes = [("ret", done), ("resume", done)]
                elif contracts.update(symbol):
                    token = select(memory, syntax.operand(args[0]))
                    require(token == 1 and not obligations(token) & done,
                            "wrong/consumed outer hash update")
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "outer update missing recoverable unwind cleanup")
                elif symbol == "llvm.memset.p0.i64":
                    require(not intersect(memory, syntax.operand(args[0]), int(args[2].split()[-1])),
                            "overwrite accelerated hash state")
                elif symbol == "llvm.assume":
                    pass  # Do not prune any obligation using compiler assumptions.
                elif common.panic_cleanup(symbol):
                    require(unwinding and index + 1 < len(lines) and lines[index + 1] == "unreachable",
                            "fatal cleanup exemption on normal entry")
                    terminal = True
                    break
                else:
                    require(syntax.auxiliary(symbol), "unknown accelerated finalizer call: " + symbol)
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            require(not intersect(memory, syntax.operand(arg)),
                                    "accelerated owner passed to auxiliary")
            elif re.search(r"\b(store|atomicrmw|cmpxchg)\b", line):
                store = re.match(r"store (?:ptr|i(\d+)) .*?, ptr (" + VALUE + ")", line)
                require(store, "unsupported accelerated owner write")
                size = (int(store[1]) + 7) // 8 if store[1] else 8
                require(not intersect(memory, store[2], size), "write into accelerated owner")
                if line.startswith("store ptr "):
                    value = re.match("store ptr (" + VALUE + "),", line)
                    require(not value or not intersect(memory, value[1]), "escaped accelerated owner pointer")
            elif not derived and not any_load and not line.startswith(("br ", "switch ")):
                # Do not silently invent provenance for an aggregate, integer
                # cast or other unsupported operation involving an owner pointer.
                referenced = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(intersect(memory, name) for name in referenced),
                        "unsupported accelerated owner-pointer operation")
            if re.search(r"\binvoke\b", line):
                edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                     + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed accelerated finalizer invoke")
                outcomes = outcomes or [("ret", done), ("resume", done)]
                queue.extend((edges[1 if outcome == "ret" else 2], memory, events,
                              tuple(sorted(values.items())), unwinding or outcome == "resume")
                             for outcome, events in outcomes)
                terminal = True
                break
            elif outcomes:
                normal = [events for outcome, events in outcomes if outcome == "ret"]
                if panic == "unwind":
                    for outcome, events in outcomes:
                        if outcome == "resume":
                            complete(events)
                require(normal and all(events == normal[0] for events in normal),
                        "ambiguous accelerated helper result")
                done = normal[0]
            if line.startswith(("br ", "switch ")):
                text = line if line.startswith("br ") else "\n".join(lines[index:]).split("]", 1)[0]
                edges = re.findall("label %" + common.LABEL, text)
                require(edges, "unparsed accelerated finalizer branch")
                condition = re.fullmatch("br i1 (" + VALUE + "), label %" + common.LABEL
                                         + ", label %" + common.LABEL
                                         + r"(?:, ![-\w.]+ !\d+)*", line)
                for n, edge in enumerate(edges):
                    child_values = dict(values)
                    if condition:
                        previous = values.get(condition[1])
                        value = n == 0
                        if previous is not None and previous != value:
                            continue
                        child_values[condition[1]] = value
                    else:
                        require(not line.startswith("br i1"), "unknown accelerated branch condition")
                    queue.append((edge, memory, done, tuple(sorted(child_values.items())), unwinding))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                complete(done)
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(False, "unreviewed accelerated finalizer terminal")
        require(terminal, "unterminated accelerated finalizer")
    require(exits, "vacuous accelerated finalizer")
    # Reuse only proven identical bodies/owner bindings in this one invocation.
    # No persisted receipt, cross-artifact or cross-route caching.
    checked.add(key)
