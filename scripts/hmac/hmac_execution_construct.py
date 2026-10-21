"""Post-admission constructor owner transfers; no compiler-copy erasure claim."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_engine_construct as portable
import hmac_execution_admission as admission
import hmac_execution_admission_contracts as layout
import hmac_execution_construct_state as model
import hmac_execution_construct_contracts as contracts
import hmac_execution_drop as cleanup
import hmac_execution_final as final
import hmac_execution_iterator as iterator
import hmac_execution_scratch as scratch

require, VALUE = common.require, syntax.VALUE


def check(body, identity, definitions, aliases, compiler="1.99.1", panic="unwind",
          route=0, long_key=False, types=None, profile="runtime"):
    seeds = admission.check(body, identity, definitions, aliases, compiler, panic, route, long_key, profile)
    contracts.validate()
    shape, discriminator, _, returned_error, pool = layout.geometry(identity, compiler, profile)
    roles = layout.roles(body, profile)
    metadata_size = layout.metadata_size(profile)
    allocs = {name: int(size) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    ptrs = syntax.pointers(body, (*allocs, "%_0", "%key.0", roles["authority"]))
    graph = common.blocks(body)
    queue = [(label, index, pred, model.State(seed, ptrs), False, ())
             for label, index, pred, seed in seeds]
    visited, successes, failures, normalized = set(), 0, 0, set()
    expected_pair = (1, 2) if long_key else (0, 1)

    def bound(state, name, size):
        root, offset = state.address(name)
        limit = shape.size if root == "%_0" else allocs.get(root, -1)
        require(0 <= offset and offset + size <= limit, "constructor move outside bounded storage")

    def destroy(state, token, kind):
        require(token < 3 and kind in (shape.core_kind, shape.scratch_kind)
                and (token, kind) not in state.parts and token not in state.done,
                "wrong/repeated constructor cleanup")
        state.parts.add((token, kind))
        if all((token, part) in state.parts for part in (shape.core_kind, shape.scratch_kind)):
            state.done.add(token)

    def all_done(state):
        require(state.born == state.done, "constructor exits with unconsumed owners: "
                + repr((state.born - state.done, label)))

    while queue:
        label, index, predecessor, state, unwinding, trail = queue.pop()
        key = label, index, predecessor, state.key(), unwinding
        require(key not in trail and len(trail) < 150, "cyclic constructor transfer")
        if key in visited:
            continue
        visited.add(key)
        trail += (key,)
        require(label in graph and len(visited) < 30000, "oversized constructor transfer")
        lines, terminal = graph[label], False
        while index < len(lines):
            line = lines[index]
            no_unwind = False
            evaluated = state.evaluate(line, predecessor, discriminator, route, types or {}, profile)
            invocation = syntax.call(line)
            if invocation:
                symbol, args = invocation
                if symbol == "llvm.memcpy.p0.p0.i64":
                    dest, source = syntax.operand(args[0]), syntax.operand(args[1])
                    extent = re.fullmatch(r"i64 (\d+)", args[2])
                    require(extent, "variable constructor owner copy")
                    size = int(extent[1])
                    if state.overlap(state.address(source), size):
                        bound(state, dest, size)
                    state.transfer(state.address(dest), state.address(source), size)
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown constructor lifetime")
                    root, offset = state.address(syntax.operand(args[-1]))
                    require(offset == 0 and root in allocs, "unknown constructor allocation lifetime")
                    if symbol.endswith("end.p0"):
                        state.end(root)
                    else:
                        require(not state.rooted(root), "constructor restarts live owner")
                elif symbol == "llvm.memset.p0.i64":
                    require(not state.overlap(state.address(syntax.operand(args[0])),
                                              int(args[2].split()[-1])), "constructor overwrites owner")
                elif final.contracts.hash_finalizer(symbol, identity) or final.contracts.adapter(symbol):
                    name = syntax.operand(args[1])
                    token = state.complete(state.address(name), shape.stride)
                    require(long_key and token == 0 and state.updates == (0,) and not state.normalized,
                            "wrong constructor normalization owner/order")
                    if final.contracts.adapter(symbol):
                        arguments, nested = common.resolve(symbol, definitions, aliases)
                        formals = syntax.parameters(arguments)
                        require(len(formals) == len(args), "normalization adapter arity changed")
                        final.check(nested, identity, definitions, aliases, panic,
                                    ((syntax.operand(formals[1]), 0, token),),
                                    route=(12 | (route & 3)) if profile == "static" else route,
                                    profile=profile)
                    state.done.add(token)
                    state.normalized = True
                    normalized.add(token)
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "normalization loses remaining owners on unwind")
                elif final.contracts.update(symbol) or contracts.update_adapter(symbol):
                    if contracts.update_adapter(symbol):
                        contracts.borrowed_update(symbol, identity, definitions, aliases)
                    name = syntax.operand(args[0])
                    token = state.complete(state.address(name), shape.stride)
                    owners = {roles["hash"]: 0, roles["inner"]: expected_pair[0],
                              roles["outer"]: expected_pair[1]}
                    require(name in owners and token == owners[name], "constructor updates wrong owner role")
                    sequence = (0, 1, 2) if long_key else (0, 1)
                    require(len(state.updates) < len(sequence) and token == sequence[len(state.updates)],
                            "constructor update order changed")
                    normalizing = long_key and not state.updates
                    input_pointer = "%key.0" if normalizing else roles["pad"]
                    input_size = r"%key\.1" if normalizing else str(layout.block_bytes(identity))
                    require(len(args) == 3 and syntax.operand(args[1]) == input_pointer
                            and re.fullmatch(r"i64 [^%]*" + input_size, args[2]),
                            "constructor update input changed")
                    state.updates += (token,)
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "constructor update loses owners on unwind")
                elif cleanup.leaf(symbol):
                    kind = cleanup.leaf(symbol)
                    root, offset = state.address(syntax.operand(args[0]))
                    relative = shape.core if kind == shape.core_kind else (
                        80 if profile == "static" and shape.core_kind == "sha2" else 0)
                    token = state.complete((root, offset - relative),
                                           shape.stride)
                    destroy(state, token, kind)
                    if panic == "unwind" and not re.search(r"\binvoke\b", line):
                        all_done(state)
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    if "Flatten" in symbol:
                        require(scratch.independent_iterator(body, line, definitions, aliases),
                                "unknown constructor iterator destruction")
                        require(syntax.operand(args[0]) == roles["states"], "iterator storage changed")
                        cursor = model.iterator_cursor(state, identity, compiler, profile, roles["states"])
                        outcomes = iterator.check(symbol, identity, definitions, aliases, compiler, panic,
                                                  cursor, long_key, route, unwinding, types, profile)
                        for token in range(cursor, 3 if long_key else 2):
                            require(state.complete((roles["states"], pool + token * shape.stride),
                                                   shape.stride) == token, "remaining iterator owner changed")
                            destroy(state, token, shape.core_kind)
                            destroy(state, token, shape.scratch_kind)
                    else:
                        parameter, nested = cleanup.helper(symbol, definitions, aliases)
                        token = state.complete(state.address(syntax.operand(args[0])), shape.stride)
                        metadata, expected = layout.owner_cleanup(identity, compiler, profile, route, token)
                        outcomes = cleanup.walk(nested, parameter, 0, metadata,
                                                frozenset(), definitions, aliases, expected=expected,
                                                size=shape.stride, unwinding=unwinding, panic=panic)
                        require(all(events == expected for _, events in outcomes), "incomplete constructor drop")
                        destroy(state, token, shape.core_kind)
                        destroy(state, token, shape.scratch_kind)
                    no_unwind = not any(outcome == "resume" for outcome, _ in outcomes)
                    if panic == "unwind" and not no_unwind and not re.search(r"\binvoke\b", line):
                        all_done(state)
                elif common.panic_cleanup(symbol):
                    require(unwinding and lines[index + 1] == "unreachable", "constructor normal fatal exit")
                    terminal = True
                    break
                else:
                    require(syntax.auxiliary(symbol) or portable.mask(symbol) or symbol == "llvm.assume",
                            "unknown constructor transfer call: " + symbol)
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            require(not state.rooted(syntax.operand(arg)), "constructor owner escapes to auxiliary")
                    no_unwind = contracts.non_unwinding(symbol)
            elif line.startswith("store "):
                store = re.match(r"store (?:i(\d+)|ptr) (.*?), ptr (" + VALUE + "),", line)
                require(store, "unmodelled constructor write")
                size = (int(store[1]) + 7) // 8 if store[1] else 8
                if not store[1]:
                    require(not state.rooted(store[2]), "constructor pointer escape")
                value = state.value(store[2])
                if isinstance(value, tuple):
                    bound(state, store[3], size)
                state.store(state.address(store[3]), size, value)
            elif not evaluated and not line.startswith(("br ", "switch ")):
                definition = re.match("(" + VALUE + r") =", line)
                refs = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(state.rooted(name) for name in refs), "unknown constructor owner pointer operation")
                require(not any(isinstance(state.value(name), tuple) for name in refs),
                        "unknown constructor owner scalar operation")
            if re.search(r"\binvoke\b", line):
                edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                     + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed constructor invoke")
                targets = [(edges[1], unwinding)] + ([] if no_unwind else [(edges[2], True)])
                queue.extend((edge, 0, label, state.clone(), exceptional, trail)
                             for edge, exceptional in targets)
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + common.LABEL, line)
                condition = re.match("br i1 (" + VALUE + ")", line)
                require(len(edges) == (2 if condition else 1), "unknown constructor branch")
                known = state.value(condition[1]) if condition else None
                for edge, truth in zip(edges, (1, 0)):
                    if known is not None and known != truth:
                        continue
                    child = state.clone()
                    if condition:
                        child.assign(condition[1], truth)
                    queue.append((edge, 0, label, child, unwinding, trail))
                terminal = True
                break
            if line.startswith("switch "):
                header = re.fullmatch(r"switch i(\d+) (" + VALUE + "), label %"
                                      + common.LABEL + r" \[", line)
                require(header and "]" in lines[index + 1:], "unknown constructor switch")
                end = lines.index("]", index + 1)
                cases = [re.fullmatch(r"i\d+ (-?\d+), label %" + common.LABEL, item)
                         for item in lines[index + 1:end]]
                require(all(cases), "invalid constructor switch case")
                value = state.number(state.value(header[2]), discriminator, route, profile)
                modulus = 1 << int(header[1])
                for case in cases:
                    if value is None or value % modulus == int(case[1]) % modulus:
                        child = state.clone()
                        if value is None:
                            child.assign(header[2], int(case[1]))
                        queue.append((case[2], 0, label, child, unwinding, trail))
                if value is None or value % modulus not in {int(case[1]) % modulus for case in cases}:
                    queue.append((header[3], 0, label, state.clone(), unwinding, trail))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                if line.startswith("resume "):
                    all_done(state)
                    failures += 1
                elif layout.constant(state, ("%_0", shape.discriminator), metadata_size) == returned_error % (
                        1 << (8 * metadata_size)):
                    all_done(state)
                    failures += 1
                else:
                    for offset, token in zip((0, shape.stride), expected_pair):
                        require(state.complete(("%_0", offset), shape.stride) == token,
                                "returned constructor owner provenance changed")
                    require(state.born - state.done == set(expected_pair), "constructor success leaks owners")
                    require(state.updates == ((0, 1, 2) if long_key else (0, 1))
                            and state.normalized == long_key, "constructor success omits initialization")
                    bits = int(identity.removeprefix("general")) if identity.startswith("general") else (
                        int(identity.split("_")[-1]) if "_" in identity else int(identity[3:]))
                    require(layout.constant(state, ("%_0", 2 * shape.stride), 8) == (bits + 7) // 8,
                            "constructor returned tag width changed")
                    successes += 1
                terminal = True
                break
            require(line != "unreachable", "unknown constructor fatal terminal")
            index += 1
        require(terminal, "unterminated constructor transfer")
    require(successes and failures and normalized == ({0} if long_key else set()),
            "vacuous constructor owner transfer")
