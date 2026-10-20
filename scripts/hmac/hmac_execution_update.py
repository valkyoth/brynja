"""Consuming accelerated update consumers: bounded logical-owner dispatch."""
import re

import hmac_engine_codegen as common
import hmac_execution_drop as cleanup
from hmac_execution_drop import SSA, SYMBOL, require

UNKNOWN = "unknown-public-result"


def update_symbol(symbol, identity):
    if identity.startswith("general"):
        patterns = (
            r"_RNvMNtNtCs\w+_16brynja_hash_sha218hardened_execution7generalNtB\w+_7Sha512T6update",
            r"_ZN16brynja_hash_sha218hardened_execution7general7Sha512T6update17h[0-9a-f]+E",
        )
    else:
        name = {"sha224": "Sha224", "sha256": "Sha256", "sha384": "Sha384",
                "sha512": "Sha512", "sha512_224": "Sha512_224",
                "sha512_256": "Sha512_256", "sha3_224": "Sha3_224",
                "sha3_256": "Sha3_256", "sha3_384": "Sha3_384",
                "sha3_512": "Sha3_512"}[identity]
        patterns = (
            r"_RNvXs\w*_NtNtCs\w+_15brynja_mac_hmac9execution8backendsNtNtB\w+_10algorithms"
            + str(len(name)) + name + r"NtB\w+_7Backend10update_cpu",
            r"_ZN\d+_\$LT\$brynja_mac_hmac\.\.algorithms\.\." + name
            + r"\$u20\$as\$u20\$brynja_mac_hmac\.\.execution\.\.backends\.\."
            r"Backend\$GT\$10update_cpu17h[0-9a-f]+E",
        )
    return any(re.fullmatch(pattern, symbol) for pattern in patterns)


def check(body, identity, definitions, aliases, compiler, panic):
    shape = cleanup.layout(identity)
    graph = common.blocks(body)
    allocations = dict((name, int(width)) for name, width in re.findall(
        rf"({SSA}) = alloca \[(\d+) x i8\], align \d+", body))
    total_updates = total_observers = exits = 0
    for route in (0, 1):
        for present in (False, True):
            memory, expected = cleanup.initial(identity, route, present, compiler)
            # Allocations carry independent discriminants, but copies transfer
            # the same logical inner/outer obligations, not new logical owners.
            queue = [(next(iter(graph)), 0, {"%state": ("state", 0)},
                      {"state": memory}, frozenset(), False)]
            steps = 0
            while queue:
                label, start, values, storage, done, unwinding = queue.pop()
                require(label in graph, "unknown accelerated update edge")
                steps += 1
                require(steps < 10000, "cyclic/oversized accelerated update graph")
                lines = graph[label]
                terminal = False

                def schedule(destination, events=done, exceptional=unwinding, position=0):
                    queue.append((destination, position, dict(values),
                                  {key: dict(value) if value is not None else None
                                   for key, value in storage.items()}, events, exceptional))

                def pointer(name):
                    value = values.get(name)
                    require(isinstance(value, tuple) and value[0] in storage
                            and storage[value[0]] is not None, "uninitialized update pointer")
                    return value

                for index in range(start, len(lines)):
                    line = lines[index]
                    allocation = re.fullmatch(rf"({SSA}) = alloca \[(\d+) x i8\], align \d+", line)
                    gep = re.fullmatch(
                        rf"({SSA}) = getelementptr inbounds(?: nuw)? i8, ptr ({SSA}), i64 (\d+)", line)
                    load = re.match(rf"({SSA}) = load i64, ptr ({SSA}),", line)
                    compare = re.fullmatch(rf"({SSA}) = icmp (?:samesign )?(eq|ne|ugt) i(8|64) ({SSA}), (-?\d+)", line)
                    store = re.match(rf"store i64 (-?\d+), ptr ({SSA}),", line)
                    call = re.search(rf"\b(call|invoke)\b.*(@{SYMBOL}|%observer)\(", line)
                    if allocation:
                        require(int(allocation[2]) in (shape.engine, shape.size)
                                and allocation[1] not in storage, "unknown update owner allocation")
                        storage[allocation[1]] = None
                        values[allocation[1]] = (allocation[1], 0)
                    elif gep:
                        root, offset = pointer(gep[2])
                        values[gep[1]] = (root, offset + int(gep[3]))
                    elif load:
                        root, offset = pointer(load[2])
                        require(offset in storage[root], "unreviewed update discriminator load")
                        values[load[1]] = storage[root][offset]
                    elif compare:
                        value = values.get(compare[4])
                        require(value is not None, "undefined update comparison operand")
                        if value == UNKNOWN or isinstance(value, frozenset):
                            values[compare[1]] = ("condition", compare[4], compare[2], int(compare[5]))
                        elif compare[2] == "eq":
                            values[compare[1]] = value == int(compare[5])
                        elif compare[2] == "ne":
                            values[compare[1]] = value != int(compare[5])
                        else:
                            require(False, "unreviewed concrete comparison")
                    elif store:
                        root, offset = pointer(store[2])
                        empty_memory, _ = cleanup.initial(identity, route, False, compiler)
                        require(root == "state" and offset == shape.discriminator
                                and int(store[1]) == empty_memory[offset],
                                "unexpected accelerated owner/discriminator write")
                        storage[root][offset] = int(store[1])
                    elif call:
                        symbol = call[2][1:].strip('"') if call[2].startswith("@") else "%observer"
                        if symbol == "llvm.memcpy.p0.p0.i64":
                            match = re.search(rf"ptr [^,]*({SSA}), ptr [^,]*({SSA}), i64 (\d+), i1 false\)", line)
                            require(match and int(match[3]) in (shape.engine, shape.size),
                                    "accelerated update copy extent")
                            source, offset = pointer(match[2])
                            destination = values.get(match[1])
                            require(source == "state" and offset == 0 and destination
                                    and destination[1] == 0 and storage[destination[0]] is None
                                    and int(match[3]) <= allocations.get(destination[0], 0),
                                    "accelerated update copy provenance")
                            require(not done or not present, "copy after owner destruction")
                            storage[destination[0]] = dict(storage[source])
                            continue
                        if symbol.startswith("llvm.lifetime."):
                            argument = re.search(rf"({SSA})\)", line)
                            require(argument and argument[1] in storage
                                    and argument[1] != "%state", "unknown update lifetime")
                            if symbol == "llvm.lifetime.end.p0":
                                require(done == expected, "update lifetime ends before destruction")
                                storage[argument[1]] = None
                            else:
                                require(symbol == "llvm.lifetime.start.p0"
                                        and storage[argument[1]] is None, "restarted update owner")
                            continue
                        if symbol in ("llvm.assume", "llvm.experimental.noalias.scope.decl"):
                            # Ignoring assumptions explores a conservative superset.
                            continue
                        if common.panic_cleanup(symbol):
                            require(unwinding and index + 1 < len(lines)
                                    and lines[index + 1] == "unreachable",
                                    "unreviewed update fatal terminal")
                            terminal = True
                            break
                        external = update_symbol(symbol, identity)
                        observer = symbol == "%observer"
                        if external or observer:
                            require(panic == "abort" or call[1] == "invoke",
                                    "unwind-capable update/observer lacks cleanup edge")
                            require(present and not done,
                                    f"update/observer after terminal cleanup: {identity} {label} "
                                    f"present={present} done={done}")
                            if external:
                                arguments = re.findall(rf"ptr [^%]*?({SSA})(?:,|\))", line)
                                require(arguments == ["%state", "%input.0"]
                                        and pointer("%state") == ("state", 0)
                                        and re.search(r"i64 [^\n]*%input\.1\)", line),
                                        "accelerated update arguments changed")
                                result = re.match(rf"({SSA}) = ", line)
                                require(result, "missing accelerated update result")
                                values[result[1]] = frozenset(range(-128, 128))
                                total_updates += 1
                            else:
                                require(re.search(r"%observer\(\)", line), "observer signature changed")
                                total_observers += 1
                            outcomes = [("ret", done), ("resume", done)]
                        else:
                            argument = re.search(rf"({SSA})\)(?: #[0-9]+)?(?:,.*)?$", line)
                            require(argument, "unresolved update cleanup argument")
                            root, offset = pointer(argument[1])
                            kind = cleanup.leaf(symbol)
                            if kind:
                                event = (kind, offset)
                                require(event in expected and event not in done,
                                        "wrong/duplicate accelerated update cleanup")
                                outcomes = [("ret", done | {event}), ("resume", done | {event})]
                            else:
                                parameter, nested = cleanup.helper(symbol, definitions, aliases)
                                outcomes = cleanup.walk(nested, parameter, offset, storage[root],
                                                        done, definitions, aliases,
                                                        unwinding=unwinding, panic=panic)
                                require(all(events <= expected for _, events in outcomes),
                                        "unexpected update helper destruction")
                        if call[1] == "invoke":
                            require(index + 1 < len(lines), "missing update invoke edges")
                            edges = re.fullmatch("to label %" + common.LABEL
                                                 + " unwind label %" + common.LABEL, lines[index + 1])
                            require(edges, "invalid update invoke")
                            for outcome, events in outcomes:
                                schedule(edges[1 if outcome == "ret" else 2], events,
                                         unwinding or outcome == "resume")
                            terminal = True
                            break
                        normal = [events for outcome, events in outcomes if outcome == "ret"]
                        if panic == "unwind":
                            require(all(events == expected for outcome, events in outcomes
                                        if outcome == "resume"),
                                    "implicit helper unwind leaves live accelerated owners")
                        require(normal and all(events == normal[0] for events in normal),
                                "ambiguous normal update helper")
                        done = normal[0]
                    elif line.startswith("br "):
                        direct = re.fullmatch("br label %" + common.LABEL, line)
                        branch = re.fullmatch(rf"br i1 ({SSA}), label %" + common.LABEL
                                              + ", label %" + common.LABEL, line)
                        require(direct or branch, "unsupported update branch")
                        if direct:
                            schedule(direct[1], done)
                        else:
                            condition = values.get(branch[1])
                            require(type(condition) is bool or condition == UNKNOWN
                                    or isinstance(condition, tuple) and condition[0] == "condition",
                                    "undefined accelerated branch")
                            if isinstance(condition, tuple):
                                _, operand, predicate, constant = condition
                                domain = values[operand]
                                if domain == UNKNOWN:
                                    domain = frozenset(range(-128, 128))
                                require(isinstance(domain, frozenset), "unsupported condition domain")
                                for truth in (False, True):
                                    subset = frozenset(value for value in domain
                                                       if {"eq": value == constant,
                                                           "ne": value != constant,
                                                           "ugt": value % 256 > constant % 256
                                                           }[predicate] == truth)
                                    if subset:
                                        values[operand] = subset
                                        schedule(branch[2 if truth else 3], done)
                            elif condition == UNKNOWN:
                                for truth in (False, True):
                                    values[branch[1]] = truth
                                    schedule(branch[2 if truth else 3], done)
                            else:
                                schedule(branch[2 if condition else 3], done)
                        terminal = True
                        break
                    elif line.startswith("switch "):
                        switch = re.fullmatch(rf"switch i8 ({SSA}), label %" + common.LABEL + r" \[", line)
                        require(switch and lines[-1] == "]", "unknown update switch")
                        cases = []
                        for row in lines[index + 1:-1]:
                            case = re.fullmatch(r"i8 (-?\d+), label %" + common.LABEL, row)
                            require(case, "unknown update switch case")
                            cases.append((int(case[1]), case[2]))
                        require(len({value for value, _ in cases}) == len(cases)
                                and all(-128 <= value < 128 for value, _ in cases),
                                "duplicate/out-of-range update switch case")
                        domain = values.get(switch[1])
                        if domain == UNKNOWN:
                            domain = frozenset(range(-128, 128))
                        require(isinstance(domain, frozenset), "undefined switch operand")
                        for value, target in cases:
                            if value in domain:
                                values[switch[1]] = frozenset({value})
                                schedule(target, done)
                        remaining = domain - {value for value, _ in cases}
                        if remaining:
                            values[switch[1]] = remaining
                            schedule(switch[2], done)
                        terminal = True
                        break
                    elif line.startswith(("ret i8 ", "resume ")):
                        require(done == expected, "accelerated update exits with live owners")
                        exits += 1
                        terminal = True
                        break
                    elif (re.match(rf"{SSA} = (phi i8|add nsw i8|select i1) ", line)):
                        name = line.split(" =", 1)[0]
                        values[name] = UNKNOWN
                    elif (re.fullmatch(rf"{SSA} = landingpad \{{ ptr, i32 \}}", line)
                          or re.match(rf"{SSA} = phi \{{ ptr, i32 \}} ", line)
                          or line in ("cleanup", "filter [0 x ptr] zeroinitializer")):
                        pass
                    else:
                        require(False, "unsupported accelerated update instruction: " + line)
                require(terminal, "unterminated accelerated update block")
    require(exits and total_updates and total_observers, "vacuous accelerated update/observer")
