"""Post-admission SHA-1 constructor owner transfers, not register/copy erasure.

Primitive update/finalize/Drop contracts and non-unwinding clearing are premises.
This checks stream ownership, initialization dispatch and public metadata, not
the cryptographic contents of pads or the primitive implementations themselves.
"""
import re

import legacy_hmac_execution_admission as admission
import legacy_hmac_execution_construct_state as model
import legacy_hmac_execution_iterator as iterator

shared, flow, syntax = admission.shared, admission.flow, admission.syntax
require, VALUE, WIDTH = admission.require, admission.VALUE, admission.WIDTH
for dependency in ("hmac_execution_update",):
    shared.load(dependency)
contracts = shared.load("hmac_execution_construct_contracts")


def check(signature, body, definitions, aliases, llvm, panic, backend, long_key, niche, cache):
    seeds = admission.check(signature, body, panic, True, backend, long_key, niche, cache)
    allocations = {name: int(size) for name, size in re.findall(rf"({VALUE}) = alloca \[(\d+) x i8\],", body)}
    pointers = syntax.pointers(body, (*allocations, "%_0", "%key.0"))
    tag = re.findall(VALUE, syntax.parameters(signature)[4])[-1]
    types = iterator.walker.array_types(llvm, "static")
    selected = iterator.selected(body, definitions, aliases) if any(
        (item := syntax.call(line)) and "Flatten" in item[0] for line in body.splitlines()) else None
    graph = flow.blocks(body)
    queue = [(label, index, pred, model.State(seed, pointers), False) for label, index, pred, seed in seeds]
    visited, successes, failures, normalized = set(), 0, 0, False
    expected = (1, 2) if long_key else (0, 1)

    def bound(state, name, width):
        root, offset = state.address(name)
        capacity = 912 if root == "%_0" else allocations.get(root, -1)
        require(0 <= offset <= capacity - width, "post-admission move outside allocation")

    def complete(state):
        require(state.born == state.done, "constructor exits with live streams")

    while queue:
        label, index, predecessor, state, unwinding = queue.pop()
        key = label, index, predecessor, state.key(), unwinding
        if key in visited:
            continue
        visited.add(key)
        require(label in graph and len(visited) < 30000, "unbounded constructor transfer graph")
        lines, terminal = graph[label], False
        while index < len(lines):
            line = lines[index]
            evaluated = state.evaluate(line, predecessor, niche, types, tag)
            invocation = syntax.call(line)
            no_unwind = False
            require(invocation or not re.search(r"\b(?:call|invoke)\b", line), "unknown indirect constructor call")
            require(not re.search(r"\b(?:atomicrmw|cmpxchg)\b", line), "unknown constructor atomic write")
            if invocation:
                symbol, args = invocation
                if symbol == "llvm.memcpy.p0.p0.i64":
                    require(len(args) == 4 and re.fullmatch(r"i64 \d+", args[2]) and args[3] == "i1 false",
                            "variable/unknown constructor copy")
                    destination, source, width = syntax.operand(args[0]), syntax.operand(args[1]), int(args[2][4:])
                    bound(state, destination, width)
                    bound(state, source, width)
                    state.transfer(state.address(destination), state.address(source), width)
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"), "unknown constructor lifetime")
                    root, offset = state.address(syntax.operand(args[-1]))
                    require(root in allocations and offset == 0, "unknown constructor lifetime root")
                    if symbol.endswith("end.p0"):
                        state.end(root)
                    else:
                        require(not state.overlap((root, 0), allocations[root]), "constructor restarts owned storage")
                elif symbol == "llvm.memset.p0.i64":
                    require(len(args) == 4 and re.fullmatch(r"i64 \d+", args[2]), "unknown constructor memset")
                    destination, width = syntax.operand(args[0]), int(args[2][4:])
                    bound(state, destination, width)
                    require(not state.overlap(state.address(destination), width), "memset overwrites stream")
                    state.invalidate(state.address(destination), width)
                elif admission.final.model.stream_update(symbol):
                    require(len(args) == 3, "constructor update arity changed")
                    destination = syntax.operand(args[0])
                    token = state.complete(state.address(destination), WIDTH)
                    sequence = (0, 1, 2) if long_key else (0, 1)
                    require(len(state.updates) < len(sequence) and token == sequence[len(state.updates)],
                            "constructor updates wrong stream/order")
                    normalizing = long_key and not state.updates
                    require(state.address(destination) == (("%state.i", 0) if normalizing else
                            (("%inner.i", 0) if token == expected[0] else ("%outer.i", 0))),
                            "constructor update role changed")
                    require(syntax.operand(args[1]) == ("%key.0" if normalizing else "%pad.i")
                            and re.search(r"(?:%key\.1|64)$", args[2])
                            and args[2].endswith("%key.1" if normalizing else "64"), "constructor update input changed")
                    state.updates += (token,)
                    require(panic == "abort" or "invoke " in line, "update loses owners on unwind")
                elif admission.final.stream_finalizer(symbol, "sha1"):
                    require(len(args) == 4 and long_key and state.updates == (0,) and not state.normalized,
                            "wrong normalization dispatch")
                    token = state.complete(state.address(syntax.operand(args[1])), WIDTH)
                    require(token == 0 and syntax.operand(args[2]) == "%digest.i"
                            and args[3].endswith(" 20"), "wrong normalization owner/destination")
                    require(panic == "abort" or "invoke " in line, "normalization loses owners on unwind")
                    state.done.add(token)
                    state.normalized = normalized = True
                elif shared.owner_drop(symbol, "sha1"):
                    require(len(args) == 1, "constructor Drop arity changed")
                    root, offset = state.address(syntax.operand(args[0]))
                    state.done.add(state.complete((root, offset - 8), WIDTH))
                elif selected and symbol == selected[0]:
                    require(len(args) == 1 and syntax.operand(args[0]) == "%streams", "iterator storage changed")
                    cursor = state.constants.get(("%streams", 8, 8))
                    require(cursor in range(4) and state.constants.get(("%streams", 16, 8)) == 3
                            and state.constants.get(("%streams", 0, 8)) == 1, "remaining iterator range changed")
                    for offset in (1809, 2257):
                        require(state.constants.get(("%streams", offset, 1)) == cache, "unexpected live iterator cache")
                    remaining = range(cursor, 3 if long_key else 2)
                    for token in remaining:
                        require(state.complete(("%streams", 24 + token * WIDTH), WIDTH) == token,
                                "remaining iterator owner changed")
                        state.done.add(token)
                    memory = {(0, 8): 1, (8, 8): cursor, (16, 8): 3,
                              (1809, 1): cache, (2257, 1): cache}
                    memory.update({(24 + token * WIDTH + 441, 1): niche if token < (3 if long_key else 2) else 2
                                   for token in range(3)})
                    parameter, nested = selected[1]
                    outcomes = iterator.walker.walk(nested, parameter, 0, memory, definitions, aliases, panic,
                                                    unwinding=unwinding, types=types)
                    events = frozenset(("sha1", 32 + token * WIDTH) for token in remaining)
                    require(outcomes and all(result == events for _, result in outcomes), "remaining helper cleanup changed")
                    no_unwind = not any(exit == "resume" for exit, _ in outcomes)
                else:
                    mask = re.fullmatch(r"_RNvNtCs\w+_11brynja_core13secret_memory20xor_secret_byte_bits|"
                                        r"_ZN11brynja_core13secret_memory20xor_secret_byte_bits17h[0-9a-f]+E", symbol)
                    require(syntax.auxiliary(symbol) or flow.panic_cleanup(symbol)
                            or symbol == "llvm.assume" or mask, "unknown constructor call: " + symbol)
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            require(not state.rooted(syntax.operand(arg)), "constructor stream escapes to auxiliary")
                    no_unwind = contracts.non_unwinding(symbol)
            elif line.startswith("store "):
                store = re.match(rf"store (?:i(\d+)|ptr) (.*?), ptr ({VALUE}),", line)
                require(store, "unknown constructor write")
                width = (int(store[1]) + 7) // 8 if store[1] else 8
                if not store[1]:
                    require(not state.rooted(store[2]), "constructor stream pointer escapes")
                value = state.value(store[2])
                bound(state, store[3], width)
                state.store(state.address(store[3]), width, value)
                if value == "tag-byte" or store[2] == tag:
                    require(width == (1 if value == "tag-byte" else 8), "constructor tag width changed")
                    state.tags.add((*state.address(store[3]), width))
            elif not evaluated and not line.startswith(("br ", "switch ")):
                definition = re.match(rf"({VALUE}) =", line)
                refs = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(state.rooted(name) for name in refs), "unknown constructor owner operation: " + line)
                require(not any(isinstance(state.value(name), tuple) for name in refs), "unknown owner scalar operation")
            if "invoke " in line:
                edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unknown constructor unwind edges")
                queue.append((edges[1], 0, label, state.clone(), unwinding))
                if not no_unwind:
                    queue.append((edges[2], 0, label, state.clone(), True))
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + flow.LABEL, line)
                condition = re.match(rf"br i1 ({VALUE})", line)
                require(len(edges) == (2 if condition else 1), "unknown constructor branch")
                value = state.value(condition[1]) if condition else None
                for edge, truth in zip(edges, (1, 0)):
                    if value is not None and value != truth:
                        continue
                    child = state.clone()
                    if condition:
                        child.assign(condition[1], truth)
                    queue.append((edge, 0, label, child, unwinding))
                terminal = True
                break
            if line.startswith("switch "):
                header = re.fullmatch(rf"switch i(\d+) ({VALUE}), label %" + flow.LABEL + r" \[", line)
                end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith("]")), None)
                require(header and end, "unknown constructor switch")
                cases = [re.fullmatch(r"i\d+ (-?\d+), label %" + flow.LABEL, item) for item in lines[index + 1:end]]
                require(all(cases), "unknown constructor cases")
                value = state.number(state.value(header[2]), niche)
                modulus = 1 << int(header[1])
                for case in cases:
                    if value is None or value % modulus == int(case[1]) % modulus:
                        queue.append((case[2], 0, label, state.clone(), unwinding))
                if value is None or value % modulus not in {int(case[1]) % modulus for case in cases}:
                    queue.append((header[3], 0, label, state.clone(), unwinding))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                if line.startswith("resume ") or state.constants.get(("%_0", 904, 1)) == 2:
                    complete(state)
                    failures += 1
                else:
                    require(not unwinding and state.constants.get(("%_0", 904, 1)) == backend,
                            "constructor returns wrong authority metadata")
                    for offset, token in zip((8, 456), expected):
                        require(state.complete(("%_0", offset), WIDTH) == token, "constructor returned wrong stream")
                    require(state.born - state.done == set(expected) and state.normalized == long_key
                            and state.updates == ((0, 1, 2) if long_key else (0, 1)), "incomplete constructor initialization")
                    require(("%_0", 0, 8) in state.tags or (("%_0", 0, 1) in state.tags
                            and state.constants.get(("%_0", 1, 7)) == 0), "constructor loses tag policy")
                    successes += 1
                terminal = True
                break
            if line == "unreachable":
                require(flow.fatal_cleanup_block(lines), "unknown constructor fatal path")
                terminal = True
                break
            index += 1
        require(terminal, "unterminated constructor graph")
    require(successes and failures and normalized == long_key, "vacuous post-admission qualification")


def validate(llvm, fixture, panic):
    contracts.validate()
    definitions, aliases = flow.definitions_and_aliases(llvm)
    target, (signature, body) = admission.final.method(definitions, aliases, "with_tag_length")
    cache = admission.contracts.validate(fixture, target)
    outlined = iterator.check(body, llvm, definitions, aliases, panic, cache)
    for backend in (0, 1):
        for long_key in (False, True):
            for niche in (0, 1):
                check(signature, body, definitions, aliases, llvm, panic, backend, long_key, niche, cache)
    return outlined
