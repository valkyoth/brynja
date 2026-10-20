"""Constructor admission to the pre-key state pool, not iterator consumption.

Factory calls are typed consuming-callee contracts. Actual cleanup
helpers and all emitted admission/move/error/unwind edges are inspected here.
"""
import re

import hmac_constructor_state as provenance
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_admission_contracts as contracts
import hmac_execution_drop as cleanup

require, VALUE = common.require, syntax.VALUE


class State(provenance.State):
    def __init__(self):
        super().__init__()
        self.parts = set()

    def key(self):
        return super().key(), frozenset(self.parts)


def check(body, identity, definitions, aliases, compiler="1.99.1", panic="unwind",
          route=0, long_key=False):
    require(identity in common.IDENTITIES and compiler in ("1.90.0", "1.99.1")
            and panic in ("abort", "unwind") and route in (0, 1), "invalid admission profile")
    shape, discriminator, error, returned_error, pool = contracts.geometry(identity, compiler)
    allocs = {name: int(size) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    ptrs = syntax.pointers(body, (*allocs, "%_0", "%key.0", "%1"))
    graph = common.blocks(body)
    births, counts = {}, {"hash": 0, "session": 0}
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            invocation = syntax.call(line)
            kind = contracts.factory(invocation[0], identity) if invocation else None
            if kind:
                token = counts[kind]
                counts[kind] += 1
                births[label, index] = kind, token + (3 if kind == "session" else 0)
    require(counts == {"hash": 3, "session": 3 if identity.startswith("general") else 0},
            "admission factory population changed")
    queue = [(next(iter(graph)), 0, None, State(), False, frozenset())]
    visited, handoffs, failures, seen = set(), 0, 0, set()

    def address(name):
        return ptrs.get(name, (name, 0))

    def width(token):
        return 752 if token >= 3 else shape.stride

    def rooted(state, name):
        return any(row[0] == address(name)[0] for row in state.memory)

    def bounded(name, size):
        root, offset = address(name)
        require(0 <= offset and root in allocs and offset + size <= allocs[root],
                "admission owner copy outside private allocation")

    def number(value):
        if isinstance(value, tuple) and value[1:] == (discriminator, 8):
            return route
        return value if isinstance(value, int) else None

    def event(state, token, kind):
        require(token < 3 and kind in (shape.core_kind, shape.scratch_kind),
                "wrong admission cleanup component")
        require((token, kind) not in state.parts and token not in state.done,
                "duplicate admission cleanup")
        state.parts.add((token, kind))
        if all((token, component) in state.parts for component in (shape.core_kind, shape.scratch_kind)):
            state.done.add(token)

    while queue:
        label, index, predecessor, state, unwinding, trail = queue.pop()
        require((label, index) not in trail, "cyclic admission path")
        trail = trail | {(label, index)}
        key = label, index, predecessor, state.key(), unwinding
        if key in visited:
            continue
        visited.add(key)
        require(label in graph and len(visited) < 30000, "invalid admission graph")
        lines, terminal = graph[label], False
        while index < len(lines):
            line = lines[index]
            # No key byte may be accessed or forwarded during admission.
            require("%key.0" not in line, "key access before complete admission")
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            if derived and rooted(state, derived[2]):
                require(derived[1] in ptrs, "unresolved admission owner pointer")
            load = re.match("(" + VALUE + r") = load (?:i(\d+)|ptr), ptr (" + VALUE + ")", line)
            if load and rooted(state, load[3]):
                require(load[2], "admission owner pointer escape")
            provenance.evaluate(line, state, address, predecessor)
            compare = re.match("(" + VALUE + r") = icmp(?: samesign)? (eq|ne) i\d+ ("
                               + VALUE + r"), (-?\d+)", line)
            if compare:
                value = number(state.value(compare[3]))
                if value is not None:
                    state.assign(compare[1], int((value == int(compare[4])) == (compare[2] == "eq")))
            key_test = re.fullmatch("(" + VALUE + r") = icmp(?: samesign)? ugt i64 %key\.1, (\d+)",
                                    line)
            if "%key.1" in line:
                require(key_test and int(key_test[2]) == contracts.block_bytes(identity),
                        "unknown admission key-length branch")
                state.assign(key_test[1], int(long_key))
            invocation = syntax.call(line)
            normal, unwind = None, None
            if invocation:
                symbol, args = invocation
                if (label, index) in births:
                    kind, token = births[label, index]
                    destination = syntax.operand(args[0])
                    bounded(destination, width(token))
                    require(len(args) == 3, "admission factory arity changed")
                    if kind == "session" or not identity.startswith("general"):
                        require(re.fullmatch(r"i64 [^%]*%0", args[1])
                                and syntax.operand(args[2]) == "%1",
                                "admission authority/route changed")
                    else:
                        require(args[1] == "i16 noundef " + identity.removeprefix("general"),
                                "general admission parameter changed")
                        session = state.complete(address(syntax.operand(args[2])), 752)
                        require(session == token + 3, "general admission session provenance changed")
                        state.done.add(session)  # Sha512T::new consumes it on both edges.
                    require(panic == "abort" or re.search(r"\binvoke\b", line)
                            or state.born == state.done, "admission call can abandon previous owners")
                    unwind = state.clone()
                    success, failure = state.clone(), state.clone()
                    success.birth(address(destination), width(token), token)
                    root, offset = address(destination)
                    failure.constants[(root, offset + discriminator, 8)] = error
                    normal = [success, failure]
                    seen.add(token)
                elif symbol == "llvm.memcpy.p0.p0.i64":
                    destination, source = syntax.operand(args[0]), syntax.operand(args[1])
                    size = re.fullmatch(r"i64 (\d+)", args[2])
                    require(size, "unknown admission copy extent")
                    bounded(destination, int(size[1]))
                    state.transfer(address(destination), address(source), int(size[1]))
                elif symbol == "llvm.memset.p0.i64":
                    require(syntax.operand(args[0]) == "%pad.i" and args[1:3] == ["i8 0", "i64 144"],
                            "unreviewed admission memory initialization")
                    contracts.pool_handoff(state, identity, compiler, long_key)
                    handoffs += 1
                    terminal = True
                    break
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown admission lifetime")
                    root, offset = address(syntax.operand(args[-1]))
                    require(root in allocs and offset == 0, "unknown admission lifetime allocation")
                    if symbol == "llvm.lifetime.start.p0":
                        require(not rooted(state, root), "restart live admission storage")
                    else:
                        state.end(root)
                elif cleanup.leaf(symbol):
                    kind = cleanup.leaf(symbol)
                    root, offset = address(syntax.operand(args[0]))
                    base = offset - (shape.core if kind == shape.core_kind else 0)
                    token = state.complete((root, base), shape.stride)
                    event(state, token, kind)
                    require(panic == "abort" or unwinding or re.search(r"\binvoke\b", line)
                            or state.born == state.done,
                            "implicit cleanup unwind abandons admitted owner")
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    parameter, helper = cleanup.helper(symbol, definitions, aliases)
                    require(len(args) == 1, "admission cleanup helper arity")
                    token = state.complete(address(syntax.operand(args[0])), shape.stride)
                    expected = frozenset(((shape.core_kind, shape.core), (shape.scratch_kind, 0)))
                    outcomes = cleanup.walk(helper, parameter, 0, {discriminator: route},
                                            frozenset(), definitions, aliases, expected=expected,
                                            size=shape.stride, unwinding=unwinding, panic=panic)
                    require(outcomes and all(events == expected for _, events in outcomes),
                            "admission helper leaves core/CPU scratch live")
                    event(state, token, shape.core_kind)
                    event(state, token, shape.scratch_kind)
                    require(panic == "abort" or unwinding or re.search(r"\binvoke\b", line)
                            or not any(outcome == "resume" for outcome, _ in outcomes)
                            or state.born == state.done,
                            "implicit helper unwind abandons admitted owner")
                elif symbol == "llvm.experimental.noalias.scope.decl":
                    pass
                elif common.panic_cleanup(symbol):
                    require(unwinding and index + 1 < len(lines) and lines[index + 1] == "unreachable",
                            "admission fatal exemption on normal entry")
                    terminal = True
                    break
                else:
                    require(False, "unknown admission call: " + symbol)
            elif line.startswith("store "):
                store = re.match(r"store (?:i(\d+)|ptr) (.*?), ptr (" + VALUE + "),", line)
                vector = re.match(r"store <2 x i64> <i64 (-?\d+), i64 (-?\d+)>, ptr ("
                                  + VALUE + "),", line)
                require(store or vector, "unreviewed admission write: " + line)
                if vector:
                    value = (int(vector[1]) % (1 << 64)) | (int(vector[2]) % (1 << 64) << 64)
                    bounded(vector[3], 16)
                    state.store(address(vector[3]), 16, value)
                else:
                    size = (int(store[1]) + 7) // 8 if store[1] else 8
                    value = state.value(store[2])
                    if not store[1]:
                        require(not rooted(state, store[2]), "admission pointer escape")
                    if isinstance(value, tuple):
                        bounded(store[3], size)
                    state.store(address(store[3]), size, value)
            elif not (derived or load or key_test or line.startswith(("br ", "switch "))):
                definition = re.match("(" + VALUE + r") =", line)
                references = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(rooted(state, name) for name in references),
                        "unknown admission owner-pointer operation")
                scalar_refs = [name for name in references if isinstance(state.value(name), tuple)]
                require(not scalar_refs or compare or " = phi i" in line,
                        "unknown admission owner-scalar operation")
            if re.search(r"\binvoke\b", line):
                edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                     + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed admission invoke")
                queue.extend((edges[1], 0, label, item, unwinding, trail)
                             for item in normal or [state.clone()])
                queue.append((edges[2], 0, label, unwind or state.clone(), True, trail))
                terminal = True
                break
            if normal:
                queue.extend((label, index + 1, predecessor, item, unwinding, trail) for item in normal)
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + common.LABEL, line)
                condition = re.match("br i1 (" + VALUE + ")", line)
                require(len(edges) == (2 if condition else 1), "unknown admission branch")
                known = number(state.value(condition[1])) if condition else None
                for edge, truth in zip(edges, (1, 0)):
                    if condition and known is not None and known != truth:
                        continue
                    child = state.clone()
                    if condition:
                        child.assign(condition[1], truth)
                    queue.append((edge, 0, label, child, unwinding, trail))
                terminal = True
                break
            if line.startswith("switch "):
                header = re.fullmatch(r"switch i\d+ (" + VALUE + "), label %" + common.LABEL + r" \[",
                                      line)
                require(header and "]" in lines[index + 1:], "unparsed admission switch")
                end = lines.index("]", index + 1)
                cases = [re.fullmatch(r"i\d+ (-?\d+), label %" + common.LABEL, item)
                         for item in lines[index + 1:end]]
                require(all(cases), "unknown admission switch cases")
                value = number(state.value(header[1]))
                for case in cases:
                    if value is None or value == int(case[1]):
                        child = state.clone()
                        child.assign(header[1], int(case[1]))
                        queue.append((case[2], 0, label, child, unwinding, trail))
                if value is None or value not in {int(case[1]) for case in cases}:
                    queue.append((header[2], 0, label, state.clone(), unwinding, trail))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(state.born == state.done, "admission failure leaks previous owner")
                if line.startswith("ret "):
                    require(contracts.constant(state, ("%_0", shape.discriminator), 8)
                            == returned_error % (1 << 64), "admission returns unexpected success")
                failures += 1
                terminal = True
                break
            require(line != "unreachable", "unknown admission fatal terminal")
            index += 1
        require(terminal, "unterminated admission block")
    expected_births = {0, 1, 2} if long_key else {0, 1}
    if identity.startswith("general"):
        expected_births |= {token + 3 for token in expected_births}
    require(handoffs and failures and seen == expected_births, "vacuous admission population")
