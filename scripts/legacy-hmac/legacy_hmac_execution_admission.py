"""Pre-key SHA-1 stream admission and transfer into the constructor iterator.

Stop before the pad lifetime begins: normalization/iterator consumption after
that frontier is a separate obligation. Exact primitive start/Drop contracts
and safe Rust non-aliasing are premises, not re-proved here.
"""
import re

import legacy_hmac_execution_final as final
import legacy_hmac_execution_handoff as handoff
import legacy_hmac_execution_admission_contracts as contracts

shared, syntax, flow = handoff.shared, handoff.syntax, handoff.flow
provenance, VALUE, require = handoff.provenance, handoff.VALUE, handoff.require
WIDTH, NICHE, POOL = 448, 441, 24


def executor_method(symbol, method):
    return bool(re.fullmatch(
        r"(?:_RNvM\w*_NtCs\w+_18brynja_legacy_sha118hardened_executionNtB\w+_8Executor|"
        r"_ZN18brynja_legacy_sha118hardened_execution8Executor)" + str(len(method)) + method
        + r"(?:17h[0-9a-f]+E)?", symbol))


class State(provenance.State):
    def __init__(self):
        super().__init__()
        self.starts = 0
        self.reported = False

    def key(self):
        return super().key(), self.starts, self.reported

    def transfer(self, destination, source, size):
        super().transfer(destination, source, size)
        root, offset = destination
        self.constants = {key: value for key, value in self.constants.items()
                          if key[0] != root or not (offset < key[1] + key[2] and key[1] < offset + size)}


def check(signature, body, panic, valid_tag, backend, long_key, niche, cache_niche):
    require(panic in ("abort", "unwind") and backend in (0, 1, 2) and niche in (0, 1), "unknown admission profile")
    formals = syntax.parameters(signature)
    require(len(formals) == 5 and syntax.operand(formals[0]) == "%_0"
            and syntax.operand(formals[1]) == "%executor" and syntax.operand(formals[2]) == "%key.0"
            and formals[3].endswith(" %key.1"), "constructor formal parameters changed")
    tag = re.search(VALUE + "$", formals[4])[0]
    allocations = {name: int(size) for name, size in re.findall(rf"({VALUE}) = alloca \[(\d+) x i8\],", body)}
    require(allocations.get("%streams") == 2264, "constructor iterator geometry changed")
    pads = [name for name, size in allocations.items() if size == 64 and re.fullmatch(r"%pad(?:\.[-\w]+)*", name)]
    require(len(pads) == 1, "constructor pad frontier changed")
    pointers = syntax.pointers(body, (*allocations, "%_0"))
    address = lambda name: pointers.get(name, (name, 0))
    graph = flow.blocks(body)
    queue = [(next(iter(graph)), 0, None, State())]
    seen, seeds, exits = set(), [], 0

    def bounded(name, width):
        root, offset = address(name)
        require(root in allocations and 0 <= offset <= allocations[root] - width, "unbounded admission move")

    def number(value):
        # A successful Stream's boolean niche is public type metadata, not
        # secret data. Its bytes still retain provenance during scalar moves.
        return niche if isinstance(value, tuple) and len(value) == 3 and value[1:] == (NICHE, 1) else value

    while queue:
        label, index, predecessor, state = queue.pop()
        key = label, index, predecessor, state.key()
        if key in seen:
            continue
        seen.add(key)
        require(label in graph and len(seen) < 5000, "unbounded admission graph")
        lines, terminal = graph[label], False
        while index < len(lines):
            line = lines[index]
            require("%key.0" not in re.findall(VALUE, line), "key read/escape before admission frontier")
            invocation = syntax.call(line)
            if invocation and invocation[0] == "llvm.lifetime.start.p0" and syntax.operand(invocation[1][-1]) == pads[0]:
                expected = set(range(3 if long_key else 2))
                require(valid_tag and backend != 2 and state.reported and state.starts == len(expected)
                        and state.born == expected and not state.done, "key frontier reached without complete admission")
                for token in expected:
                    require(state.complete(("%streams", POOL + token * WIDTH), WIDTH) == token,
                            "wrong admitted iterator owner/order")
                for offset, width, value in ((0, 8, 1), (8, 8, 0), (16, 8, 3), (1809, 1, cache_niche), (2257, 1, cache_niche)):
                    require(state.constants.get(("%streams", offset, width)) == value, "iterator admission metadata changed")
                if not long_key:
                    require(state.constants.get(("%streams", POOL + 2 * WIDTH + NICHE, 1)) == 2,
                            "short-key iterator contains unadmitted third stream")
                seeds.append((label, index, predecessor, state.clone()))
                terminal = True
                break
            definition = re.match(rf"({VALUE}) = (.*)", line)
            provenance.evaluate(line, state, address, predecessor)
            if definition:
                name, expression = definition.groups()
                if expression == f"add i64 {tag}, -10":
                    state.assign(name, ("tag-offset",))
                elif re.fullmatch(rf"icmp ult i64 {VALUE}, 11", expression):
                    operand = re.findall(VALUE, expression)[0]
                    if state.value(operand) == ("tag-offset",):
                        state.assign(name, int(valid_tag))
                elif re.fullmatch(r"icmp(?: samesign)? ugt i64 %key\.1, 64", expression):
                    state.assign(name, int(long_key))
                else:
                    compare = re.fullmatch(rf"icmp(?: samesign)? (eq|ne) i\d+ ({VALUE}), (-?\d+)", expression)
                    extract = re.fullmatch(rf"extractvalue \{{ i1, i8 \}} ({VALUE}), 1", expression)
                    mask = re.fullmatch(rf"and i8 ({VALUE}), 1", expression)
                    if compare:
                        value = number(state.value(compare[2]))
                        if isinstance(value, int):
                            state.assign(name, int((value == int(compare[3])) == (compare[1] == "eq")))
                    elif extract and state.value(extract[1]) == ("report",):
                        state.assign(name, backend)
                    elif mask and isinstance(state.value(mask[1]), int):
                        state.assign(name, state.value(mask[1]) & 1)
                if tag in re.findall(VALUE, expression):
                    require(expression == f"add i64 {tag}, -10", "changed tag admission predicate")
                if "%key.1" in re.findall(VALUE, expression):
                    require(re.fullmatch(r"icmp(?: samesign)? ugt i64 %key\.1, 64", expression), "changed key-length admission predicate")
            if invocation:
                symbol, args = invocation
                if executor_method(symbol, "report"):
                    require(valid_tag and not state.reported and not state.starts and len(args) == 1
                            and syntax.operand(args[0]) == "%executor" and definition, "invalid authority report order/binding")
                    state.reported = True
                    state.assign(definition[1], ("report",))
                elif executor_method(symbol, "start"):
                    require(valid_tag and state.reported and backend != 2
                            and state.starts < (3 if long_key else 2) and len(args) == 2
                            and state.born == set(range(state.starts)) and not state.done
                            and syntax.operand(args[1]) == "%executor", "unapproved/extra stream admission")
                    destination = syntax.operand(args[0])
                    bounded(destination, WIDTH)
                    require(re.search(r"sret\(\[448 x i8\]\)", args[0]), "start result geometry changed")
                    require(not state.overlap(address(destination), WIDTH), "admission overwrites live owner")
                    failure, success = state.clone(), state.clone()
                    # The failure payload stays unknown: only its independently
                    # probed outer niche is fixed. Error-payload branches remain
                    # conservative, not just the Quarantined example probe.
                    root, offset = address(destination)
                    failure.constants[(root, offset + NICHE, 1)] = 2
                    success.birth(address(destination), WIDTH, state.starts)
                    failure.starts += 1
                    success.starts += 1
                    if "invoke " in line:
                        edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL, lines[index + 1])
                        require(edges, "unknown admission unwind edges")
                        queue.extend((edges[1], 0, label, child) for child in (failure, success))
                        queue.append((edges[2], 0, label, state.clone()))
                    else:
                        require(panic == "abort" or not state.born, "stream admission loses prior owners on unwind")
                        queue.extend((label, index + 1, predecessor, child) for child in (failure, success))
                    terminal = True
                    break
                elif symbol == "llvm.memcpy.p0.p0.i64":
                    require(len(args) == 4 and re.fullmatch(r"i64 \d+", args[2]) and args[3] == "i1 false", "unknown admission copy")
                    destination, source, width = syntax.operand(args[0]), syntax.operand(args[1]), int(args[2][4:])
                    bounded(destination, width)
                    bounded(source, width)
                    state.transfer(address(destination), address(source), width)
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"), "unknown admission lifetime")
                    root, offset = address(syntax.operand(args[-1]))
                    require(root in allocations and offset == 0, "unknown admission lifetime root")
                    if symbol.endswith("end.p0"):
                        state.end(root)
                    else:
                        require(not state.overlap((root, 0), allocations[root]), "admission restarts live owner")
                elif shared.owner_drop(symbol, "sha1"):
                    require(len(args) == 1, "admission destructor arity changed")
                    root, offset = address(syntax.operand(args[0]))
                    state.done.add(state.complete((root, offset - 8), WIDTH))
                else:
                    require(symbol == "llvm.experimental.noalias.scope.decl" or flow.panic_cleanup(symbol),
                            "unknown pre-key admission call: " + symbol)
            elif line.startswith("store "):
                store = re.match(rf"store i(\d+) (.*?), ptr ({VALUE}),", line)
                vector = re.fullmatch(rf"store <2 x i64> <i64 (-?\d+), i64 (-?\d+)>, ptr ({VALUE}), align \d+", line)
                if vector:
                    root, offset = address(vector[3])
                    bounded(vector[3], 16)
                    for part in range(2):
                        state.store((root, offset + part * 8), 8, int(vector[part + 1]))
                    index += 1
                    continue
                require(store, "unknown admission store/escape")
                width, value = (int(store[1]) + 7) // 8, state.value(store[2])
                root, offset = address(store[3])
                capacity = 912 if root == "%_0" else allocations.get(root, -1)
                require(0 <= offset <= capacity - width, "unbounded admission store")
                if isinstance(value, tuple):
                    bounded(store[3], width)
                state.store(address(store[3]), width, value)
            elif definition:
                if re.search(r"getelementptr|load ", definition[2]):
                    refs = re.findall(VALUE, definition[2])
                    require(refs and (address(refs[0])[0] in allocations or
                            ("getelementptr" in definition[2] and address(refs[0])[0] == "%_0")),
                            "admission reads/derives unknown storage: " + line)
                    if "getelementptr" in definition[2]:
                        require(definition[1] in pointers, "unknown admission pointer arithmetic")
                    else:
                        load = re.match(rf"load i(\d+), ptr ({VALUE}),", definition[2])
                        require(load, "untracked admission load/alias")
                        bounded(load[2], (int(load[1]) + 7) // 8)
                elif re.search(r"phi ptr|ptrtoint|inttoptr|bitcast|select .*ptr", definition[2]):
                    require(False, "untracked admission alias")
            if "%executor" in re.findall(VALUE, line):
                require(invocation and any(executor_method(invocation[0], method) for method in ("report", "start")),
                        "authority pointer escaped admission")
            if "invoke " in line:
                edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unknown admission cleanup unwind")
                queue.extend((edge, 0, label, state.clone()) for edge in edges.groups())
                terminal = True
                break
            branch = re.fullmatch(rf"br i1 ({VALUE}), label %" + flow.LABEL + ", label %" + flow.LABEL, line)
            jump = re.fullmatch("br label %" + flow.LABEL, line)
            if branch or jump:
                value = state.value(branch[1]) if branch else None
                targets = [jump[1]] if jump else ([branch[2 if value else 3]] if value in (0, 1) else branch.groups()[1:])
                queue.extend((edge, 0, label, state.clone()) for edge in targets)
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(state.done == state.born, "admission exits with live owner")
                if line.startswith("ret "):
                    require(state.constants.get(("%_0", 904, 1)) == 2, "pre-key path returns constructor success")
                    expected = 1 if not valid_tag else 3 if backend == 2 else None
                    if expected is not None:
                        require(not state.starts and state.constants.get(("%_0", 0, 1)) == expected,
                                "admission rejection identity changed")
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(flow.fatal_cleanup_block(lines), "unknown admission fatal path")
                terminal = True
                break
            index += 1
        require(terminal, "unterminated admission graph")
    require(exits and bool(seeds) == (valid_tag and backend != 2), "vacuous admission population")
    return seeds


def validate(llvm, fixture, panic):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    target, (signature, body) = final.method(definitions, aliases, "with_tag_length")
    cache = contracts.validate(fixture, target)
    contracts.forwarding(final.method(definitions, aliases, "new")[1][1], target, "20")
    for valid in (False, True):
        for backend in (0, 1, 2):
            for long_key in (False, True):
                for niche in (0, 1):
                    check(signature, body, panic, valid, backend, long_key, niche, cache)
