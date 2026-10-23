"""Conservative byte-discriminant reachability over emitted MD5 caller CFGs.

Unknown data/operations never establish a successful exclusion: branch both
ways. Only byte loads from the modeled result, byte/bool SSA operations and
predecessor-specific phi values refine paths. This is not an LLVM interpreter
or a proof of report contents, returned error identity or memory erasure.
"""
import re

import legacy_hmac_md5_phases as phases

flow, syntax, require, VALUE = phases.flow, phases.syntax, phases.require, phases.VALUE


def value(text, values):
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if text in ("true", "false"):
        return int(text == "true")
    return values.get(text)


def evaluate(expression, values, previous, pointers, memory):
    load = re.match(rf"load i8, ptr ({VALUE}),", expression)
    if load:
        return memory.get(pointers.get(load[1]))
    phi = re.fullmatch(r"phi i([18]) (.*)", expression)
    if phi:
        entries = re.findall(r"\[ ([^,]+), %" + flow.LABEL + r" \]", phi[2])
        require(entries and len({label for _, label in entries}) == len(entries), "malformed MD5 error phi")
        selected = [operand for operand, label in entries if label == previous]
        require(len(selected) == 1, "MD5 error phi lacks predecessor")
        result = value(selected[0], values)
        return None if result is None else result & ((1 << int(phi[1])) - 1)
    extract = re.fullmatch(rf"extractvalue \{{ i8, i8 \}} ({VALUE}), ([01])", expression)
    if extract:
        pair = values.get(extract[1])
        return pair[int(extract[2])] if isinstance(pair, tuple) else None
    compare = re.fullmatch(r"icmp (eq|ne) i([18]) ([^,]+), ([^,]+)", expression)
    if compare:
        left, right = value(compare[3], values), value(compare[4], values)
        if left is None or right is None:
            return None
        mask = (1 << int(compare[2])) - 1
        return int(((left & mask) == (right & mask)) == (compare[1] == "eq"))
    binary = re.fullmatch(r"(and|or|xor) i([18]) ([^,]+), ([^,]+)", expression)
    if binary:
        left, right = value(binary[3], values), value(binary[4], values)
        if left is None or right is None:
            return None
        result = {"and": lambda: left & right, "or": lambda: left | right,
                  "xor": lambda: left ^ right}[binary[1]]()
        return result & ((1 << int(binary[2])) - 1)
    select = re.fullmatch(r"select i1 ([^,]+), i([18]) ([^,]+), i\2 ([^,]+)", expression)
    if select:
        condition = value(select[1], values)
        return None if condition is None else value(select[3 if condition else 4], values)
    return None


def ancestors(graph, destinations):
    parents = {label: set() for label in graph}
    for label, lines in graph.items():
        for child in re.findall("label %" + flow.LABEL, "\n".join(lines)):
            require(child in graph, "unknown MD5 result edge")
            parents[child].add(label)
    result, pending = set(), list(destinations)
    while pending:
        label = pending.pop()
        require(label in graph, "unknown MD5 result destination")
        if label not in result:
            result.add(label)
            pending.extend(parents[label])
    return result


def reaches(body, start, previous, values, result, error_tag, stops, barriers=frozenset()):
    """Overapproximate reachability; terminate cycles by finite byte-state reuse.

    `start` is a (block,index) immediately after a modeled call. Every unmodeled
    call or potentially aliasing write invalidates modeled memory. SSA values
    already loaded remain values, independent of subsequent memory changes.
    """
    graph = flow.blocks(body)
    relevant = ancestors(graph, {label for label, _ in stops})
    allocs = phases.allocations(body)
    pointers = syntax.pointers(body, tuple(allocs))
    memory = {(result, 48): error_tag} if result is not None else {}
    pending = [(start[0], start[1], previous, dict(values), memory)]
    seen = set()
    while pending:
        label, index, predecessor, state, memory = pending.pop()
        if label not in relevant:
            continue
        key = (label, index, predecessor, tuple(sorted(state.items())), tuple(sorted(memory.items())))
        if key in seen:
            continue
        seen.add(key)
        require(len(seen) <= 20000, "MD5 error reachability state bound exceeded")
        lines = graph[label]
        incoming = dict(state)  # phi nodes are simultaneous, not sequential assignments.

        def enqueue(child):
            require(child in graph, "unknown MD5 result branch")
            pending.append((child, 0, label, dict(state), dict(memory)))

        while index < len(lines):
            if (label, index) in barriers:
                break
            if (label, index) in stops:
                return True
            line = lines[index]
            definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
            invocation = syntax.call(line)
            if invocation:
                symbol, args = invocation
                if symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
                    # Ending/restarting result storage kills all modeled bytes.
                    origin = pointers.get(syntax.operand(args[-1]), (None, None))
                    if origin[0] not in allocs or origin[0] == result or origin[1] != 0:
                        memory.clear()
                elif symbol == "llvm.experimental.noalias.scope.decl":
                    pass
                else:
                    memory.clear()
                if definition:
                    state.pop(definition[1], None)
                if "invoke " in line:
                    require(index + 1 < len(lines), "truncated MD5 result invoke")
                    edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                         + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                    require(edges and index + 2 == len(lines), "malformed MD5 result invoke")
                    enqueue(edges[1])
                    enqueue(edges[2])
                    break
            elif definition:
                name, expression = definition.groups()
                # An unfamiliar value-producing instruction may also mutate
                # memory (e.g. atomicrmw/cmpxchg/va_arg). Only known non-writing
                # instruction classes may preserve the modeled result byte.
                if not re.match(r"(?:alloca|load|getelementptr|phi|extractvalue|insertvalue|extractelement|"
                                r"insertelement|shufflevector|icmp|fcmp|select|freeze|trunc|zext|sext|"
                                r"bitcast|ptrtoint|inttoptr|add|sub|mul|and|or|xor|shl|lshr|ashr|"
                                r"udiv|sdiv|urem|srem)\b", expression):
                    memory.clear()
                evaluated = evaluate(expression, incoming if expression.startswith("phi ") else state,
                                     predecessor, pointers, memory)
                state.pop(name, None)
                if evaluated is not None:
                    state[name] = evaluated
            elif line.startswith("store "):
                address = re.search(rf", ptr ({VALUE}),", line)
                root, offset = pointers.get(address[1], (None, None)) if address else (None, None)
                kind = re.match(r"store (ptr|i(\d+)) ", line)
                width = (8 if kind[1] == "ptr" else (int(kind[2]) + 7) // 8) if kind else None
                if root not in allocs or root == result or width is None or not 0 <= offset <= allocs[root] - width:
                    memory.clear()
            elif line.startswith("br "):
                jump = re.fullmatch("br label %" + flow.LABEL, line)
                branch = re.fullmatch(r"br i1 ([^,]+), label %" + flow.LABEL + ", label %" + flow.LABEL
                                      + r"(?:, ![-\w.]+ !\d+)*", line)
                require(index + 1 == len(lines) and (jump or branch), "unparsed MD5 result branch")
                if jump:
                    enqueue(jump[1])
                else:
                    condition = value(branch[1], state)
                    for child in (branch[2], branch[3]) if condition is None else (branch[2 if condition else 3],):
                        enqueue(child)
                break
            elif line.startswith("switch "):
                switch = re.fullmatch(r"switch i([18]) ([^,]+), label %" + flow.LABEL + r" \[", line)
                require(switch and lines[-1] == "]", "unparsed MD5 result switch")
                cases = [re.fullmatch(r"i" + switch[1] + r" (-?\d+), label %" + flow.LABEL, item)
                         for item in lines[index + 1:-1]]
                require(all(cases), "malformed MD5 result cases")
                mask = (1 << int(switch[1])) - 1
                choices = {int(case[1]) & mask: case[2] for case in cases}
                require(len(choices) == len(cases), "duplicate MD5 result case")
                tested = value(switch[2], state)
                for child in [switch[3], *choices.values()] if tested is None else [choices.get(tested & mask, switch[3])]:
                    enqueue(child)
                break
            elif line.startswith(("ret ", "resume ")) or line == "unreachable":
                break
            elif line.startswith(("landingpad ", "cleanup", "catch ", "filter ")):
                pass
            else:
                require(False, "unparsed MD5 error-path effect: " + line)
            index += 1
        else:
            require(False, "MD5 error path lacks terminator")
    return False
