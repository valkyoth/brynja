"""Retained Engine byte provenance through actual accelerated public wrappers.

This joins the public consumer to the separately checked Engine finalizer. It
does not claim erasure of compiler-created copies or inspect Tag's destructor.
"""
import re

import hmac_constructor_state as provenance
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as cleanup
import hmac_execution_scratch as scratch

require = common.require
VALUE = syntax.VALUE


def check(body, identity, operation, definitions, aliases, compiler="1.99.1", route=0,
          present=True):
    require(identity in common.IDENTITIES and operation in syntax.OPERATIONS and route in (0, 1)
            and compiler in ("1.90.0", "1.99.1"), "invalid wrapper profile")
    shape = cleanup.layout(identity)
    # Resolve the actual implementation; the driver checks its owner/cleanup
    # graph separately, for the same identity and both authority variants.
    engine = scratch.consumer(body, operation, definitions, aliases)
    calls = [syntax.call(line.strip()) for line in body.splitlines()
             if re.search(r"\b(?:call|invoke)\b.*@", line) and not line.lstrip().startswith(";")]
    candidates = [symbol for symbol, _ in calls if "15brynja_mac_hmac6engine" in symbol]
    require(len(candidates) == 1
            and common.resolve(candidates[0], definitions, aliases)[1] == engine,
            "ambiguous wrapper Engine edge")
    target = candidates[0]
    allocs = {name: int(size) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    ptrs = syntax.pointers(body, (*allocs, "%state", "%input", "%output.0", "%candidate.0"))
    graph = common.blocks(body)
    initial = provenance.State()
    if present:
        initial.birth(("%state", 0), shape.engine, 0)
    else:
        initial.constants[("%state", shape.discriminator, 8)] = (
            2 if identity.startswith("sha3_") else 3 if compiler == "1.90.0" else -1)
    queue = [(next(iter(graph)), None, initial, False, frozenset())]
    visited, exits, dispatched = set(), 0, False

    def address(name):
        return ptrs.get(name, (name, 0))

    def owner(state, name, size=1):
        return state.overlap(address(name), size)

    def rooted(state, name):
        return any(row[0] == address(name)[0] for row in state.memory)

    def bounded(name, size):
        root, offset = address(name)
        require(root in allocs and 0 <= offset and offset + size <= allocs[root],
                "wrapper move outside private allocation")

    def complete(state):
        require(state.done == state.born, "wrapper exits with undispatched Engine")

    def numerical(state, value):
        if value == (0, shape.discriminator, 8):
            require(0 not in state.done, "wrapper discriminator read after consumption")
            return route
        return value if isinstance(value, int) else None

    while queue:
        label, predecessor, state, cleared, trail = queue.pop()
        require(label not in trail, "cyclic wrapper path")
        trail = trail | {label}
        key = label, predecessor, state.key(), cleared
        if key in visited:
            continue
        visited.add(key)
        require(label in graph and len(visited) < 10000, "invalid wrapper graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            definition = re.match("(" + VALUE + r") =", line)
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            load = re.match("(" + VALUE + r") = load (?:i(\d+)|ptr), ptr (" + VALUE + ")", line)
            if derived and rooted(state, derived[2]):
                require(derived[1] in ptrs, "unresolved wrapper owner pointer")
            if load and owner(state, load[3]):
                require(load[2], "wrapper owner pointer load/escape")
            if load and not present and address(load[3])[0] == "%state":
                require(load[2] == "64" and address(load[3])[1] == shape.discriminator,
                        "empty wrapper reads absent Engine payload")
            provenance.evaluate(line, state, address, predecessor)
            compare = re.match("(" + VALUE + r") = icmp(?: samesign)? (eq|ne) i\d+ ("
                               + VALUE + r"), (-?\d+)", line)
            if compare:
                number = numerical(state, state.values.get(compare[3]))
                if number is not None:
                    state.values[compare[1]] = int(
                        (number == int(compare[4])) == (compare[2] == "eq"))
            # Empty inline asm is the fixture's output observer, not a crypto
            # or cleanup boundary. Never allow an Engine pointer into it.
            observer = re.fullmatch(
                r'call void asm sideeffect "", "r,~\{memory\}"\(ptr nonnull ('
                + VALUE + r')\).*', line)
            if observer:
                require(not rooted(state, observer[1]), "owner escapes through observer")
                invocation = None
            else:
                invocation = syntax.call(line)
            if invocation:
                symbol, args = invocation
                if symbol == "llvm.memcpy.p0.p0.i64":
                    destination, source = syntax.operand(args[0]), syntax.operand(args[1])
                    size = re.fullmatch(r"i64 (\d+)", args[2])
                    require(size, "unknown wrapper copy extent")
                    size = int(size[1])
                    bounded(destination, size)
                    state.transfer(address(destination), address(source), size)
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown wrapper lifetime")
                    root, offset = address(syntax.operand(args[-1]))
                    require(root in allocs and offset == 0, "invalid wrapper lifetime root")
                    if symbol == "llvm.lifetime.start.p0":
                        require(not state.overlap((root, 0), allocs[root]),
                                "restart live wrapper owner storage")
                    else:
                        state.end(root)
                        require(all(token in state.done or any(row[3] == token
                                    for row in state.memory) for token in state.born),
                                "last wrapper owner copy lost")
                elif symbol == target:
                    base = operation.removesuffix("_bits")
                    engine_index = 0 if base == "verify" else 1
                    require(len(args) == engine_index + 4, "wrapper Engine arity changed")
                    name = syntax.operand(args[engine_index])
                    token = state.complete(address(name), shape.engine)
                    require(present and token == 0, "empty/wrong wrapper Engine dispatch")
                    # No second argument can alias the consumed engine.
                    for arg in args[:engine_index] + args[engine_index + 1:]:
                        if arg.startswith("ptr "):
                            require(not rooted(state, syntax.operand(arg)),
                                    "wrapper Engine aliased argument")
                    input_pointer = syntax.operand(args[engine_index + 1])
                    if operation.endswith("_bits"):
                        require(input_pointer == "%input", "wrapper final bits pointer changed")
                    else:
                        require(state.constants.get((*address(input_pointer), 8)) == 0,
                                "wrapper byte finalizer lacks None input")
                    output = "%candidate.0" if base == "verify" else "%output.0"
                    length = "%candidate.1" if base == "verify" else "%output.1"
                    require(syntax.operand(args[-2]) == output
                            and re.search(re.escape(length) + "$", args[-1]),
                            "wrapper output/candidate slice changed")
                    state.done.add(token)
                    dispatched = True
                elif syntax.auxiliary(symbol):
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            require(not rooted(state, syntax.operand(arg)),
                                    "wrapper owner passed to auxiliary")
                        require(not any(isinstance(state.values.get(name), tuple)
                                        for name in re.findall(VALUE, arg)),
                                "wrapper scalar owner passed to auxiliary")
                    if "18clear_owned_region" in symbol:
                        require(len(args) == 2 and syntax.operand(args[0]) == "%output.0"
                                and re.search(r"%output\.1$", args[1]),
                                "wrapper rejection clears wrong output")
                        cleared = True
                    # No unknown throwing call may abandon a live Engine.
                    if symbol != "llvm.experimental.noalias.scope.decl":
                        complete(state)
                else:
                    require(False, "unknown wrapper call: " + symbol)
            elif line.startswith("store "):
                store = re.match(r"store (?:i(\d+)|ptr) (.*?), ptr (" + VALUE + "),", line)
                require(store, "unsupported wrapper write")
                size = (int(store[1]) + 7) // 8 if store[1] else 8
                value = state.value(store[2])
                if not store[1]:
                    require(not rooted(state, store[2]), "wrapper owner pointer escape")
                    value = 0 if store[2] == "null" else None
                if isinstance(value, tuple):
                    bounded(store[3], size)
                state.store(address(store[3]), size, value)
            elif not (derived or load or observer):
                references = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(rooted(state, name) for name in references),
                        "unsupported wrapper owner-pointer operation")
                # A scalar piece of the owner may only be copied or compared
                # as the known discriminator, never laundered through arithmetic.
                scalar_refs = [name for name in references
                               if isinstance(state.values.get(name), tuple)]
                require(not scalar_refs or compare, "unsupported wrapper scalar-owner operation")
            if re.search(r"\binvoke\b", line):
                edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                     + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed wrapper invoke")
                complete(state)
                queue.extend((edge, label, state.clone(), cleared, trail) for edge in edges.groups())
                terminal = True
                break
            branch = re.fullmatch(r"br i1 ([-\w%.]+), label %" + common.LABEL
                                  + ", label %" + common.LABEL + r"(?:, !.*)?", line)
            jump = re.fullmatch("br label %" + common.LABEL, line)
            if branch or jump:
                if jump:
                    successors = [jump[1]]
                else:
                    value = state.value(branch[1])
                    successors = [branch[2 if value else 3]] if value in (0, 1) else branch.groups()[1:]
                queue.extend((edge, label, state.clone(), cleared, trail) for edge in successors)
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                complete(state)
                require(present or not operation.startswith("secret") or cleared,
                        "empty secret wrapper failed to clear destination")
                exits += 1
                terminal = True
                break
            require(line != "unreachable", "unreviewed wrapper fatal terminal")
        require(terminal, "unterminated wrapper block")
    require(exits and dispatched == present, "missing/spurious wrapper dispatch")
