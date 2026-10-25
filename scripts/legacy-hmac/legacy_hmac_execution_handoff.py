"""Byte provenance from optional SHA-1 Engine to consuming finalizers.

Track both complete streams, including split LLVM moves. Safe Rust non-aliasing
and the separately checked consuming hash/core contracts remain premises.
Compiler-created copies, registers, spills and fatal paths are not erased by
this analysis. Secret output clearing is checked only on the empty-owner path;
the typed output owner's existing contract applies after successful dispatch.
"""
import re

import legacy_hmac_engine_codegen as shared
import legacy_hmac_execution_final as cores
import legacy_hmac_execution_state as model

provenance = shared.load("hmac_constructor_state")
syntax, flow, require = model.final, shared.flow, shared.require
VALUE = model.SSA
WIDTH, FIELDS = 448, (8, 456)


def error_range_assumption(graph, label, index, args, target):
    """Only the compiler's eight-variant Error range after Engine::verify.

    This is not authority to assume a comparison matched or a stream cleared.
    The caller separately requires both stream owners already consumed.
    """
    rows = graph[label]
    if index != 1 or len(args) != 1:
        return False
    compare = re.fullmatch(rf'({VALUE}) = icmp ult i8 ({VALUE}), 8', rows[0])
    if not compare or args != ['i1 ' + compare[1]]:
        return False
    for parent, lines in graph.items():
        for n, line in enumerate(lines):
            call = syntax.call(line)
            result = re.match(rf'({VALUE}) = (?:call|invoke) ', line)
            if not call or call[0] != target or not result:
                continue
            flag = [m[1] for row in lines[n + 1:]
                    if (m := re.fullmatch(rf'({VALUE}) = extractvalue \{{ i1, i8 \}} '
                                          + re.escape(result[1]) + ', 0', row))]
            payload = f'{compare[2]} = extractvalue {{ i1, i8 }} {result[1]}, 1'
            if len(flag) == 1 and payload in lines[n + 1:] and re.fullmatch(
                    'br i1 ' + re.escape(flag[0]) + ', label %' + re.escape(label)
                    + r', label %[-\w.$]+', lines[-1]):
                return True
    return False


class State(provenance.State):
    def __init__(self):
        super().__init__()
        self.references = {}
        self.aliases = {}

    def key(self):
        return super().key(), frozenset(self.references.items()), frozenset(self.aliases.items())

    def invalidate_constants(self, address, width=None):
        root, offset = address
        self.constants = {key: value for key, value in self.constants.items()
                          if key[0] != root or (width is not None
                          and not (offset < key[1] + key[2] and key[1] < offset + width))}


def check(body, operation, definitions, aliases, panic, target=None):
    require(operation in ("public", "verify", "secret", "public_bits", "verify_bits"), "unknown handoff")
    base = operation.removesuffix("_bits")
    require((target is None) == (base == "secret"), "wrong handoff target kind")
    allocations = {name: int(size) for name, size in re.findall(
        rf"({VALUE}) = alloca \[(\d+) x i8\],", body)}
    pointers = syntax.pointers(body, (*allocations, "%self", "%_0", "%tail", "%output.0", "%candidate.0"))
    graph = flow.blocks(body)

    def address(name):
        return state.aliases.get(name, pointers.get(name, (name, 0)))

    for niche in (0, 1, 2):
        initial = State()
        if niche != 2:
            for token, field in enumerate(FIELDS):
                initial.birth(("%self", field), WIDTH, token)
        else:
            initial.constants[("%self", model.NICHE, 1)] = 2
        queue = [(next(iter(graph)), None, initial, False)]
        visited, exits, consumed = set(), 0, set()

        def rooted(state, name):
            return any(row[0] == address(name)[0] for row in state.memory)

        def bounded(name, width, *, source=False):
            root, offset = address(name)
            capacity = 912 if source and root == "%self" else allocations.get(root, -1)
            require(0 <= offset <= capacity - width,
                    "handoff move outside allocation")

        def complete(state):
            require(state.done == state.born, "handoff exits with live stream")

        def separate_arguments(args, owner_index):
            for index, arg in enumerate(args):
                if index != owner_index and arg.startswith("ptr "):
                    name = syntax.operand(arg)
                    require(not rooted(state, name) and name not in state.aliases,
                            "aliased stream operation arguments")

        while queue:
            label, predecessor, state, cleared = queue.pop()
            key = label, predecessor, state.key(), cleared
            if key in visited:
                continue
            visited.add(key)
            require(label in graph and len(visited) < 20000, "invalid handoff graph")
            lines, terminal = graph[label], False
            for index, line in enumerate(lines):
                derived = re.match(rf"({VALUE}) = getelementptr.*?, ptr ({VALUE})", line)
                load = re.match(rf"({VALUE}) = load (?:i(\d+)|ptr), ptr ({VALUE})", line)
                if derived and derived[2] in state.aliases:
                    offset = re.fullmatch(rf"{VALUE} = getelementptr inbounds(?: nuw)? i8, ptr {VALUE}, i64 (\d+)", line)
                    require(offset, "unknown captured-pointer arithmetic")
                    root, previous = address(derived[2])
                    state.aliases[derived[1]] = (root, previous + int(offset[1]))
                if derived and rooted(state, derived[2]):
                    require(derived[1] in pointers or derived[1] in state.aliases, "unknown handoff pointer arithmetic")
                if load and load[3] in state.aliases:
                    require(load[2] == "64" and address(load[3])[1] == 0
                            and any(row[0] == address(load[3])[0] and row[3] not in state.done
                                    for row in state.memory)
                            and not state.overlap(address(load[3]), 8),
                            "captured prefix pointer reads dead storage/stream bytes")
                if load and state.overlap(address(load[3]), 1):
                    require(load[2], "owner pointer load/escape")
                if load and niche == 2 and address(load[3])[0] == "%self":
                    require(load[2] == "8" and address(load[3])[1] == model.NICHE,
                            "empty handoff reads absent payload")
                provenance.evaluate(line, state, address, predecessor)
                if load and not load[2] and address(load[3]) in state.references:
                    state.aliases[load[1]] = state.references[address(load[3])]
                compare = re.match(rf"({VALUE}) = icmp(?: samesign)? (eq|ne) i\d+ ({VALUE}), (-?\d+)", line)
                if compare:
                    value = state.value(compare[3])
                    if value == (1, 441, 1):
                        require(1 not in state.done, "late retained discriminator read")
                        value = niche
                    if isinstance(value, int):
                        state.assign(compare[1], int((value == int(compare[4])) == (compare[2] == "eq")))
                invocation = syntax.call(line)
                if invocation:
                    symbol, args = invocation
                    if symbol == "llvm.memcpy.p0.p0.i64":
                        destination, source = syntax.operand(args[0]), syntax.operand(args[1])
                        extent = re.fullmatch(r"i64 (\d+)", args[2])
                        require(extent and args[3] == "i1 false", "unknown handoff copy")
                        width = int(extent[1])
                        require(niche != 2 or address(source)[0] != "%self", "copy of absent retained payload")
                        state.invalidate_constants(address(destination), width)
                        if state.overlap(address(source), width) or state.overlap(address(destination), width):
                            bounded(destination, width)
                            bounded(source, width, source=True)
                            state.transfer(address(destination), address(source), width)
                        src_root, src_offset = address(source)
                        dst_root, dst_offset = address(destination)
                        require(not any(root == dst_root and dst_offset < offset + 8 and offset < dst_offset + width
                                        for root, offset in state.references), "captured pointer overwritten by copy")
                        for (root, offset), reference in list(state.references.items()):
                            if root == src_root and src_offset < offset + 8 and offset < src_offset + width:
                                require(src_offset <= offset and offset + 8 <= src_offset + width,
                                        "partial captured-pointer copy")
                                bounded(destination, width)
                                bounded(source, width, source=True)
                                state.references[dst_root, dst_offset + offset - src_offset] = reference
                    elif symbol == "llvm.memset.p0.i64":
                        extent = re.fullmatch(r"i64 (\d+)", args[2])
                        require(extent and not state.overlap(address(syntax.operand(args[0])), int(extent[1])),
                                "memset overwrites stream")
                        root, offset = address(syntax.operand(args[0]))
                        state.invalidate_constants((root, offset), int(extent[1]))
                        require(not any(root == other and offset < start + 8 and start < offset + int(extent[1])
                                        for other, start in state.references), "memset overwrites captured pointer")
                    elif symbol.startswith("llvm.lifetime."):
                        require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"), "unknown handoff lifetime")
                        root, offset = address(syntax.operand(args[-1]))
                        require(root in allocations and offset == 0, "invalid handoff lifetime root")
                        if symbol == "llvm.lifetime.start.p0":
                            require(not state.overlap((root, 0), allocations[root]), "restarted handoff owner")
                        else:
                            state.end(root)
                            state.references = {key: value for key, value in state.references.items() if key[0] != root}
                            require(all(token in state.done or any(row[3] == token for row in state.memory)
                                        for token in state.born), "last stream copy lost")
                    elif symbol == "llvm.assume":
                        require(base == "verify" and state.done == state.born == {0, 1}
                                and error_range_assumption(graph, label, index, args, target),
                                "unbound verification Error range assumption")
                    elif symbol == target:
                        position = 0 if base == "verify" else 1
                        require(len(args) == position + 4, "changed Engine finalizer arity")
                        root, offset = address(syntax.operand(args[position]))
                        tokens = {state.complete((root, offset + field), WIDTH) for field in FIELDS}
                        require(niche != 2 and tokens == {0, 1} and not state.done, "wrong Engine handoff owners")
                        for arg in args[:position] + args[position + 1:]:
                            if arg.startswith("ptr "):
                                require(not rooted(state, syntax.operand(arg)), "aliased finalizer arguments")
                        tail = syntax.operand(args[position + 1])
                        if operation.endswith("_bits"):
                            require(tail == "%tail", "changed bit-tail forwarding")
                        else:
                            require(state.constants.get((*address(tail), 8)) == 0, "byte finalizer missing None tail")
                        output, length = ("%candidate.0", "%candidate.1") if base == "verify" else ("%output.0", "%output.1")
                        require(syntax.operand(args[-2]) == output and re.search(re.escape(length) + "$", args[-1]),
                                "changed output/candidate forwarding")
                        state.done.update(tokens)
                        consumed.update(tokens)
                    elif shared.owner_drop(symbol, "sha1") or cores.stream_finalizer(symbol, "sha1"):
                        dropping = shared.owner_drop(symbol, "sha1")
                        require(len(args) == (1 if dropping else 5 if "20finalize_bits_secret" in symbol else 4),
                                "changed stream consumption arity")
                        separate_arguments(args, 0 if dropping else 1)
                        root, offset = address(syntax.operand(args[0 if dropping else 1]))
                        token = state.complete((root, offset - 8 if dropping else offset), WIDTH)
                        state.done.add(token)
                        consumed.add(token)
                    elif model.stream_update(symbol):
                        require(len(args) == 3, "changed outer update arity")
                        separate_arguments(args, 0)
                        require(state.complete(address(syntax.operand(args[0])), WIDTH) == 1,
                                "wrong outer update stream")
                        require(panic == "abort" or "invoke " in line, "outer update lacks unwind edge")
                    elif model.helper(symbol):
                        require(len(args) == 1, "changed Engine cleanup arity")
                        root, offset = address(syntax.operand(args[0]))
                        tokens = {state.complete((root, offset + field), WIDTH) for field in FIELDS}
                        require(tokens == {0, 1} and not state.done, "wrong Engine cleanup handoff")
                        cores.interpreter(panic).update.helper(symbol, "sha1", definitions, aliases)
                        state.done.update(tokens)
                        consumed.update(tokens)
                    else:
                        require(syntax.auxiliary(symbol) or flow.panic_cleanup(symbol), "unknown handoff call: " + symbol)
                        for arg in args:
                            if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                                require(not rooted(state, syntax.operand(arg)) and syntax.operand(arg) not in state.aliases,
                                        "owner/captured pointer passed to auxiliary")
                                state.invalidate_constants(address(syntax.operand(arg)))
                        if niche == 2 and "18clear_owned_region" in symbol:
                            require(len(args) == 2 and syntax.operand(args[0]) == "%output.0"
                                    and re.search(r"%output\.1$", args[1]), "empty secret clears wrong destination")
                            cleared = True
                elif line.startswith("store "):
                    store = re.match(rf"store (?:i(\d+)|ptr) (.*?), ptr ({VALUE}),", line)
                    require(store, "unknown handoff store")
                    width = (int(store[1]) + 7) // 8 if store[1] else 8
                    value = state.value(store[2])
                    root, offset = address(store[3])
                    require(not any(root == other and offset < start + 8 and start < offset + width
                                    for other, start in state.references), "captured pointer overwritten by store")
                    if not store[1]:
                        if rooted(state, store[2]):
                            # An inlined closure captures the Engine prefix
                            # solely for its public tag width. Follow its private
                            # slot/copies/loads, never admit a stream-byte pointer.
                            source = address(store[2])
                            require(source[1] == 0 and not state.overlap(source, 8), "handoff owner pointer escaped")
                            bounded(store[3], 8)
                            state.references[address(store[3])] = source
                        value = 0 if store[2] == "null" else None
                    if isinstance(value, tuple):
                        bounded(store[3], width)
                    state.store(address(store[3]), width, value)
                elif not (derived or load):
                    definition = re.match(rf"({VALUE}) =", line)
                    refs = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                    require(not any(rooted(state, name) for name in refs), "untracked handoff owner operation")
                    require(compare or not any(isinstance(state.values.get(name), tuple) for name in refs),
                            "untracked scalar stream operation")
                if "invoke " in line:
                    edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                         + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                    require(edges, "unknown handoff unwind edges")
                    queue.extend((edge, label, state.clone(), cleared) for edge in edges.groups())
                    terminal = True
                    break
                branch = re.fullmatch(rf"br i1 ({VALUE}), label %" + flow.LABEL + ", label %" + flow.LABEL, line)
                jump = re.fullmatch("br label %" + flow.LABEL, line)
                if branch or jump:
                    if jump:
                        successors = [jump[1]]
                    else:
                        value = state.value(branch[1])
                        successors = [branch[2 if value else 3]] if value in (0, 1) else branch.groups()[1:]
                    for edge in successors:
                        child = state.clone()
                        if branch:
                            child.assign(branch[1], int(edge == branch[2]))
                        queue.append((edge, label, child, cleared))
                    terminal = True
                    break
                if line.startswith(("ret ", "resume ")):
                    complete(state)
                    require(niche != 2 or base != "secret" or cleared, "empty secret destination not cleared")
                    exits += 1
                    terminal = True
                    break
                if line == "unreachable":
                    require(flow.fatal_cleanup_block(lines), "unknown fatal handoff path")
                    terminal = True
                    break
            require(terminal, "unterminated handoff block")
        require(exits and consumed == ({0, 1} if niche != 2 else set()), "vacuous handoff check")


def forwarding(body, operation, target, *, leaf=False):
    """The real downstream consumer must dispatch its own state on every exit."""
    graph = flow.blocks(body)
    pointers = syntax.pointers(body, re.findall(rf"({VALUE}) = alloca", body))
    owner = "%self" if leaf else "%state"
    queue, seen, exits = [(next(iter(graph)), False, frozenset())], set(), 0
    while queue:
        label, dispatched, nulls = queue.pop()
        if (label, dispatched, nulls) in seen:
            continue
        seen.add((label, dispatched, nulls))
        require(label in graph and len(seen) < 1000, "invalid finalizer forwarding graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            # Only the known typed implementation edge is an ownership transfer.
            match = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
            if match and match[1].strip('"') == target:
                require(not dispatched, "repeated finalizer forwarding")
                _, args = syntax.call(line)
                base = operation.removesuffix("_bits")
                position = 0 if base == "verify" else 1
                require(len(args) == position + 3 + int(leaf or operation.endswith("_bits")), "changed forwarding arity")
                require(syntax.operand(args[position]) == owner, "wrong forwarded owner")
                require(all(owner not in re.findall(VALUE, arg) for index, arg in enumerate(args)
                            if index != position), "forwarded owner aliases another argument")
                if operation.endswith("_bits"):
                    require(syntax.operand(args[position + 1]) == ("%tail" if leaf else "%input"), "wrong forwarded bit tail")
                elif leaf:
                    tail = syntax.operand(args[position + 1])
                    require(pointers.get(tail, (tail, 0)) in nulls, "secret byte tail is not None")
                output, length = ("%candidate.0", "%candidate.1") if base == "verify" else ("%output.0", "%output.1")
                require(syntax.operand(args[-2]) == output and re.search(re.escape(length) + "$", args[-1]),
                        "wrong forwarded output/candidate")
                dispatched = True
            else:
                require(owner not in re.findall(VALUE, line), "forwarded owner used outside dispatch")
            store = re.match(rf"store (?:ptr|i\d+) (.*?), ptr ({VALUE}),", line)
            if store:
                root, offset = pointers.get(store[2], (store[2], 0))
                # Conservatively invalidate this allocation's prior None fact.
                nulls = frozenset(item for item in nulls if item[0] != root)
                if line.startswith("store ptr null,"):
                    nulls = nulls | {(root, offset)}
            if match and match[1].strip('"') != target:
                symbol, args = syntax.call(line)
                if symbol.startswith("llvm.lifetime."):
                    root, _ = pointers.get(syntax.operand(args[-1]), (syntax.operand(args[-1]), 0))
                    nulls = frozenset(item for item in nulls if item[0] != root)
                else:
                    # An opaque call cannot preserve a pre-dispatch None fact.
                    nulls = frozenset()
            if "invoke " in line:
                edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges and dispatched, "forwarding unwinds before ownership transfer")
                queue.extend((edge, dispatched, nulls) for edge in edges.groups())
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + flow.LABEL, line)
                require(edges, "unknown forwarding branch")
                queue.extend((edge, dispatched, nulls) for edge in edges)
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(dispatched, "forwarding exits without consumption")
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(dispatched and flow.fatal_cleanup_block(lines), "unknown forwarding fatal path")
                terminal = True
                break
        require(terminal, "unterminated forwarding graph")
    require(exits, "vacuous finalizer forwarding")


def validate(llvm, panic, fixture=None):
    _, definitions, aliases = cores.bodies(llvm)
    for operation, method in (("public", "finalize_tag"), ("public_bits", "finalize_bits_tag"),
                              ("verify", "verify"), ("verify_bits", "verify_bits"), ("secret", "secret")):
        _, (_, body) = cores.method(definitions, aliases, method)
        targets = [invocation[0] for line in body.splitlines()
                   if (invocation := syntax.call(line)) and "6engine" in invocation[0]
                   and not model.helper(invocation[0])]
        require(len(targets) == (0 if operation == "secret" else 1), "ambiguous handoff core")
        check(body, operation, definitions, aliases, panic, targets[0] if targets else None)
    if fixture is not None:
        probe_defs, probe_aliases = flow.definitions_and_aliases(fixture)
        methods = {"public": "finalize_tag", "public_bits": "finalize_bits_tag",
                   "secret": "finalize_secret", "secret_bits": "finalize_bits_secret",
                   "verify": "verify", "verify_bits": "verify_bits"}
        secret, _ = cores.method(definitions, aliases, "secret")
        for operation, method in methods.items():
            symbol, (_, body) = cores.method(definitions, aliases, method)
            suffix = "36brynja_legacy_hmac_execution_cleanup" + str(len(operation)) + operation
            names = [name for name in (*probe_defs, *probe_aliases) if re.search(suffix + r"(?:17h\w+E)?$", name)]
            require(len(names) == 1, "missing/ambiguous finalizer consumer")
            forwarding(flow.resolve(names[0], probe_defs, probe_aliases)[1], operation, symbol)
            if operation.startswith("secret"):
                forwarding(body, operation, secret, leaf=True)
