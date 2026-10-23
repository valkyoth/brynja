"""Portable legacy constructor initialization, cleanup and returned ownership.

Tracks the actual inline initializations and all CFG exits. Callee destruction
and safe-Rust aliasing are premises; emitted copies are provenance, not erasure.
"""
import re
import legacy_hmac_engine_codegen as codegen
import legacy_hmac_engine_final as final

codegen.load("hmac_engine_final")
shared = codegen.load("hmac_constructor_state")
VALUE = r"%[-\w.]+"
require = codegen.require


class State(shared.State):
    def __init__(self):
        super().__init__()
        self.initializing = {}
        self.returned = set()

    def key(self):
        return super().key(), tuple(sorted((name, frozenset(parts)) for name, parts in self.initializing.items())), frozenset(self.returned)


def mask(symbol):
    return bool(re.fullmatch(r"_RNvNtCs\w+_18brynja_legacy_hmac7scratch4mask|"
                             r"_ZN18brynja_legacy_hmac7scratch4mask17h[0-9a-f]+E", symbol))


def check(body, identity, panic):
    api = final.interpreter(identity)
    width, _, fields = final.geometry(identity)
    allocs = {name: int(size) for name, size in re.findall("(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    roles = {}
    for token, role in enumerate(("state", "inner", "outer")):
        names = [name for name, size in allocs.items() if size == width and re.fullmatch("%" + role + r"(?:\.[-\w]+)*", name)]
        require(len(names) == 1, "legacy constructor owner allocation missing: " + role)
        roles[names[0]] = token
    ptrs = api.pointers(body, (*allocs, "%_0"))
    graph = codegen.flow.blocks(body)
    queue = [(next(iter(graph)), None, State())]
    visited, successes, failures, births, normalized = set(), 0, 0, set(), set()

    def address(name):
        return ptrs.get(name, (name, 0))

    def extent(root, offset, size):
        limit = codegen.layout(identity)[0] + 8 if root == "%_0" else allocs.get(root, 0)
        require(0 <= offset and offset + size <= limit, "constructor owner storage extent changed")

    def initialize(state, name, size, public):
        root, offset = address(name)
        if root not in state.initializing:
            return False
        require(public and 0 <= offset and offset + size <= width, "non-public/oversized constructor initialization")
        state.initializing[root].update(range(offset, offset + size))
        if len(state.initializing[root]) == width:
            state.birth((root, 0), width, roles[root])
            del state.initializing[root]
            births.add(roles[root])
        return True

    while queue:
        label, predecessor, state = queue.pop()
        key = label, predecessor, state.key()
        if key in visited:
            continue
        visited.add(key)
        require(label in graph and len(visited) < 30000, "invalid constructor graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            load = re.search(r"\bload .*?, ptr (" + VALUE + ")", line)
            if load:
                require(address(load[1])[0] not in state.initializing,
                        "read before complete constructor initialization")
            shared.evaluate(line, state, address, predecessor)
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            if derived and (address(derived[2])[0] in roles or state.overlap(address(derived[2]), width)):
                require(derived[1] in ptrs, "unresolved constructor owner arithmetic")
            if re.search(r"= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)", line):
                for name in re.findall(VALUE, line)[1:]:
                    require(address(name)[0] not in roles and not state.overlap(address(name), width), "untracked constructor alias")
            invocation = api.call(line)
            if invocation:
                symbol, args = invocation
                if symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"), "unknown constructor lifetime")
                    root, offset = address(api.operand(args[-1]))
                    require(offset == 0, "interior constructor lifetime")
                    if symbol == "llvm.lifetime.start.p0":
                        if root in roles:
                            require(roles[root] not in state.born and root not in state.initializing, "duplicate constructor lifetime")
                            state.initializing[root] = set()
                    else:
                        require(root not in state.initializing, "partially initialized owner lifetime ended")
                        remaining = {row for row in state.memory if row[0] != root}
                        require(all(row[3] in state.done or any(other[3] == row[3] for other in remaining)
                                    for row in state.memory if row[0] == root), "last constructor owner lifetime ended live")
                        state.end(root)
                elif symbol == "llvm.memset.p0.i64":
                    name, size = api.operand(args[0]), int(args[2].split()[-1])
                    if not initialize(state, name, size, bool(re.fullmatch(r"i8 -?\d+", args[1]))):
                        require(not state.overlap(address(name), size), "memset overwrites initialized owner")
                elif symbol == "llvm.memcpy.p0.p0.i64":
                    dest, source = api.operand(args[0]), api.operand(args[1])
                    size = int(args[2].split()[-1])
                    require(address(source)[0] not in state.initializing and address(dest)[0] not in state.initializing,
                            "copy of partly initialized owner")
                    rows = state.overlap(address(source), size)
                    if rows:
                        extent(*address(dest), size)
                        token = state.complete(address(source), width)
                        require(size == width, "partial/oversized constructor owner transfer")
                        if address(dest)[0] == "%_0":
                            require(token in (1, 2) and address(dest)[1] == fields[token - 1] + 8,
                                    "wrong returned constructor owner/field")
                            # Keep returned bytes in the provenance map so later
                            # stores/copies cannot overwrite exported owners.
                            state.transfer(address(dest), address(source), size)
                            state.returned.add(token)
                            state.done.add(token)
                        else:
                            state.transfer(address(dest), address(source), size)
                    else:
                        require(not state.overlap(address(dest), size), "unrelated copy overwrites owner")
                elif codegen.owner_drop(symbol, identity) or final.hash_finalizer(symbol, identity):
                    dropping = codegen.owner_drop(symbol, identity)
                    token = state.complete(address(api.operand(args[0 if dropping else 1])), width)
                    if not dropping:
                        require(token == 0, "constructor finalized wrong normalization owner")
                        normalized.add(token)
                    state.done.add(token)
                elif codegen.adapter_update(symbol, identity):
                    name = api.operand(args[0])
                    require(address(name)[0] not in state.initializing, "update before complete initialization")
                    state.complete(address(name), width)
                    require(panic == "abort" or re.search(r"\binvoke\b", line), "constructor update missing unwind cleanup")
                else:
                    require(api.auxiliary(symbol) or mask(symbol) or codegen.flow.panic_cleanup(symbol),
                            "unknown legacy constructor call: " + symbol)
                    for argument in args:
                        if argument.startswith("ptr ") and re.search(VALUE + "$", argument):
                            name = api.operand(argument)
                            require(address(name)[0] not in state.initializing and not state.overlap(address(name), width),
                                    "owner passed to constructor auxiliary")
            elif re.search(r"\b(store|atomicrmw|cmpxchg)\b", line):
                store = re.match(r"store (i(\d+)|ptr|<(\d+) x i(\d+)>) (.*?), ptr (" + VALUE + ")", line)
                require(store, "unparsed constructor write")
                kind, bits, count, element, value, destination = store.groups()
                size = int(count) * int(element) // 8 if count else (int(bits) + 7) // 8 if bits else 8
                public = bool(re.fullmatch(r"-?\d+|zeroinitializer|<i\d+ -?\d+(?:, i\d+ -?\d+)*>", value))
                if not initialize(state, destination, size, public):
                    if kind == "ptr" and re.fullmatch(VALUE, value):
                        require(not state.overlap(address(value), width) and address(value)[0] not in roles,
                                "constructor owner pointer escaped")
                    state.store(address(destination), size, state.value(value))
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing constructor unwind edge")
                edges = re.fullmatch("to label %" + codegen.LABEL + " unwind label %" + codegen.LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed constructor invoke")
                queue += [(edge, label, state.clone()) for edge in edges.groups()]
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + codegen.LABEL, line)
                require(len(edges) in (1, 2), "unparsed constructor branch")
                condition = re.match("br i1 (" + VALUE + "),", line)
                for edge, truth in zip(edges, (1, 0)):
                    child = state.clone()
                    if condition:
                        value = state.value(condition[1])
                        if isinstance(value, int) and value != truth:
                            continue
                        child.assign(condition[1], truth)
                    queue.append((edge, label, child))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(not state.initializing and state.born <= state.done, "constructor exits with live/partial owner")
                if line.startswith("ret "):
                    tag = state.constants.get(("%_0", 0, 1))
                    require((tag == 0 and state.returned == {1, 2}) or (tag == 1 and not state.returned),
                            "constructor result/returned owner mismatch")
                    successes += tag == 0
                    failures += tag == 1
                else:
                    require(not state.returned, "constructor unwind after ownership export")
                terminal = True
                break
            if line == "unreachable":
                require(codegen.flow.fatal_cleanup_block(lines), "unknown constructor terminal")
                terminal = True
                break
        require(terminal, "unparsed constructor terminator")
    require(successes and failures and births == {0, 1, 2} and normalized == {0}, "vacuous constructor ownership graph")
