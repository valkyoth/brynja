"""Consuming finalizer dispatch over emitted owner copies and closure bodies.

This is a bounded LLVM caller check, not a proof that compiler-created copies,
registers, spills or the transitive hash implementation are erased. Hash
finalizers consume their state on both edges; hash destruction is non-panicking.
Those separately reviewed callee contracts and safe-Rust non-aliasing remain
premises. Copies preserve provenance, not additional logical ownership.
"""
import re

import hmac_engine_codegen as codegen
import hmac_engine_update as update
from hmac_engine_codegen import LABEL, require

VALUE = r"%[-\w.]+"
OPERATIONS = ("public", "secret", "verify", "public_bits", "secret_bits", "verify_bits")


def parameters(text):
    """Split LLVM operands without splitting captures/sret attribute arguments."""
    result, start, depth = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            require(depth >= 0, "unbalanced finalizer arguments")
        elif char == "," and not depth:
            result.append(text[start:index].strip())
            start = index + 1
    require(depth == 0, "unbalanced finalizer attributes")
    result.append(text[start:].strip())
    return result


def call(line):
    line = line.split(";", 1)[0]
    match = re.search(r'\b(?:call|invoke)\b.*?@("[^"]+"|[-\w.$]+)\(', line)
    if not match:
        require(not re.search(r"\b(?:call|invoke)\b", line), "indirect finalizer call")
        return None
    start, depth = match.end(), 1
    for end in range(start, len(line)):
        depth += (line[end] == "(") - (line[end] == ")")
        if not depth:
            return match[1].strip('"'), parameters(line[start:end])
    require(False, "unterminated finalizer call")


def operand(text):
    match = re.search("(" + VALUE + r")$", text)
    require(match and text.startswith("ptr "), "unknown finalizer pointer operand")
    return match[1]


def geometry(identity):
    if identity.startswith("sha3_"):
        return 1040, 0, (0, 1040)
    if identity.startswith("general"):
        return 1172, 2, (8, 1180)
    return 1170, 0, (8, 1178)


def type_name(identity):
    if identity.startswith("general"):
        return "HardenedSha512T"
    return "Hardened" + ("Sha3_" + identity[5:] if identity.startswith("sha3_")
                         else "Sha" + identity[3:])


def hash_finalizer(symbol, identity):
    name = type_name(identity)
    family = "3" if identity.startswith("sha3_") else "2"
    # Exact method/type, not an arbitrary symbol containing finalize_secret.
    prefix = (r"_RNvM(?:\w*_)?Nt(?:Nt)?Cs\w+_16brynja_hash_sha" + family +
              r"(?:7general8hardened|8hardened(?:5fixed)?)NtB\w+_"
              + str(len(name)) + name)
    legacy = (r"_ZN16brynja_hash_sha" + family +
              r"(?:7general8hardened|8hardened(?:5fixed)?)"
              + str(len(name)) + name)
    return bool(re.fullmatch(
        "(?:" + prefix + "|" + legacy + r")(?:15finalize_secret|20finalize_bits_secret)"
        r"(?:17h[0-9a-f]+E)?", symbol))


def finish_closure(symbol):
    return ("15brynja_mac_hmac6engine" in symbol and "6finish" in symbol
            and ("_RNC" == symbol[:4] or "closure" in symbol))


def adapter_update(symbol):
    return bool(re.fullmatch(
        r"(?:_RN\w+15brynja_mac_hmac\w+4Hash6update(?:B\w+_)?|"
        r"_ZN[^\s]+brynja_mac_hmac[^\s]+6update17h[0-9a-f]+E|"
        r"_RN\w+16brynja_hash_sha27general8hardened\w+15HardenedSha512T6update)",
        symbol))


def auxiliary(symbol):
    """Exact non-owner callee classes; arguments must not overlap owner state."""
    return bool(re.fullmatch(
        r"(?:llvm\.(?:umin\.i64|experimental\.noalias\.scope\.decl)|"
        r"_RNvMNtCs\w+_16brynja_hash_core10bit_stringNtB\w+_9BitString3new|"
        r"_ZN16brynja_hash_core10bit_string9BitString3new17h[0-9a-f]+E|"
        r"_RN\w+11brynja_core13secret_memory(?:18clear_owned_region|"
        r"18copy_secret_region|33accumulate_secret_byte_difference|25secret_difference_is_zero)|"
        r"_RN\w+11brynja_core13secret_memory\w+26SecretRegionInitialization"
        r"(?:5begin|5write|6finish)|"
        r"_RN\w+11brynja_core13secret_memory\w+(?:17OwnedSecretRegion|"
        r"26SecretRegionInitialization)\w+4Drop4drop|"
        r"_ZN[^\s]+brynja_core[^\s]+(?:clear_owned_region|copy_secret_region|"
        r"accumulate_secret_byte_difference|secret_difference_is_zero|"
        r"SecretRegionInitialization|OwnedSecretRegion)"
        r"[^\s]*17h[0-9a-f]+E)", symbol))


def pointers(body, roots):
    result = {name: (name, 0) for name in roots}
    for line in body.splitlines():
        match = re.match(r"\s*(" + VALUE + r") = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ("
                         + VALUE + r"), i64 (-?\d+)", line)
        if match:
            name, base, offset = match.groups()
            root, previous = result.get(base, (base, 0))
            require(name not in result, "duplicate finalizer pointer")
            result[name] = root, previous + int(offset)
    return result


def check(body, identity, definitions, aliases, panic="unwind", seed=None, depth=0):
    require(identity in codegen.IDENTITIES and panic in ("abort", "unwind"),
            "unknown finalizer identity/panic profile")
    require(depth <= 1, "recursive finalizer closure")
    width, core_offset, fields = geometry(identity)
    if seed is None:
        seed = tuple(("%self", offset, token) for token, offset in enumerate(fields))
    tokens = frozenset(row[2] for row in seed)
    allocs = dict((name, int(size)) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body))
    ptrs = pointers(body, (*allocs, *(row[0] for row in seed)))
    graph = codegen.blocks(body)
    queue = [(next(iter(graph)), frozenset(seed), frozenset(), frozenset())]
    visited, exits, consumed = set(), set(), set()
    trails = {queue[0]: ()}

    def address(name):
        return ptrs.get(name, (name, 0))

    def intersect(memory, name, size=1):
        root, offset = address(name)
        return {row for row in memory if row[0] == root
                and offset < row[1] + width and row[1] < offset + size}

    def selected(memory, name, offset=0):
        root, position = address(name)
        found = {token for base, start, token in memory
                 if base == root and start + offset == position}
        require(len(found) == 1, "missing/ambiguous finalizer owner provenance: " + name)
        return next(iter(found))

    while queue:
        label, memory, done, facts = queue.pop()
        state = label, memory, done, facts
        if state in visited:
            continue
        visited.add(state)
        trail = (*trails[state], label)
        require(label in graph and len(visited) < 20000, "invalid finalizer graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            definition = re.match("(" + VALUE + r") =", line)
            if definition:
                # SSA values outside a loop retain branch facts. A value
                # redefined on a loop iteration must not retain its old value.
                facts = frozenset(item for item in facts if item[0] != definition[1])
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            if derived and any(row[0] == address(derived[2])[0] for row in memory):
                require(derived[1] in ptrs, "unresolved owner pointer arithmetic")
            if re.search(r"= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)", line):
                referenced = re.findall(VALUE, line)[1:]
                require(not any(address(name)[0] == row[0] for row in memory for name in referenced),
                        "unsupported owner pointer alias")
            invocation = call(line)
            if invocation:
                symbol, args = invocation
                if symbol == "llvm.memcpy.p0.p0.i64":
                    dest, source = operand(args[0]), operand(args[1])
                    extent = re.fullmatch(r"i64 (\d+)", args[2])
                    require(extent, "variable finalizer copy extent")
                    size = int(extent[1])
                    src_root, src_offset = address(source)
                    dst_root, dst_offset = address(dest)
                    rows = intersect(memory, source, size)
                    require(not intersect(memory, dest, size), "overwrite finalizer owner")
                    additions = set()
                    for base, start, token in rows:
                        require(src_offset <= start and start + width <= src_offset + size,
                                "partial finalizer owner copy")
                        require(token not in done, "copy after finalizer consumption")
                        additions.add((dst_root, dst_offset + start - src_offset, token))
                    if additions:
                        require(dst_root in allocs and dst_offset >= 0
                                and dst_offset + size <= allocs[dst_root],
                                "owner copy escapes allocation")
                    memory = memory | additions
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown finalizer lifetime")
                    name = operand(args[-1])
                    root, offset = address(name)
                    require(offset == 0, "interior finalizer lifetime")
                    rows = {row for row in memory if row[0] == root}
                    if symbol == "llvm.lifetime.start.p0":
                        require(not rows, "owner lifetime restart")
                    else:
                        memory = memory - rows
                        require(all(token in done or any(row[2] == token for row in memory)
                                    for _, _, token in rows), "last owner lifetime ends unconsumed")
                elif codegen.owner_drop(symbol, identity) or hash_finalizer(symbol, identity):
                    is_drop = codegen.owner_drop(symbol, identity)
                    token = selected(memory, operand(args[0 if is_drop else 1]),
                                     core_offset if is_drop else 0)
                    require(token not in done, "duplicate finalizer consumption")
                    done = done | {token}
                    consumed.add(token)
                elif finish_closure(symbol):
                    require(depth == 0, "nested HMAC finalizer closure")
                    name = operand(args[0])
                    root, offset = address(name)
                    rows = [row for row in memory if row[0] == root]
                    require(len(rows) == 1 and rows[0][2] == 1 and done == {0},
                            "wrong/missing outer closure owner")
                    arguments, closure = codegen.resolve(symbol, definitions, aliases)
                    formals = parameters(arguments)
                    require(len(formals) == 3 and formals[1].startswith("ptr ")
                            and formals[2].startswith("i64 "), "unexpected finalizer closure signature")
                    formal = operand(formals[0])
                    closure_seed = ((formal, rows[0][1] - offset, rows[0][2]),)
                    check(closure, identity, definitions, aliases, panic, closure_seed, depth + 1)
                    done = done | {rows[0][2]}
                    consumed.add(rows[0][2])
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    require(depth == 0, "unexpected finalizer closure drop helper")
                    name = operand(args[0])
                    require({selected(memory, name, -field) for field in fields} == tokens
                            and not done, "wrong full-engine cleanup helper")
                    update.helper(symbol, identity, definitions, aliases)
                    done = tokens
                    consumed.update(tokens)
                elif adapter_update(symbol):
                    token = selected(memory, operand(args[0]))
                    require(token == 1 and token not in done, "wrong/late outer update")
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "outer update missing unwind cleanup")
                elif symbol == "llvm.memset.p0.i64":
                    require(not intersect(memory, operand(args[0]), int(args[2].split()[-1])),
                            "overwrite owner with memset")
                else:
                    require(auxiliary(symbol) or codegen.panic_cleanup(symbol),
                            "unknown finalizer call: " + symbol)
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            require(not any(row[0] == address(operand(arg))[0] for row in memory),
                                    "owner storage passed to auxiliary")
            elif re.search(r"\b(store|atomicrmw|cmpxchg)\b", line):
                store = re.match(r"store (?:ptr|i(\d+)) .*?, ptr (" + VALUE + ")", line)
                require(store, "unsupported finalizer write")
                size = (int(store[1]) + 7) // 8 if store[1] else 8
                require(not intersect(memory, store[2], size), "write into finalizer owner")
                if line.startswith("store ptr "):
                    value = re.match("store ptr (" + VALUE + "),", line)
                    require(not value or not intersect(memory, value[1]),
                            "owner pointer stored outside tracked copy")
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing finalizer invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed finalizer invoke edges")
                children = [(edge, memory, done, facts) for edge in edges.groups()]
                for child in children:
                    trails.setdefault(child, trail)
                queue += children
                terminal = True
                break
            if line.startswith(("br ", "switch ")):
                text = line if line.startswith("br ") else "\n".join(lines[index:]).split("]", 1)[0]
                edges = re.findall("label %" + LABEL, text)
                require(edges, "unparsed finalizer branch")
                condition = re.fullmatch("br i1 (" + VALUE + "), label %" + LABEL
                                         + ", label %" + LABEL
                                         + r"(?:, ![-\w.]+ !\d+)*", line)
                if condition:
                    known = dict(facts).get(condition[1])
                    children = [(edge, memory, done, facts | {(condition[1], value)})
                                for edge, value in zip(edges, (True, False))
                                if known is None or known == value]
                else:
                    require(not line.startswith("br i1"), "unknown finalizer branch condition")
                    children = [(edge, memory, done, facts) for edge in edges]
                for child in children:
                    trails.setdefault(child, trail)
                queue += children
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(done == tokens, "finalizer exits with undispatched hash owner; "
                        + repr((done, trail)))
                exits.add(label)
                terminal = True
                break
            if line == "unreachable":
                require(codegen.fatal_cleanup_block(lines), "unknown finalizer terminal")
                terminal = True
                break
        require(terminal, "unknown finalizer terminator")
    require(exits and consumed == tokens, "vacuous finalizer owner graph")
