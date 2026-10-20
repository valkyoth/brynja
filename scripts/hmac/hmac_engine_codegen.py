"""Bounded cancellation-dispatch checks, not caller-copy erasure proofs."""
import re

LABEL = r'("[^"]+"|[-\w.]+)'


def require(condition, message):
    if not condition:
        raise ValueError("HMAC cancellation dispatch evidence: " + message)


def blocks(body):
    graph = {}
    current = None
    for raw in body.splitlines():
        line = raw.split(";", 1)[0].strip()
        if not line:
            continue
        label = re.fullmatch(LABEL + ":", line)
        if label:
            current = label[1]
            require(current not in graph, "duplicate cancellation block")
            graph[current] = []
        else:
            require(current is not None, "instruction before cancellation entry")
            graph[current].append(line)
    require(graph, "empty cancellation graph")
    return graph

IDENTITIES = ("sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
              "sha3_224", "sha3_256", "sha3_384", "sha3_512", "general129", "general511")
OPERATIONS = ("cancel", "construct", "public", "secret", "verify", "update_cancel")


def emitted(llvm):
    definitions = {}
    for match in re.finditer(r"^define [^\n]*@(\w+)\([^\n]*\{\n(.*?)^\}", llvm, re.M | re.S):
        name, body = match.groups()
        require(name not in definitions, "duplicate engine definition")
        definitions[name] = body
    aliases = {}
    for match in re.finditer(r"^@(\w+) = [^\n]*\balias\b[^\n]*, ptr @(\w+)$", llvm, re.M):
        require(match[1] not in aliases and match[1] not in definitions, "duplicate engine alias")
        aliases[match[1]] = match[2]
    result = {}
    for identity in IDENTITIES:
        for operation in OPERATIONS:
            suffix = ("26brynja_hmac_engine_cleanup" + str(len(identity)) + identity
                      + str(len(operation)) + operation)
            names = [name for name in (*definitions, *aliases)
                     if re.search(suffix + r"(?:17h\w+E)?$", name)]
            require(len(names) == 1, "missing/ambiguous engine probe " + identity + "::" + operation)
            name = names[0]
            seen = set()
            while name in aliases:
                require(name not in seen, "cyclic engine alias")
                seen.add(name)
                name = aliases[name]
            require(name in definitions, "external/unresolved engine alias")
            result[identity, operation] = definitions[name]
    return result


def cancellation(body, identity):
    sha3 = identity.startswith("sha3_")
    size = 2088 if sha3 else 2352
    offsets = {0, 1040} if sha3 else ({10, 1182} if identity.startswith("general") else {8, 1178})
    allocations = re.findall(r"(%[-\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
    require(len(allocations) <= 1, "ambiguous engine owner allocation")
    owner = allocations[0] if allocations else "%state"
    pointers = {owner: 0}
    if allocations:
        copies = [line for line in body.splitlines() if "@llvm.memcpy." in line]
        require(len(copies) == 1 and re.search(
            re.escape(owner) + r", ptr [^\n]*%state, i64 " + str(size) + r", i1 false\)", copies[0]),
            "owner copy identity/extent changed")
    for name, base, offset in re.findall(
            r"(%[-\w.]+) = getelementptr inbounds(?: nuw)? i8, ptr (%[-\w.]+), i64 (\d+)", body):
        require(base in pointers, "unknown cancellation pointer base")
        require(name not in pointers, "duplicate cancellation pointer definition")
        pointers[name] = pointers[base] + int(offset)
    graph = blocks(body)
    queue = [(next(iter(graph)), frozenset(), not allocations)]
    visited = set()
    exits = 0
    while queue:
        label, attempted, initialized = queue.pop()
        if (label, attempted, initialized) in visited:
            continue
        visited.add((label, attempted, initialized))
        require(label in graph, "unknown cancellation edge")
        lines = graph[label]
        terminated = False
        for index, line in enumerate(lines):
            call = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
            if call:
                symbol = call[1].strip('"')
                is_drop = (
                    re.fullmatch(r"_ZN16brynja_hash_sha38hardened5owner29HardenedFips202Owner"
                                 r"\$LT\$_\$GT\$4wipe17h[0-9a-f]+E", symbol) if sha3 else
                    re.fullmatch(r"_ZN94_\$LT\$brynja_hash_sha2\.\.hardened\.\.owner\.\."
                                 r"HardenedSha2Owner\$u20\$as\$u20\$core\.\.ops\.\.drop\.\."
                                 r"Drop\$GT\$4drop17h[0-9a-f]+E", symbol))
                if symbol.startswith("_R"):
                    is_drop = (
                        re.fullmatch(r"_RNvMNtNtCs\w+_16brynja_hash_sha38hardened5owner"
                                     r"INtB\w+_20HardenedFips202OwnerKj[0-9a-f]+_E4wipeB\w+_",
                                     symbol) if sha3 else
                        re.fullmatch(r"_RNvXs_NtNtCs\w+_16brynja_hash_sha28hardened5owner"
                                     r"NtB\w+_17HardenedSha2OwnerNtNtNtCs\w+_4core3ops4drop4Drop4drop",
                                     symbol))
                intrinsic = symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0",
                                       "llvm.memcpy.p0.p0.i64")
                require(is_drop or intrinsic or "panic_in_cleanup" in symbol,
                        "unexpected cancellation call")
                require(not attempted or symbol != "llvm.memcpy.p0.p0.i64",
                        "owner copy after cleanup")
                if symbol == "llvm.memcpy.p0.p0.i64":
                    require(not initialized, "repeated owner initialization")
                    initialized = True
                if is_drop:
                    require(initialized, "cleanup before owner copy")
                    argument = re.search(r"(%[-\w.]+)\)", line)
                    require(argument and argument[1] in pointers, "unknown cleanup pointer")
                    offset = pointers[argument[1]]
                    require(offset in offsets and offset not in attempted, "duplicate/wrong owner cleanup")
                    # Dispatch evidence: core/hash cleanup internals retain their
                    # separately reviewed non-panicking destruction contracts.
                    attempted = attempted | {offset}
            elif re.search(r"\b(call|invoke)\b", line):
                require(False, "indirect/unparsed cancellation call")
            require(not re.search(r"\b(store|atomicrmw|cmpxchg)\b", line),
                    "unexpected cancellation write")
            if " invoke " in " " + line:
                require(index + 1 < len(lines), "missing cancellation invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL,
                                     lines[index + 1])
                require(edges, "unsupported cancellation invoke")
                queue += [(edges[1], attempted, initialized), (edges[2], attempted, initialized)]
                terminated = True
                break
            if line.startswith("br "):
                targets = re.findall("label %" + LABEL, line)
                require(len(targets) in (1, 2), "unsupported cancellation branch")
                queue += [(target, attempted, initialized) for target in targets]
                terminated = True
                break
            if line.startswith(("ret ", "resume ")):
                require(attempted == offsets, "exit without both owner cleanup calls")
                exits += 1
                terminated = True
                break
            if line == "unreachable":
                require(any("panic_in_cleanup" in item for item in lines),
                        "unreviewed cancellation terminal")
                terminated = True
                break
            if "llvm.lifetime.end" in line and owner in line:
                require(attempted == offsets, "owner lifetime ended before cleanup calls")
        require(terminated, "unsupported cancellation terminator")
    require(exits, "vacuous cancellation graph")


def check(llvm):
    functions = emitted(llvm)
    for identity in IDENTITIES:
        cancellation(functions[identity, "cancel"], identity)
    return functions
