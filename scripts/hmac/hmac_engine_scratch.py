"""Local scratch clear-dispatch obligations, not callee or frame-erasure proofs."""
import re

from hmac_engine_codegen import LABEL, blocks, fatal_cleanup_block, require, resolve

SCRATCH = {
    "construct": {"pad": 144, "normalized": 64},
    "public": {"inner_digest": 64, "tag": 64},
    "secret": {"inner_digest": 64, "tag": 64},
    "verify": {"inner_digest": 64, "tag": 64, "difference": 1},
    "public_bits": {"inner_digest": 64, "tag": 64},
    "secret_bits": {"inner_digest": 64, "tag": 64},
    "verify_bits": {"inner_digest": 64, "tag": 64, "difference": 1},
}
CLEAR = r"@(?:_RN\w*|_ZN\w*)11brynja_core13secret_memory18clear_owned_region\w*\("


def consumer(body, operation, definitions, aliases):
    """Resolve the exact emitted shared Engine method when LLVM outlines it."""
    if any(re.search(r"%" + role + r"(?:\.[-\w]+)* = alloca", body)
           for role in SCRATCH[operation]):
        return body
    method = operation.removesuffix("_bits")
    calls = re.findall(r'\b(?:call|invoke)\b[^\n]*@("[^"]+"|\w+)\(', body)
    calls = [symbol.strip('"') for symbol in calls if "15brynja_mac_hmac6engine" in symbol]
    require(len(calls) == 1, "missing/ambiguous outlined HMAC method")
    symbol = calls[0]
    require(re.search(str(len(method)) + method
                      + r"(?:17h[0-9a-f]+E|B\w+_|Cs\w+_26brynja_hmac_engine_cleanup)?$", symbol),
            "unexpected outlined HMAC method")
    outlined = resolve(symbol, definitions, aliases)[1]
    # No recursive marker search: the actual called definition must own all
    # expected scratch; its complete graph is checked by the same checker.
    allocations(outlined, operation)
    return outlined


def output_guard_drop(line, body):
    """Separate caller-output guard; safe Rust excludes aliasing local scratch."""
    v0 = (r"@_RNvXs_NtCs\w+_11brynja_core13secret_memoryNtB\w+_"
          r"26SecretRegionInitializationNtNtNtCs\w+_4core3ops4drop4Drop4drop\(")
    legacy = (r'@"_ZN96_\$LT\$brynja_core\.\.secret_memory\.\.SecretRegionInitialization'
              r'\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E"\(')
    if not re.search(v0 + "|" + legacy, line):
        return False
    argument = re.search(r"(%[-\w.]+)\)", line)
    require(argument and re.fullmatch(r"%initialization(?:\.[-\w]+)*", argument[1]),
            "output guard identity changed")
    require(re.search(re.escape(argument[1]) + r" = alloca \[24 x i8\],", body),
            "output guard storage changed")
    return True


def allocations(body, operation):
    result = {}
    for role, size in SCRATCH[operation].items():
        matches = re.findall(r"(%" + role + r"(?:\.[-\w]+)*) = alloca \[" + str(size)
                             + r" x i8\],", body)
        require(len(matches) == 1, "missing/ambiguous real scratch " + role)
        result[matches[0]] = size
    return result


def check(body, operation):
    owners = allocations(body, operation)
    names = tuple(owners)
    graph = blocks(body)
    # Inactive, live-needing-clear, and live-cleared.
    queue = [(next(iter(graph)), (-1,) * len(names))]
    trails = {queue[0]: ()}
    visited = set()
    started = set()
    cleared = set()
    exits = 0
    while queue:
        label, state = queue.pop()
        if (label, state) in visited:
            continue
        visited.add((label, state))
        trail = (*trails[label, state], label)
        require(len(visited) < 20000, "scratch state graph exceeded bound")
        require(label in graph, "unknown scratch branch")
        values = list(state)
        lines = graph[label]
        terminal = False
        for index, line in enumerate(lines):
            is_clear = bool(re.search(CLEAR, line))
            if "clear_owned_region" in line:
                require(is_clear, "unrecognized scratch clear identity")
            selected = [name for name in names if re.search(re.escape(name) + r"(?=[,) ]|$)", line)]
            if "@llvm.lifetime." in line:
                require("@llvm.lifetime.start.p0(" in line or "@llvm.lifetime.end.p0(" in line,
                        "unknown lifetime operation")
                for name in selected:
                    slot = names.index(name)
                    if "@llvm.lifetime.start." in line:
                        require(values[slot] == -1, "scratch lifetime restarted while live")
                        values[slot] = 0
                        started.add(name)
                    else:
                        require(values[slot] == 1, "scratch lifetime ended without clear: " + name)
                        values[slot] = -1
            elif is_clear:
                for name in selected:
                    require(re.search(re.escape(name) + r", i64(?: noundef)? "
                                      + str(owners[name]) + r"\)", line),
                            "scratch clear pointer/extent changed")
                    slot = names.index(name)
                    require(values[slot] != -1, "clear outside scratch lifetime")
                    values[slot] = 1
                    cleared.add(name)
            elif output_guard_drop(line, body):
                pass
            elif re.search(r"\b(call|invoke|store|atomicrmw|cmpxchg)\b", line):
                require(all(values[names.index(name)] != -1 for name in selected),
                        "operation references inactive scratch")
                # Conservatively treat other operations as potentially writing
                # any live scratch, including pointers captured in closures.
                values = [0 if value != -1 else -1 for value in values]
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing scratch invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed scratch invoke edges")
                # Both edges establish dispatch, not successful callee erasure.
                # The core clear's non-panicking contract is a separate premise.
                children = [(edges[1], tuple(values)), (edges[2], tuple(values))]
                for child in children:
                    trails.setdefault(child, trail)
                queue += children
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + LABEL, line)
                require(len(edges) in (1, 2), "unparsed scratch branch")
                children = [(edge, tuple(values)) for edge in edges]
                for child in children:
                    trails.setdefault(child, trail)
                queue += children
                terminal = True
                break
            if line.startswith("switch "):
                rest = "\n".join(lines[index:])
                require("]" in rest, "unterminated scratch switch")
                edges = re.findall("label %" + LABEL, rest.split("]", 1)[0])
                require(edges, "empty scratch switch")
                children = [(edge, tuple(values)) for edge in edges]
                for child in children:
                    trails.setdefault(child, trail)
                queue += children
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(0 not in values, "scratch exits uncleared: " + repr(dict(zip(names, values)))
                        + "; path=" + repr(trail))
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(fatal_cleanup_block(lines), "unreviewed scratch terminal")
                terminal = True
                break
        require(terminal, "unparsed scratch terminator")
    require(exits and started == set(names) and cleared == set(names), "vacuous scratch check")
