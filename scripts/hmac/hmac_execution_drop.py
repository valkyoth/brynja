"""Bounded emitted destruction graphs, including actual outlined helper bodies."""
import re
from dataclasses import dataclass

import hmac_engine_codegen as common

require = common.require
SSA = r"%[-\w.]+"
SYMBOL = r'("[^"]+"|[-\w.$]+)'


@dataclass(frozen=True)
class Layout:
    size: int
    engine: int
    stride: int
    discriminator: int
    empty: int
    core: int
    core_kind: str
    scratch_kind: str


def layout(identity):
    if identity.startswith("sha3_"):
        return Layout(1792, 1760, 864, 1440, 2, 624, "memory", "keccak")
    general = identity.startswith("general")
    return Layout(4064 if general else 4032, 4048 if general else 4016,
                  2016 if general else 2000, 704, -1, 816, "sha2", "scratch")


def leaf(symbol):
    """Exact terminal cleanup identities, not arbitrary drop-named functions."""
    if common.owner_drop(symbol, "sha256"):
        return "sha2"
    paths = {
        "memory": ("16brynja_hash_sha3", "hardened", "accelerated", "engine", "Memory"),
        "scratch": ("17brynja_crypto_cpu", "hardened_execution", "scratch", "Scratch"),
        "keccak": ("17brynja_crypto_cpu", "hardened_execution", "keccak_scratch", "KeccakScratch"),
    }
    for kind, (crate, *parts) in paths.items():
        if symbol.startswith("_R"):
            path = "".join(str(len(part)) + part for part in parts[:-1])
            pattern = (r"_RNvXs_Nt(?:Nt)+Cs\w+_" + crate + path
                       + r"NtB\w+_" + str(len(parts[-1])) + parts[-1]
                       + r"NtNtNtCs\w+_4core3ops4drop4Drop4drop")
        else:
            path = r"\.\.".join((crate[2:], *parts))
            pattern = (r"_ZN\d+_\$LT\$" + path
                       + r"\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E")
        if re.fullmatch(pattern, symbol):
            return kind
    return None


def initial(identity, route, present, compiler="1.99.1"):
    shape = layout(identity)
    require(compiler in ("1.90.0", "1.99.1"), "unreviewed compiler layout")
    empty = 3 if compiler == "1.90.0" and shape.core_kind == "sha2" else shape.empty
    memory = {shape.discriminator: route if present else empty}
    if not identity.startswith("sha3_"):
        memory[shape.stride + shape.discriminator] = route
    expected = frozenset(
        (kind, offset)
        for base in (0, shape.stride)
        for kind, offset in ((shape.core_kind, base + shape.core),
                             (shape.scratch_kind, base))
    ) if present else frozenset()
    return memory, expected


def helper(symbol, definitions, aliases):
    require(("drop_glue" in symbol or "drop_in_place" in symbol)
            and ("brynja_mac_hmac" in symbol or "brynja_hash_sha" in symbol),
            "unexpected accelerated cleanup helper")
    arguments, body = common.resolve(symbol, definitions, aliases)
    parameters = re.findall(SSA, arguments)
    require(len(parameters) == 1, "unexpected accelerated helper signature")
    return parameters[0], body


def walk(body, parameter, base, memory, attempted, definitions, aliases, depth=0,
         expected=None, size=None, unwinding=False, panic="unwind"):
    """Explore normal and recoverable unwind edges; leaves are dispatch contracts.

    No secret values are modeled. Only public enum discriminants and immutable
    field offsets may be loaded. Unsupported instructions/callees fail closed.
    """
    require(depth < 8, "recursive accelerated cleanup")
    graph = common.blocks(body)
    queue = [(next(iter(graph)), {parameter: ("ptr", base)}, attempted, unwinding)]
    results = []
    steps = 0
    while queue:
        label, values, done, exceptional = queue.pop()
        require(label in graph, "unknown accelerated cleanup edge")
        steps += 1
        require(steps < 1000, "cyclic/oversized accelerated cleanup")
        lines = graph[label]
        terminated = False
        for index, line in enumerate(lines):
            allocation = re.fullmatch(rf"({SSA}) = alloca \[(\d+) x i8\], align \d+", line)
            gep = re.fullmatch(
                rf"({SSA}) = getelementptr inbounds(?: nuw)? i8, ptr ({SSA}), i64 (\d+)", line)
            load = re.match(rf"({SSA}) = load i64, ptr ({SSA}),", line)
            compare = re.fullmatch(rf"({SSA}) = icmp (eq|ne) i64 ({SSA}), (-?\d+)", line)
            call = re.search(rf"\b(call|invoke)\b.*@{SYMBOL}\(", line)
            if allocation:
                require(size and int(allocation[2]) == size and allocation[1] not in values,
                        "unexpected cancellation allocation")
                values[allocation[1]] = ("uninitialized", 0)
            elif gep:
                require(values.get(gep[2], (None,))[0] == "ptr", "unknown cleanup pointer base")
                values[gep[1]] = ("ptr", values[gep[2]][1] + int(gep[3]))
            elif load:
                pointer = values.get(load[2])
                require(pointer and pointer[0] == "ptr" and pointer[1] in memory,
                        "unexpected cleanup discriminator load")
                values[load[1]] = memory[pointer[1]]
            elif compare:
                require(isinstance(values.get(compare[3]), int), "unknown cleanup condition")
                equal = values[compare[3]] == int(compare[4])
                values[compare[1]] = equal if compare[2] == "eq" else not equal
            elif call:
                symbol = call[2].strip('"')
                if symbol == "llvm.memcpy.p0.p0.i64":
                    match = re.search(rf"ptr [^,]*({SSA}), ptr [^,]*({SSA}), i64 (\d+), i1 false\)", line)
                    require(match and size and int(match[3]) == size and not done
                            and values.get(match[1]) == ("uninitialized", 0)
                            and match[2] == parameter and values.get(parameter) == ("ptr", base),
                            "accelerated owner copy extent/source/order")
                    values[match[1]] = ("ptr", base)
                    values[parameter] = ("moved", base)
                    continue
                if symbol.startswith("llvm.lifetime."):
                    argument = re.search(rf"({SSA})\)", line)
                    require(argument and argument[1] in values and argument[1] != parameter,
                            "unknown cancellation lifetime")
                    if symbol == "llvm.lifetime.end.p0":
                        require(expected is not None and done == expected,
                                "accelerated lifetime ends before destruction")
                        values[argument[1]] = ("ended", 0)
                    else:
                        require(symbol == "llvm.lifetime.start.p0"
                                and values[argument[1]] == ("uninitialized", 0),
                                "unexpected cancellation lifetime start")
                    continue
                if common.panic_cleanup(symbol):
                    require(exceptional and index + 1 < len(lines)
                            and lines[index + 1] == "unreachable",
                            "unexpected fatal cleanup continuation")
                    # Only compiler's double-panic terminal. Not a successful exit.
                    terminated = True
                    break
                argument = re.search(rf"({SSA})\)(?: #[0-9]+)?(?:,.*)?$", line)
                require(argument and values.get(argument[1], (None,))[0] == "ptr",
                        "unresolved accelerated cleanup argument")
                pointer = values[argument[1]][1]
                kind = leaf(symbol)
                if kind:
                    event = (kind, pointer)
                    require(event not in done, "duplicate accelerated owner destruction")
                    outcomes = [("ret", done | {event}), ("resume", done | {event})]
                else:
                    param, nested = helper(symbol, definitions, aliases)
                    outcomes = walk(nested, param, pointer, memory, done,
                                    definitions, aliases, depth + 1, unwinding=exceptional, panic=panic)
                if call[1] == "invoke":
                    require(index + 1 < len(lines), "missing cleanup invoke edges")
                    edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                         + common.LABEL, lines[index + 1])
                    require(edges, "invalid cleanup invoke edges")
                    for outcome, attempted_next in outcomes:
                        queue.append((edges[1 if outcome == "ret" else 2],
                                      dict(values), attempted_next, exceptional or outcome == "resume"))
                    terminated = True
                    break
                normal = [events for outcome, events in outcomes if outcome == "ret"]
                if panic == "unwind":
                    results.extend((outcome, events) for outcome, events in outcomes
                                   if outcome == "resume")
                require(normal and all(events == normal[0] for events in normal),
                        "ambiguous normal helper destruction")
                done = normal[0]
            elif line.startswith("br "):
                direct = re.fullmatch("br label %" + common.LABEL, line)
                branch = re.fullmatch(rf"br i1 ({SSA}), label %" + common.LABEL
                                      + ", label %" + common.LABEL, line)
                require(direct or branch, "unsupported cleanup branch")
                if direct:
                    target = direct[1]
                else:
                    require(type(values.get(branch[1])) is bool, "unknown cleanup branch condition")
                    target = branch[2 if values[branch[1]] else 3]
                queue.append((target, dict(values), done, exceptional))
                terminated = True
                break
            elif line.startswith(("ret void", "resume ")):
                results.append(("ret" if line == "ret void" else "resume", done))
                terminated = True
                break
            elif (re.fullmatch(rf"{SSA} = landingpad \{{ ptr, i32 \}}", line)
                  or re.match(rf"{SSA} = phi \{{ ptr, i32 \}} ", line)
                  or line in ("cleanup", "filter [0 x ptr] zeroinitializer")):
                pass  # Exception payload cannot affect owner pointers/branches.
            else:
                require(False, "unsupported accelerated destruction instruction: " + line)
        require(terminated, "unterminated accelerated destruction block")
    require(results, "vacuous accelerated destruction graph")
    return results


def cancellation(body, identity, definitions, aliases, compiler="1.99.1", panic="unwind"):
    shape = layout(identity)
    for route in (0, 1):
        for present in (False, True):
            memory, expected = initial(identity, route, present, compiler)
            for _, done in walk(body, "%state", 0, memory, frozenset(), definitions, aliases,
                                expected=expected, size=shape.size, panic=panic):
                require(done == expected, "missing/wrong accelerated core or CPU scratch cleanup")
