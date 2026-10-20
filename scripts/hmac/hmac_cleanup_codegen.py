"""Fail-closed LLVM flow checks for five fixed HMAC scratch probes only."""
import re

PROBES = {"scratch_1": 1, "scratch_64": 64, "scratch_144": 144,
          "scratch_unwind": 64, "scratch_mask": 144}
CLEAR = r"@(?:_RN\w*|_ZN\w*)11brynja_core13secret_memory18clear_owned_region\w*\("


def require(condition, message):
    if not condition:
        raise ValueError("HMAC scratch compiler evidence: " + message)


def functions(llvm):
    result = {}
    for match in re.finditer(r"^define [^\n]*@(\w+)\([^\n]*\{\n(.*?)^\}", llvm, re.M | re.S):
        name, body = match.groups()
        for probe in PROBES:
            if re.search(r"19brynja_hmac_cleanup" + str(len(probe)) + probe + r"(?:17h\w+E)?$", name):
                require(probe not in result, "duplicate probe " + probe)
                result[probe] = body
    require(set(result) == set(PROBES), "missing exact probe population")
    return result


def blocks(body):
    result = {}
    current = None
    for raw in body.splitlines():
        line = raw.split(";", 1)[0].strip()
        if not line:
            continue
        label = re.fullmatch(r"([-\w.]+):", line)
        if label:
            current = label[1]
            require(current not in result, "duplicate LLVM block")
            result[current] = []
        else:
            require(current is not None, "instruction outside LLVM block")
            result[current].append(line)
    require(result, "empty LLVM function")
    return result


def check_body(body, size, panic):
    graph = blocks(body)
    owner = re.findall(r"(%[\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
    require(len(owner) == 1, "missing/ambiguous owned scratch allocation")
    owner = owner[0]
    visited = set()
    queue = [(next(iter(graph)), False)]
    exits = 0
    clears = 0
    while queue:
        label, clean = queue.pop()
        if (label, clean) in visited:
            continue
        visited.add((label, clean))
        require(label in graph, "unknown branch target")
        instructions = graph[label]
        terminal = False
        for index, line in enumerate(instructions):
            is_clear = bool(re.search(CLEAR, line))
            if re.search(r"\b(?:call|invoke)\b", line):
                require(is_clear or any(token in line for token in (
                    "copy_secret_region", "xor_secret_byte_bits", "%observer(",
                    "@llvm.lifetime.", "@llvm.memset.", "@llvm.memcpy.",
                    'asm sideeffect ""', "panic_in_cleanup")),
                    "unreviewed call in fixed scratch probe")
            require(not re.search(r"\b(?:atomicrmw|cmpxchg)\b", line),
                    "unreviewed memory operation")
            if "clear_owned_region" in line:
                require(is_clear, "wrong clear function identity")
            if is_clear:
                # Attribute parentheses can occur before the actual pointer.
                require(re.search(re.escape(owner) + r", i64(?: noundef)? " + str(size) + r"\)", line),
                        "clear does not cover exact owned range")
                clears += 1
                if " invoke " in " " + line:
                    require(index + 1 < len(instructions), "missing invoke edges")
                    edges = re.fullmatch(r"to label %([-\w.]+) unwind label %([-\w.]+)",
                                         instructions[index + 1])
                    require(edges, "invalid clear invoke edges")
                    queue += [(edges[1], True), (edges[2], clean)]
                    terminal = True
                    break
                clean = True
            elif ("copy_secret_region" in line or "xor_secret_byte_bits" in line
                  or "%observer(" in line or line.startswith("store ")
                  or "llvm.memset" in line or "llvm.memcpy" in line
                  or "asm sideeffect" in line):
                clean = False
            if " invoke " in " " + line:
                require(index + 1 < len(instructions), "missing invoke destination")
                edges = re.fullmatch(r"to label %([-\w.]+) unwind label %([-\w.]+)",
                                     instructions[index + 1])
                require(edges, "unsupported invoke destination")
                queue += [(edges[1], clean), (edges[2], clean)]
                terminal = True
                break
            if line.startswith("br "):
                labels = re.findall(r"label %([-\w.]+)", line)
                require(len(labels) in (1, 2), "unsupported branch")
                queue += [(target, clean) for target in labels]
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(clean, "normal/error/unwind exit without scratch clear")
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(any("panic_in_cleanup" in item for item in instructions),
                        "unreviewed unreachable exit")
                terminal = True  # Double-panic termination is outside recoverable unwind.
                break
            if "llvm.lifetime.end" in line and re.search(re.escape(owner) + r"\)", line):
                require(clean, "scratch lifetime ended before clearing")
        require(terminal, "unsupported or missing block terminator")
    require(exits and clears, "vacuous cleanup graph")
    if panic == "unwind":
        require("resume " in body and "landingpad " in body, "unwind path absent")
    else:
        require("resume " not in body and "landingpad " not in body, "wrong panic profile")


def check(mir, llvm, assembly, panic):
    require(panic in ("abort", "unwind"), "unknown panic profile")
    require(re.search(r"fn scratch::.*::drop\(_1: &mut Scratch<N>\)", mir),
            "actual Scratch destructor MIR missing")
    require("clear_owned_region(" in mir, "MIR clearing call absent")
    for name, body in functions(llvm).items():
        check_body(body, PROBES[name], panic)
        require(name in assembly, "assembly probe absent: " + name)
    require("clear_owned_region" in assembly, "assembly clear symbol absent")
