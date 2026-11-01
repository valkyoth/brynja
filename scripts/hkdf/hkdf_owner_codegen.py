"""Bounded symbolic LLVM execution of HKDF owner-to-core Drop dispatch.

Only the fixed consuming probes and x86_64 descriptor layout are supported.
Unknown instructions fail closed. Core's destructor is a delegated premise,
not re-proved here; neither scratch nor whole-frame erasure is claimed.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hmac"))
from hmac_engine_codegen import blocks, definitions_and_aliases, resolve

IDENTITIES = {"modern": ("sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256"),
              "legacy": ("sha1",)}
SSA = r"%[-\w.]+"
LABEL = r'("[^"]+"|[-\w.]+)'
DROP = (
    r"(?:_RNvXs\w*_NtCs\w+_11brynja_core13secret_memoryNt\w+_17OwnedSecretRegion"
    r"NtNtNtCs\w+_4core3ops4drop4Drop4drop|"
    r"_ZN87_\$LT\$brynja_core\.\.secret_memory\.\.OwnedSecretRegion\$u20\$as\$u20\$"
    r"core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E)"
)


def require(condition, message):
    if not condition:
        raise ValueError("HKDF owner dispatch: " + message)


def split_args(text):
    depth = 0
    start = 0
    result = []
    for index, char in enumerate(text):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
        require(depth >= 0, "unbalanced arguments")
    require(depth == 0, "unbalanced arguments")
    return [*result, text[start:].strip()]


def value(text, values):
    if text.endswith("inttoptr (i64 1 to ptr)"):
        return "empty-pointer"
    token = text.split()[-1]
    if token.startswith("%"):
        require(token in values, "unknown SSA value " + token)
        return values[token]
    if token in ("null", "true", "false"):
        return {"null": None, "true": True, "false": False}[token]
    require(re.fullmatch(r"\d+", token), "unsupported value " + text)
    return int(token)


def address(pointer, offset=0):
    require(isinstance(pointer, tuple) and len(pointer) == 2, "non-local memory access")
    return pointer[0], pointer[1] + offset


def execute(arguments, body, kind, outer, inner, unwind, failure):
    """Enumerate option discriminants, retaining symbolic secret pointer/length."""
    args = split_args(arguments)
    expected = 3 if kind == "prk" else 2
    require(len(args) == expected and args[-1].endswith("%observer"), "probe ABI changed")
    pointer = "secret-pointer" if inner else None
    length = "secret-length"
    memory = {}
    if kind == "prk":
        require(args[0].startswith("ptr ") and args[1].startswith("i64 "), "PRK ABI changed")
        values = {args[0].split()[-1]: pointer, args[1].split()[-1]: length}
    else:
        require(args[0].startswith("ptr "), "key ABI changed")
        values = {args[0].split()[-1]: ("input", 0)}
        memory = {("input", 0): int(outer), ("input", 8): pointer, ("input", 16): length}
    values["unwind-observer"] = failure
    graph = blocks(body)
    label, previous = next(iter(graph)), None
    observed = dispatched = 0
    steps = 0
    while True:
        steps += 1
        require(steps <= 80 and label in graph, "cyclic/unknown control flow")
        lines = graph[label]
        next_label = None
        for index, raw in enumerate(lines):
            line = raw.split(", !", 1)[0]
            assignment = re.fullmatch(r"(" + SSA + r") = (.*)", line)
            if assignment:
                dest, expr = assignment.groups()
                require(dest not in values, "redefined SSA value")
                if re.fullmatch(r"alloca \[(16|24) x i8\], align 8", expr):
                    values[dest] = (dest, 0)
                elif match := re.fullmatch(r"getelementptr inbounds(?: nuw)? i8, ptr (" + SSA + r"), i64 (\d+)", expr):
                    values[dest] = address(value(match[1], values), int(match[2]))
                elif match := re.fullmatch(r"load (?:ptr|i64), ptr (" + SSA + r"), align 8", expr):
                    location = address(value(match[1], values))
                    require(location in memory, "load from uninitialized descriptor")
                    values[dest] = memory[location]
                elif match := re.fullmatch(r"icmp (eq|ne) (?:ptr|i64) (.*), (.*)", expr):
                    left, right = value(match[2], values), value(match[3], values)
                    require("secret-length" not in (left, right), "unmodeled symbolic-length comparison")
                    require(left != "secret-pointer" or right is None,
                            "unmodeled symbolic-pointer comparison")
                    require(right != "secret-pointer" or left is None,
                            "unmodeled symbolic-pointer comparison")
                    equal = left == right
                    values[dest] = equal if match[1] == "eq" else not equal
                elif match := re.fullmatch(r"trunc(?: nuw)? i64 (" + SSA + r") to i1", expr):
                    source = value(match[1], values)
                    require(source in (0, 1), "non-boolean option discriminant")
                    values[dest] = bool(source)
                elif expr.startswith("select i1 "):
                    condition, yes, no = split_args(expr.removeprefix("select i1 "))
                    condition = value(condition, values)
                    require(isinstance(condition, bool), "unknown select condition")
                    values[dest] = value(yes if condition else no, values)
                elif expr.startswith(("phi ptr ", "phi i64 ")):
                    choices = re.findall(r"\[ (.*?), %" + LABEL + r" \]", expr)
                    selected = [v for v, block in choices if block == previous]
                    require(len(selected) == 1, "ambiguous phi predecessor")
                    values[dest] = value(selected[0], values)
                elif expr == "landingpad { ptr, i32 }":
                    values[dest] = "exception"
                else:
                    require(False, "unsupported instruction " + line)
                continue
            if match := re.fullmatch(r"store (?:ptr|i64) (.*), ptr (" + SSA + r"), align 8", line):
                require(dispatched == 0, "write after destruction")
                location = address(value(match[2], values))
                require(location[0] != "input", "mutation of borrowed input descriptor")
                memory[location] = value(match[1], values)
                continue
            call = re.match(r'(?:tail )?(call|invoke) void (@"[^"]+"|@[-\w.]+|%observer)\(', line)
            if call:
                mode, callee = call.groups()
                tail = line[call.end():]
                depth, end = 1, None
                for pos, char in enumerate(tail):
                    depth += (char == "(") - (char == ")")
                    if depth == 0:
                        end = pos
                        break
                require(end is not None, "unterminated call")
                actual = split_args(tail[:end])
                if callee == "%observer":
                    require(observed == 0 and dispatched == 0, "observer order/count changed")
                    require(len(actual) == 1, "observer ABI changed")
                    location = address(value(actual[0], values))
                    expected_words = (pointer, length) if kind == "prk" else (int(outer), pointer, length)
                    require(tuple(memory.get(address(location, 8 * i)) for i in range(len(expected_words)))
                            == expected_words, "observer does not borrow exact owner")
                    observed += 1
                    require((mode == "invoke") == unwind, "observer panic profile changed")
                elif re.fullmatch(DROP, callee[1:].strip('"')):
                    require(observed == 1 and dispatched == 0 and outer, "invalid cleanup order/count")
                    require(len(actual) == 1, "destructor ABI changed")
                    location = address(value(actual[0], values))
                    require((memory.get(location), memory.get(address(location, 8))) == (pointer, length),
                            "destructor receives wrong pointer or extent")
                    dispatched += 1
                elif callee == "@llvm.memcpy.p0.p0.i64":
                    require(dispatched == 0 and len(actual) == 4, "copy after destruction")
                    target, source, size, volatile = (value(item, values) for item in actual)
                    require(size == 24 and volatile is False and source == ("input", 0), "descriptor copy changed")
                    require(address(target)[0] != "input", "overlapping descriptor copy")
                    for offset in (0, 8, 16):
                        memory[address(target, offset)] = memory[address(source, offset)]
                elif callee in ("@llvm.lifetime.start.p0", "@llvm.lifetime.end.p0", "@llvm.assume"):
                    # Intrinsics are not treated as evidence of clearing.
                    if callee == "@llvm.lifetime.end.p0":
                        require(dispatched == int(outer), "owner lifetime ended before destruction")
                else:
                    require(False, "unexpected call " + callee)
                if mode == "invoke":
                    require(index + 1 < len(lines), "missing invoke edges")
                    edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL, lines[index + 1])
                    require(edges, "invalid invoke edges")
                    # Observer unwind is exercised separately. Core destructor
                    # dispatch assumes its existing non-panicking contract.
                    next_label = edges[2] if callee == "%observer" and values["unwind-observer"] else edges[1]
                    break
                continue
            if line == "cleanup":
                continue
            if match := re.fullmatch("br label %" + LABEL, line):
                next_label = match[1]
                break
            if match := re.fullmatch("br i1 (" + SSA + "), label %" + LABEL + ", label %" + LABEL, line):
                condition = value(match[1], values)
                require(isinstance(condition, bool), "unknown branch condition")
                next_label = match[2] if condition else match[3]
                break
            if line == "ret void" or line.startswith("resume { ptr, i32 }"):
                require(observed == 1 and dispatched == int(outer), "exit without exact owner destruction")
                require(line.startswith("resume") == values["unwind-observer"], "wrong exit kind")
                return
            require(False, "unsupported instruction " + line)
        require(next_label is not None, "missing terminator")
        previous, label = label, next_label


def check(llvm, family, panic):
    require(family in IDENTITIES and panic in ("abort", "unwind"), "unknown configuration")
    require('target triple = "x86_64-unknown-linux-gnu"' in llvm, "unsupported target layout")
    definitions, aliases = definitions_and_aliases(llvm)
    population = {f"{kind}_{identity}" for kind in ("prk", "key") for identity in IDENTITIES[family]}
    selected = {}
    for name in (*definitions, *aliases):
        match = re.search(r"25brynja_hkdf_owner_cleanup6" + family + r"\d+((?:prk|key)_\w+?)(?:17h[0-9a-f]+E)?$", name)
        if match:
            require(match[1] not in selected, "duplicate probe")
            selected[match[1]] = resolve(name, definitions, aliases)
    require(set(selected) == population, "wrong probe population")
    for name, (args, body) in selected.items():
        kind = name.split("_", 1)[0]
        require(("landingpad " in body) == (panic == "unwind"), "panic profile mismatch")
        states = [(True, True), (True, False)]
        if kind == "key":
            states.append((False, False))
        for outer, inner in states:
            for failure in ((False, True) if panic == "unwind" else (False,)):
                execute(args, body, kind, outer, inner, panic == "unwind", failure)
    return len(selected)
