"""Actual final workspace readiness helper, with source-bound cleanup premises.

Checks dispatch/result preservation and Scope completion, not the transitive
ready implementation, machine-code erasure, or full HMAC caller provenance.
"""
import hashlib
import re

import legacy_hmac_md5_admission as admission

rows = admission.rows
flow, syntax, require, VALUE = rows.flow, rows.syntax, rows.require, admission.VALUE
PINS = {
    "crates/brynja-legacy-md5/src/batch/hardened_execution/in_place.rs":
        "64fc49bae729fcdaadbffe82ff5d36f206835828f115255539dff5dcf7a13d95",
    "crates/brynja-legacy-md5/src/batch/hardened_execution/mod.rs":
        "aaa00977c44f48c3c7c62d0f3f12d1a2c3095ec0b88f005090dfd5fc69e0f282",
    "crates/brynja-legacy-md5/src/cpu/secret.rs":
        "1fd19b0d4167991ae1cb93ec209807350e334a3a85b3204124f013f05afbddb8",
}


def validate_source(root=rows.contracts.ROOT):
    for name, digest in PINS.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                "workspace non-refilling/no-callback cleanup premise changed: " + name)


def identity(symbol, role):
    prefix = r"_RNvMs\w*_NtNt(?:Nt)?Cs\w+_17brynja_legacy_md55batch18hardened_execution"
    patterns = {
        "ready": prefix + r"NtB\w+_8Executor5ready|_ZN17brynja_legacy_md55batch18hardened_execution8Executor5ready17h[0-9a-f]+E",
        "clear": r"_RNvNtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_place5clear|"
                 r"_ZN17brynja_legacy_md55batch18hardened_execution8in_place5clear17h[0-9a-f]+E",
        "cancel": prefix + r"8in_placeNtB\w+_5Batch6cancel|"
                  r"_ZN17brynja_legacy_md55batch18hardened_execution8in_place5Batch6cancel17h[0-9a-f]+E",
        "drop": r"_RNvXNtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_5Scope"
                r"NtNtNtCs\w+_4core3ops4drop4Drop4drop|"
                r"_ZN103_\$LT\$brynja_legacy_md5\.\.batch\.\.hardened_execution\.\.in_place\.\.Scope"
                r"\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E",
    }
    return bool(re.fullmatch(patterns[role], symbol))


def helper(symbol):
    return bool(re.fullmatch(
        r"_RINvMs_NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_9Workspace4withu\w+|"
        r"_ZN17brynja_legacy_md55batch18hardened_execution8in_place9Workspace4with17h[0-9a-f]+E", symbol))


def success(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    lines = list(flow.blocks(admission.probe(definitions, aliases, "readiness_ok")).values())
    require(len(lines) == 1 and len(lines[0]) == 1, "readiness ABI probe gained control flow")
    match = re.fullmatch(r"ret \{ i8, i8 \} \{ i8 (-1|4), i8 (?:undef|poison) \}", lines[0][0])
    require(match, "readiness Result ABI changed")
    return int(match[1])


def walk(signature, body, llvm, ok, outcome, interrupt=None):
    params = syntax.parameters(signature)
    require(len(params) == 1 and syntax.operand(params[0]) == "%self"
            and "dereferenceable(912)" in params[0], "readiness helper workspace changed")
    graph, values = flow.blocks(body), {"%self": ("workspace", 0)}
    label, predecessor, seen = next(iter(graph)), None, set()
    memory, copied = {}, set()
    cleared = ready = cancelled = dropped = False
    unwinding = False

    def value(text):
        if text in ("undef", "poison"):
            return None
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        require(text in values, "unknown fence value: " + text)
        return values[text]

    while label not in seen:
        seen.add(label)
        require(label in graph, "unknown readiness edge")
        lines = graph[label]
        for index, line in enumerate(lines):
            definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
            invocation = syntax.call(line)
            if invocation:
                symbol, args = invocation
                role = next((kind for kind in ("ready", "clear", "cancel", "drop") if identity(symbol, kind)), None)
                if role:
                    require(len(args) == 1, "readiness callee arity changed")
                    pointer = value(syntax.operand(args[0]))
                    require(pointer == ("scope", 0) if role == "drop" else
                            pointer == ("authority", 0) if role == "ready" else pointer == ("workspace", 0),
                            "readiness callee pointer changed")
                    if role == "clear":
                        require(not cleared and not ready and not copied, "readiness clear reordered/repeated")
                        cleared = True
                    elif role == "ready":
                        require(cleared and not ready and copied == {72 + 113 * lane for lane in range(8)}
                                and memory == {0: ("workspace", 0), 8: 0}, "readiness guard/IV initialization changed")
                        ready = True
                        require(definition, "unused readiness result")
                        values[definition[1]] = outcome
                    elif role == "cancel":
                        require(ready and outcome[0] == ok and not cancelled and not dropped,
                                "cancel without successful readiness")
                        cancelled = True
                    else:
                        require(ready and not dropped and memory.get(0) == ("workspace", 0)
                                and memory.get(8) == int(cancelled and not unwinding),
                                "wrong/absent Scope completion or repeated cleanup")
                        dropped = True
                    if re.search(r"\binvoke\b", line):
                        edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL, lines[index + 1])
                        require(edges, "readiness invoke edges changed")
                        exception = interrupt == role
                        unwinding |= exception
                        predecessor, label = label, edges[2 if exception else 1]
                        break
                    require(interrupt != role, "missing readiness unwind edge")
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0")
                            and len(args) in (1, 2) and value(syntax.operand(args[-1])) == ("scope", 0)
                            and (len(args) == 1 or args[0] == "i64 16"), "unbound fence guard lifetime")
                    if symbol.endswith("end.p0"):
                        require(dropped, "Scope lifetime ends without destruction")
                elif symbol == "llvm.memcpy.p0.p0.i64":
                    require(cleared and not ready and len(args) == 4 and args[2:] == ["i64 16", "i1 false"],
                            "unexpected fence copy")
                    pointer = value(syntax.operand(args[0]))
                    require(pointer[0] == "workspace" and pointer[1] in {72 + 113 * lane for lane in range(8)}
                            and pointer[1] not in copied, "fence IV extent/lane changed")
                    source = re.search(r"(@[-\w.]+)$", args[1])
                    require(source and re.search(re.escape(source[1]) + r' = private unnamed_addr constant \[16 x i8\] c"'
                            + re.escape(r'\01#Eg\89\AB\CD\EF\FE\DC\BA\98vT2\10') + '"', llvm), "fence IV source changed")
                    copied.add(pointer[1])
                else:
                    require(False, "unreviewed readiness helper call: " + symbol)
            elif definition:
                name, expression = definition.groups()
                gep = re.fullmatch(rf"getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", expression)
                extract = re.fullmatch(rf"extractvalue \{{ i8, i8 \}} ({VALUE}), ([01])", expression)
                insert = re.fullmatch(rf"insertvalue \{{ i8, i8 \}} ({VALUE}), i8 ({VALUE}), 1", expression)
                compare = re.fullmatch(rf"icmp eq i8 ({VALUE}), (-?\d+)", expression)
                load = re.match(rf"load ptr, ptr ({VALUE}), align 8(?:,|$)", expression)
                if expression == "alloca [16 x i8], align 8":
                    require(("scope", 0) not in values.values(), "duplicate scope allocation")
                    values[name] = ("scope", 0)
                elif gep:
                    root, offset = value(gep[1])
                    values[name] = root, offset + int(gep[2])
                elif load:
                    require(value(load[1]) == ("workspace", 0), "unbound workspace authority load")
                    values[name] = ("authority", 0)
                elif extract:
                    values[name] = value(extract[1])[int(extract[2])]
                elif insert:
                    values[name] = value(insert[1])[0], value(insert[2])
                elif compare:
                    values[name] = value(compare[1]) == int(compare[2])
                elif expression.startswith("phi i8 "):
                    choices = re.findall(rf"\[ ({VALUE}|undef|poison), %" + flow.LABEL + r" \]", expression)
                    selected = [item for item, parent in choices if parent == predecessor]
                    require(len(selected) == 1, "unbound readiness result phi")
                    values[name] = value(selected[0])
                else:
                    require(expression == "landingpad { ptr, i32 }", "unknown fence instruction: " + line)
            elif line.startswith("store "):
                store = re.match(rf"store (ptr|i8) ({VALUE}|[01]), ptr ({VALUE}), align 8", line)
                require(store and not dropped, "unknown/post-Drop fence store")
                pointer = value(store[3])
                require(pointer == ("scope", 0 if store[1] == "ptr" else 8), "fence writes outside Scope")
                memory[pointer[1]] = value(store[2])
            elif line.startswith("br "):
                direct = re.fullmatch("br label %" + flow.LABEL, line)
                branch = re.fullmatch(rf"br i1 ({VALUE}), label %" + flow.LABEL + ", label %" + flow.LABEL, line)
                require(direct or branch, "unknown fence branch")
                if branch:
                    require(isinstance(value(branch[1]), bool), "nonboolean fence condition")
                predecessor, label = label, direct[1] if direct else branch[2 if value(branch[1]) else 3]
                break
            elif line.startswith(("ret ", "resume ")):
                require(ready and dropped, "fence returns without readiness/cleanup")
                if unwinding:
                    require(line.startswith("resume ") and interrupt, "fence swallow of unwind")
                else:
                    returned = re.fullmatch(rf"ret \{{ i8, i8 \}} ({VALUE})", line)
                    require(returned and value(returned[1])[0] == outcome[0]
                            and (outcome[0] == ok or value(returned[1])[1] == outcome[1])
                            and cancelled == (outcome[0] == ok), "fence changes readiness result")
                return
            else:
                require(line == "cleanup", "unparsed fence effect: " + line)
        else:
            require(False, "unterminated fence path")
    require(False, "cyclic fence path")


def validate(signature, body, llvm, ok, panic):
    validate_source()
    for tag in (0, 1, 2, 3, ok):
        for payload in range(-128, 128):
            walk(signature, body, llvm, ok, (tag, payload))
    if panic == "unwind":
        for interrupt in ("ready", "cancel"):
            walk(signature, body, llvm, ok, (ok, 0), interrupt)
