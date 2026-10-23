"""Real legacy constructor/finalizer scratch paths, not hash-owner destruction."""
import re
import legacy_hmac_engine_codegen as codegen
import legacy_hmac_engine_final as final

# A private instance gives this legacy population its own configuration while
# leaving the modern checker/module untouched. Its codegen import was already
# loaded and origin-checked by codegen; no family-relative search is introduced.
flow = codegen.load("hmac_engine_scratch", "legacy_hmac_scratch_graph")
flow.SCRATCH = {
    "construct": {"pad": 64, "digest": 20},
    **{operation: {"inner_digest": 20, "tag": 20,
                   **({"difference": 1} if operation.startswith("verify") else {})}
       for operation in ("public", "secret", "verify", "public_bits", "secret_bits", "verify_bits")},
}
require = codegen.require


def guard_drop(line, body):
    symbol = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
    if not symbol:
        return False
    name = symbol[1].strip('"')
    if not re.fullmatch(
        r"_RNvXs_NtCs\w+_11brynja_core13secret_memoryNtB\w+_26SecretRegionInitialization"
        r"NtNtNtCs\w+_4core3ops4drop4Drop4drop|"
        r"_ZN96_\$LT\$brynja_core\.\.secret_memory\.\.SecretRegionInitialization"
        r"\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E", name):
        return False
    argument = re.search(r"(%[-\w.]+)\)", line)
    require(argument and re.fullmatch(r"%guard(?:\.[-\w]+)*", argument[1]), "legacy output guard identity changed")
    require(re.search(re.escape(argument[1]) + r" = alloca \[24 x i8\],", body), "legacy output guard storage changed")
    return True


flow.output_guard_drop = guard_drop


def wrapper(body, identity, method, symbol):
    """Bind each outlined call to the real consuming probe's input owner."""
    size, _ = codegen.layout(identity)
    copies = re.findall(r"(%[-\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
    require(len(copies) == 1, "outlined caller owner allocation changed")
    copy = copies[0]
    copy_lines = [line for line in body.splitlines() if "@llvm.memcpy." in line and re.search(r"%state,", line)]
    require(len(copy_lines) == 1 and re.search(re.escape(copy) + r", ptr [^\n]*%state, i64 "
                                              + str(size) + r", i1 false\)", copy_lines[0]),
            "outlined caller owner copy binding changed")
    graph = codegen.flow.blocks(body)
    queue, visited, exits = [(next(iter(graph)), False, False)], set(), 0
    while queue:
        label, copied, dispatched = queue.pop()
        if (label, copied, dispatched) in visited:
            continue
        visited.add((label, copied, dispatched))
        require(label in graph and len(visited) < 10000, "invalid outlined caller graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            if line == copy_lines[0].strip().split(";", 1)[0].strip():
                require(not copied and not dispatched, "repeated/late outlined caller copy")
                copied = True
            if re.search(r"@\"?" + re.escape(symbol) + r'\"?\(', line):
                require(copied and not dispatched, "outlined dispatch before copy or repeated")
                _, args = final.interpreter(identity).call(line)
                require(final.interpreter(identity).operand(args[0 if method == "verify" else 1]) == copy,
                        "outlined call not bound to consumed input")
                dispatched = True
            if "llvm.lifetime.end" in line and re.search(re.escape(copy) + r"\)", line):
                require(dispatched, "outlined owner lifetime ends before dispatch")
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing outlined unwind edge")
                edges = re.fullmatch("to label %" + codegen.LABEL + " unwind label %" + codegen.LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unknown outlined invoke edges")
                queue += [(edge, copied, dispatched) for edge in edges.groups()]
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + codegen.LABEL, line)
                require(len(edges) in (1, 2), "unknown outlined branch")
                queue += [(edge, copied, dispatched) for edge in edges]
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(dispatched, "outlined caller exits without dispatch")
                exits += 1
                terminal = True
                break
            if line == "unreachable":
                require(codegen.flow.fatal_cleanup_block(lines), "unknown outlined terminal")
                terminal = True
                break
        require(terminal, "unknown outlined terminator")
    require(exits, "vacuous outlined caller")


def consumer(body, identity, operation, definitions, aliases):
    if any(re.search(r"%" + role + r"(?:\.[-\w]+)* = alloca", body) for role in flow.SCRATCH[operation]):
        flow.allocations(body, operation)
        return body
    method = operation.removesuffix("_bits")
    name = "Sha1" if identity == "sha1" else "Md5"
    calls = re.findall(r'\b(?:call|invoke)\b[^\n]*@("[^"]+"|\w+)\(', body)
    calls = [symbol.strip('"') for symbol in calls if "18brynja_legacy_hmac6engine" in symbol]
    require(len(calls) == 1, "missing/ambiguous outlined legacy method")
    symbol = calls[0]
    legacy = bool(re.fullmatch(r"_ZN18brynja_legacy_hmac6engine15Engine\$LT\$A\$GT\$"
                              + str(len(method)) + method + r"17h[0-9a-f]+E", symbol))
    require((legacy or str(len(name)) + name in symbol) and re.search(
        str(len(method)) + method + r"(?:17h[0-9a-f]+E|B\w+_|Cs\w+_33brynja_legacy_hmac_engine_cleanup)?$", symbol),
        "wrong outlined legacy identity/method")
    arguments, outlined = codegen.flow.resolve(symbol, definitions, aliases)
    size, _ = codegen.layout(identity)
    require(re.search(r"dereferenceable\(" + str(size) + r"\) %self(?:,|$)", arguments),
            "outlined legacy owner geometry changed")
    wrapper(body, identity, method, symbol)
    flow.allocations(outlined, operation)
    return outlined


def check(body, operation):
    flow.check(body, operation)
