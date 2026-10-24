"""Inspect actual normalization setup and readiness before key hashing.

Scope/clear and hash semantics remain source-bound callee premises. This checks
caller initialization, instruction ordering and error/unwind exclusion, not a
new proof of kernels, cleanup on fatal aborts or full HMAC output ownership.
"""
import re

import legacy_hmac_md5_keys as keys

n = keys.normalization
flow, syntax, require, VALUE = n.flow, n.syntax, n.require, n.VALUE
Pointer, Bits, Memory = n.bits.Pointer, n.bits.Bits, n.bits.Memory
results, phases, errors = n.results, n.phases, n.transport.errors


def setup(check, key_check, llvm):
    clear = phases.one(check.body, lambda name, args: results.fence.identity(name, "clear"), "normalization clear")
    ready = phases.one(check.body, lambda name, args: results.fence.identity(name, "ready"), "normalization ready")
    digest = check.calls["simd"]
    phases.dominates(check.graph, clear, ready)
    phases.dominates(check.graph, ready, digest)
    require(clear[:2] in key_check.frontiers and key_check.frontiers[clear[:2]] == "simd",
            "normalization route no longer enters actual setup")
    start, unwind = results.continuation(check.graph, clear)
    memory = Memory({**check.allocs, check.workspace: 912})
    memory.store(Pointer(check.workspace), Pointer("authority"))
    state = n.transport.State(check, start, memory)
    state.dead.add(check.scope)
    label, index = start
    seen, copies, visited = set(), set(), set()
    while True:
        require((label, index) not in seen, "cycle in normalization setup")
        seen.add((label, index))
        lines = check.graph[label]
        while index < len(lines):
            site, line = (label, index), lines[index]
            if site == ready[:2]:
                require(copies == {72 + 113 * lane for lane in range(8)} and check.scope not in state.dead
                        and state.memory.load(Pointer(check.scope), "ptr") == Pointer(check.workspace)
                        and state.memory.load(Pointer(check.scope, 8), "i8") == Bits.integer(0, 8)
                        and len(ready[3]) == 1 and state.address(syntax.operand(ready[3][0])) == Pointer("authority"),
                        "normalization readiness IV/Scope/authority binding changed")
                return ready, visited, unwind
            visited.add(site)
            definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
            store = re.fullmatch(rf"store (ptr|i8) ({VALUE}|0), ptr ({VALUE}), align 8(?:, !.*)?", line)
            call = syntax.call(line)
            jump = re.fullmatch("br label %" + flow.LABEL, line)
            if call:
                name, args = call
                require(not definition and "invoke " not in line, "unexpected setup call result/unwind")
                if name == "llvm.memcpy.p0.p0.i64":
                    require(len(args) == 4 and args[2:] == ["i64 16", "i1 false"], "normalization IV copy extent changed")
                    dest = state.address(syntax.operand(args[0]))
                    require(dest.root == check.workspace and dest.offset in {72 + 113 * lane for lane in range(8)}
                            and dest.offset not in copies, "normalization IV lane repeated/changed")
                    source = re.search(r"(@[-\w.]+)$", args[1])
                    require(source and re.search(re.escape(source[1]) + r' = private unnamed_addr constant \[16 x i8\] c"'
                            + re.escape(r'\01#Eg\89\AB\CD\EF\FE\DC\BA\98vT2\10') + '"', llvm),
                            "normalization IV bytes changed")
                    copies.add(dest.offset)
                else:
                    require(name in ("llvm.lifetime.start.p0", "llvm.experimental.noalias.scope.decl") and
                            (name.endswith("decl") or syntax.operand(args[-1]) == check.scope),
                            "unreviewed normalization setup effect")
                    state.call(name, args)
            elif definition:
                state.values[definition[1]] = state.expression(definition[2])
            elif store:
                address = state.address(store[3])
                require(address == Pointer(check.scope, 0 if store[1] == "ptr" else 8), "setup store outside Scope")
                state.memory.store(address, state.value(store[2], store[1]))
            elif jump:
                label, index = jump[1], 0
                break
            else:
                require(False, "unparsed normalization setup instruction: " + line)
            index += 1
        else:
            require(False, "normalization setup bypasses readiness")


def validate(fixture, llvm, panic):
    results.fence.validate_source()
    key_check = keys.Check(fixture, llvm)
    definitions, _ = flow.definitions_and_aliases(llvm)
    signature, body = next(value for name, value in definitions.items() if phases.identity(name, "pads"))
    check = n.Check(signature, body, llvm, fixture)
    ready, visited, clear_unwind = setup(check, key_check, llvm)
    ok = results.fence.success(fixture) & 255
    line = check.graph[ready[0]][ready[1]]
    returned = re.match(rf"({VALUE}) = (?:tail )?(?:call|invoke) \{{ i8, i8 \}} ", line)
    require(returned, "normalization readiness result discarded")
    start, unwind = results.continuation(check.graph, ready)
    stops = {site[:2] for site in check.calls.values()} | {(check.stop, 0)}
    for tag in range(4):
        require(not errors.reaches(body, start, ready[0], {returned[1]: (tag, None)}, None, None, stops),
                "normalization readiness error enters scalar/SIMD/pad work")
    seed = {returned[1]: (ok, None)}
    require(errors.reaches(body, start, ready[0], seed, None, None, {check.calls["simd"][:2]}),
            "normalization readiness success has no SIMD witness")
    require(not errors.reaches(body, start, ready[0], seed, None, None,
                               {check.calls["scalar"][:2], (check.stop, 0)}, barriers={check.calls["simd"][:2]}),
            "normalization readiness success bypasses SIMD dispatch")
    for exceptional in (clear_unwind, unwind):
        require(bool(exceptional) == (panic == "unwind"), "normalization setup panic profile changed")
        if exceptional:
            require(not errors.reaches(body, exceptional, None, {}, None, None, stops),
                    "normalization setup unwind enters work")
    # Scalar initialization must lead directly to the already-bound digest;
    # no callback, buffer mutation or error-driven route switch is allowed.
    scalar_setup = next(site for site, kind in key_check.frontiers.items() if kind == "scalar")
    scalar_start, scalar_unwind = results.continuation(check.graph, scalar_setup)
    label, index = scalar_start
    seen = set()
    while (label, index) != check.calls["scalar"][:2]:
        require((label, index) not in seen, "cyclic scalar normalization setup")
        seen.add((label, index))
        lines = check.graph[label]
        jump = re.fullmatch("br label %" + flow.LABEL, lines[index])
        require(jump and index == len(lines) - 1, "effect after scalar normalization initialization")
        label, index = jump[1], 0
    require(bool(scalar_unwind) == (panic == "unwind"), "scalar normalization panic profile changed")
    if scalar_unwind:
        require(not errors.reaches(body, scalar_unwind, None, {}, None, None, stops),
                "scalar initializer unwind enters work")
    return check, ready, visited
