"""Bind normalization key descriptors, shape-only routing and the empty path.

The bit-string constructor's validation/return semantics are source-bound
premises. This check stops at backend setup, before cryptographic computation;
separate checks cover result transport and the conditional pad loop.
"""
import hashlib
import re

import legacy_hmac_md5_key_model as model

normalization = model.normalization
phases, flow, syntax = normalization.phases, model.flow, model.syntax
require, VALUE, Bits, Pointer = model.require, model.VALUE, model.Bits, model.Pointer
SOURCE = "crates/brynja-hash-core/src/bit_string.rs"
DIGEST = "5380273f4bffdf50eb69520c874e1cc330dbb1cff3c4f8b47596d01e2c0e634a"


def constructor(symbol):
    return bool(re.fullmatch(r"_RNvMNtCs\w+_16brynja_hash_core10bit_stringNtB\w+_9BitString3new|"
                            r"_ZN16brynja_hash_core10bit_string9BitString3new17h[0-9a-f]+E", symbol))


def probes(fixture):
    normalization.pads.descriptors.layout(fixture)
    definitions, aliases = flow.definitions_and_aliases(fixture)
    probe = normalization.pads.descriptors.admission.probe
    body = probe(definitions, aliases, "key_descriptor_success")
    graph = flow.blocks(body)
    require(len(graph) == 1, "key descriptor ABI gained control flow")
    lines = next(iter(graph.values()))
    call = syntax.call(lines[0])
    require(len(lines) == 2 and lines[1] == "ret void" and call and call[0] == "llvm.memcpy.p0.p0.i64"
            and len(call[1]) == 4 and call[1][2:] == ["i64 32", "i1 false"]
            and [syntax.operand(arg) for arg in call[1][:2]] == ["%_0", "%message"],
            "key success descriptor representation changed")
    for name, expected in (("key_descriptor_failure", {0: "ptr null", 8: "i8 2"}),
                            ("key_length_rejection", {0: "i8 1", 1: "i8 0"})):
        body = probe(definitions, aliases, name)
        graph, stores = flow.blocks(body), {}
        require(len(graph) == 1, "key rejection probe gained control flow")
        pointers = syntax.pointers(body, ("%_0",))
        lines = next(iter(graph.values()))
        require(lines[-1] == "ret void", "key rejection probe lacks return")
        for line in lines[:-1]:
            if re.fullmatch(normalization.pads.descriptors.GEP, line):
                continue
            match = re.fullmatch(rf"store (ptr null|i8 [012]), ptr ({VALUE}), align [18]", line)
            require(match and pointers.get(match[2], (None,))[0] == "%_0", "unknown key rejection probe")
            offset = pointers[match[2]][1]
            require(offset not in stores, "overwritten key rejection probe")
            stores[offset] = match[1]
        require(stores == expected, "key rejection ABI changed")


class Check:
    constructor = staticmethod(constructor)

    def __init__(self, fixture, llvm):
        probes(fixture)
        definitions, _ = flow.definitions_and_aliases(llvm)
        found = [value for name, value in definitions.items() if phases.identity(name, "pads")]
        require(len(found) == 1, "normalization input helper missing/repeated")
        signature, self.body = found[0]
        owner = normalization.Check(signature, self.body, llvm, fixture)
        self.graph, self.allocs = owner.graph, owner.allocs
        self.selection, self.output, self.keys = owner.selection, owner.output, owner.keys
        self.owner = owner.owner
        params = syntax.parameters(signature)
        self.result, self.inputs = (syntax.operand(params[i]) for i in (0, 2))
        new = phases.one(self.body, lambda name, args: bool(re.fullmatch(
            r"_RNvMs0_NtCs\w+_17brynja_legacy_md55batchNtB\w+_16HardenedMd5Batch3new|"
            r"_ZN17brynja_legacy_md55batch16HardenedMd5Batch3new17h[0-9a-f]+E", name)), "scalar normalization setup")
        clear = phases.one(self.body, lambda name, args: normalization.results.fence.identity(name, "clear"),
                           "SIMD normalization setup")
        require(len(new[3]) == 1 and syntax.operand(new[3][0]) == syntax.operand(owner.calls["scalar"][3][1])
                and len(clear[3]) == 1 and syntax.operand(clear[3][0]) == owner.workspace,
                "normalization setup does not bind actual digest owner")
        for site, kind in ((new, "scalar"), (clear, "simd")):
            phases.dominates(self.graph, site, owner.calls[kind])
        self.frontiers = {new[:2]: "scalar", clear[:2]: "simd", (owner.stop, 0): "none"}
        self.digest = {site[:2] for site in owner.calls.values()}
        self.types = {}
        dtype = '%"core::option::Option<brynja_hash_core::bit_string::BitString<\'_>>"'
        if dtype in self.body:
            require(dtype + " = type { ptr, [3 x i64] }" in llvm, "key array element geometry changed")
            self.types[dtype] = 32
        self.visited, self.routes = set(), set()
        self.error_sites = set()

    def error_exclusion(self, site):
        if site in self.error_sites:
            return
        forbidden = set(self.frontiers) | self.digest | {
            (label, index) for label, lines in self.graph.items() for index, line in enumerate(lines)
            if (call := syntax.call(line)) and constructor(call[0])}
        pending, seen = [(site[0], site[1] + 1)], set()
        while pending:
            label, start = pending.pop()
            require(label in self.graph, "unknown key-error control-flow edge")
            if (label, start) in seen:
                continue
            seen.add((label, start))
            for index in range(start, len(self.graph[label])):
                require((label, index) not in forbidden, "key constructor failure re-enters normalization/pad work")
                pending.extend((target, 0) for target in re.findall("label %" + flow.LABEL, self.graph[label][index]))
        self.error_sites.add(site)

    def run(self, lengths, mask=255, backend=0, failure=None):
        state = model.State(self, lengths, mask, backend, failure)
        route = state.walk()
        self.visited.update(state.visited)
        long = [lane for lane, length in enumerate(lengths) if mask & (1 << lane) and length > 64]
        bad = [lane for lane in long if lane == failure or lengths[lane] > ((1 << 64) - 1) // 8]
        if bad:
            require(route == "error" and state.failed and state.constructed == [lane for lane in long if lane <= bad[0]]
                    and state.memory.load(Pointer(self.result), "i8") == Bits.integer(1, 8)
                    and state.memory.load(Pointer(self.result, 1), "i8") == Bits.integer(0, 8),
                    "key constructor failure not propagated before work")
        else:
            width = 8 if backend == 0 else 4
            eligible = any(all(lane in long for lane in range(start, start + width)) for start in range(0, 8, width))
            expected = "none" if not long else "simd" if eligible else "scalar"
            require(route == expected and state.constructed == long, "key shape selects wrong route or constructor population")
            require(self.keys in state.live and self.output in state.live, "normalization buffers expired before dispatch")
            require(state.memory.load(Pointer(self.output), "<2 x i64>") == Bits.integer(0, 128)
                    and all(state.memory.cells.get((self.output, i)) == (0,) * 8 for i in range(128)),
                    "normalization destination not freshly zeroed")
            for lane in range(8):
                pointer = state.memory.load(Pointer(self.keys, lane * 32), "ptr")
                if lane not in long:
                    require(pointer == Bits.integer(0, 64), "short/inactive key incorrectly normalized")
                else:
                    require(pointer == Pointer("key" + str(lane)) and
                            tuple(bit for i in range(lane * 32 + 8, lane * 32 + 32)
                                  for bit in state.memory.cells.get((self.keys, i), (None,) * 8)) ==
                            Bits.token(("descriptor", lane), 192).data,
                            "normalization key descriptor lost lane or payload provenance")
            if route == "none":
                require(self.owner in state.live and state.memory.load(Pointer(self.owner), "i64") == Bits.integer(0, 64),
                        "no-long-key branch did not retain absent owner")
        self.routes.add(route)
        return state

    def preservation(self):
        # Track address aliases only, not the key-data pointers loaded from
        # descriptors. No later mutation/escape may hide after setup frontiers.
        names = {self.keys}
        changed = True
        while changed:
            changed = False
            for lines in self.graph.values():
                for line in lines:
                    match = re.fullmatch(rf"({VALUE}) = (?:getelementptr|phi ptr|select .* ptr|ptrtoint|inttoptr).*", line)
                    if match and match[1] not in names and set(re.findall(VALUE, line)[1:]) & names:
                        names.add(match[1]); changed = True
        before = normalization.transport.errors.ancestors(self.graph, {site[0] for site in self.digest} | {site[0] for site in self.frontiers})
        after_setup = set().union(*(phases.handoff.reachable(self.graph, site[0]) for site, kind in self.frontiers.items()
                                   if kind in ("scalar", "simd")))
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                if not set(re.findall(VALUE, line)) & names or (label, index) in self.visited | self.digest:
                    continue
                # LLVM's unrolled AArch64 loop retains a remainder prologue
                # that no checked 4/8-lane shape enters. Only pure address
                # calculations/reads before backend setup may be unvisited;
                # writes, escapes and all post-setup uses still reject. This
                # is scenario coverage, not proof for arbitrary future shapes.
                if label not in after_setup and re.fullmatch(
                    rf"{VALUE} = (?:getelementptr .*|phi ptr .*|load ptr, ptr {VALUE}, align 8(?:, !.*)?)", line):
                    continue
                call = syntax.call(line)
                require(label not in before and call and call[0] == "llvm.lifetime.end.p0"
                        and syntax.operand(call[1][-1]) == self.keys, "normalization key array changed/escaped after shape selection")


def validate(fixture, llvm):
    require(hashlib.sha256((phases.rows.contracts.ROOT / SOURCE).read_bytes()).hexdigest() == DIGEST,
            "key constructor semantic premise changed")
    check = Check(fixture, llvm)
    for backend in (0, 1):
        for mask in range(256):
            check.run(tuple(65 + lane * 17 if mask & (1 << lane) else 64 for lane in range(8)), backend=backend)
            check.run(tuple(65 + lane * 17 for lane in range(8)), mask, backend)
        for lane in range(8):
            for length in (0, 1, 63, 64, 65, (1 << 61) - 1, 1 << 61):
                shape = [65 + at * 17 for at in range(8)]
                shape[lane] = length
                check.run(tuple(shape), backend=backend)
            check.run((65,) * 8, backend=backend, failure=lane)
    require(check.routes == {"none", "scalar", "simd", "error"}, "key routing coverage is vacuous")
    check.preservation()
    return check
