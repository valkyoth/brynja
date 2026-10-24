"""Conditional post-normalization MD5 ipad construction in emitted LLVM.

The normalized owner is seeded as a premise: its earlier digest/result binding
is not established here. Nor are outer opad conversion, report return or cleanup.
"""
import hashlib
import re

import legacy_hmac_md5_descriptors as descriptors
import legacy_hmac_md5_pad_model as model

phases = descriptors.phases
flow, syntax, require, VALUE = model.flow, model.syntax, model.require, model.VALUE
PINS = {
    **phases.rows.contracts.PINS,
    "crates/brynja-core/src/secret_memory_transfer.rs": "85f0cef7c2a8508c4d594ad7462bccb92fd8e5bea7897164d7df3ee655dcf3e0",
    "crates/brynja-core/src/secret_memory_xor.rs": "fc6c8a3caccc38c9b45795805b266bec60d2fcd10f1414f654d2e407af9bec7d",
}


def probes(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    def body(name):
        return descriptors.admission.probe(definitions, aliases, name)
    copied = list(flow.blocks(body("copy_success")).values())
    require(copied in ([["ret i8 4"]], [["ret i8 -1"]]), "copy success ABI changed")
    require(list(flow.blocks(body("xor_success")).values()) == [["ret i1 false"]], "XOR success ABI changed")
    expected = {
        "normalized_present": {0: "i64 1", 8: "ptr %region.0", 16: "i64 %region.1"},
        "normalized_absent": {0: "i64 0"},
        "pad_rejection": {0: "i8 1", 1: "i8 2"},
        "pad_success": {0: "i8 0"},
    }
    for name, wanted in expected.items():
        code = body(name)
        graph, stores, clears = flow.blocks(code), {}, []
        require(len(graph) == 1, "pad ABI probe gained control flow")
        pointers = syntax.pointers(code, ("%_0",))
        lines = next(iter(graph.values()))
        require(lines[-1] == "ret void", "pad ABI probe has no return")
        for line in lines[:-1]:
            gep = re.fullmatch(descriptors.GEP, line)
            store = re.fullmatch(rf"store ((?:ptr|i8|i64) (?:{VALUE}|\d+)), ptr ({VALUE}), align [18]", line)
            call = syntax.call(line)
            if gep:
                require(pointers.get(gep[1], (None,))[0] == "%_0", "pad probe GEP changed")
            elif store:
                root, at = pointers.get(store[2], (None, None))
                require(root == "%_0" and at not in stores, "pad probe store aliases/escapes")
                stores[at] = store[1]
            elif call and call[0] == "llvm.memset.p0.i64":
                require(call[1][1:] == ["i8 0", "i64 24", "i1 false"], "pad probe report extent")
                clears.append(pointers.get(syntax.operand(call[1][0])))
            else:
                require(False, "unparsed pad ABI probe")
        require(stores == wanted and clears == ([("%_0", 8)] if name == "pad_success" else []),
                "pad ABI probe layout changed: " + name)
    return int(copied[0][0].split()[-1])


class Check:
    def __init__(self, signature, body, llvm, copy_ok):
        self.body, self.graph, self.copy_ok = body, flow.blocks(body), copy_ok
        params = syntax.parameters(signature)
        require(len(params) == 6 and "readonly" in params[2] and "noalias" in params[2] and
                "dereferenceable(384)" in params[2] and "dereferenceable(512)" in params[3],
                "pad input/output extent or ownership changed")
        self.result, self.inputs, self.pads = [syntax.operand(params[i]) for i in (0, 2, 3)]
        allocs = phases.allocations(body)
        self.owner = phases.owner(allocs, "normalized1", 24)
        self.locals = {name for name, size in allocs.items() if size == 1}
        require(len(self.locals) == 1, "ambiguous pad mask local")
        self.types = {}
        for dtype in set(re.findall(r'getelementptr(?: inbounds)?(?: nuw)? (%"[^"]+"),', body)):
            if dtype == '%"core::option::Option<md5_batch::Input<\'_>>"':
                require(dtype + " = type { ptr, [5 x i64] }" in llvm, "input element geometry changed")
                self.types[dtype] = 48
        row = [(label, index, line) for label, lines in self.graph.items() for index, line in enumerate(lines)
               if re.fullmatch(rf'{VALUE} = getelementptr inbounds(?: nuw)? \[64 x i8\], ptr {re.escape(self.pads)}, i64 {VALUE}', line)]
        require(len(row) == 1, "pad row loop missing/repeated")
        self.start, _, row_line = row[0]
        require([line for line in body.splitlines() if self.pads in re.findall(VALUE, line)] == ["  " + row_line],
                "pad root escapes or is changed outside modeled loop")
        first = self.graph[self.start][0]
        initial = re.findall(r"\[ 0, %" + flow.LABEL + r" \]", first)
        require(" = phi i64 " in first and len(initial) == 1, "pad loop initial cursor changed")
        self.previous = initial[0]
        require(self.graph[self.previous][-1] == "br label %" + self.start, "pad preheader changed")
        pointer_map = syntax.pointers(body, (self.owner,))
        self.pointers = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                gep = re.fullmatch(descriptors.GEP, line)
                if gep and pointer_map.get(gep[1], (None,))[0] == self.owner:
                    # Only pre-loop descriptor addresses may be seeded; never
                    # load or invent the actual normalized digest owner here.
                    if label == self.previous:
                        phases.dominates(self.graph, (label, index), (self.start, 0))
                        self.pointers[gep[1]] = pointer_map[gep[1]]
        require(set(self.pointers.values()) == {(self.owner, 8), (self.owner, 16)}, "normalized field addresses changed")
        self.stops = {}
        result_ptrs = syntax.pointers(body, (self.result,))
        for label, lines in self.graph.items():
            tag = f"store i8 0, ptr {self.result}, align 8"
            if tag in lines:
                self.stops[label] = True
            elif f"store i8 1, ptr {self.result}, align 8" in lines:
                payload = [line for line in lines if (match := re.fullmatch(rf"store i8 2, ptr ({VALUE}), align 1", line))
                           and result_ptrs.get(match[1]) == (self.result, 1)]
                if len(payload) == 1:
                    self.stops[label] = False
        require(sorted(self.stops.values()) == [False, True], "pad loop result frontiers changed")
        self.visited = set()

    def run(self, lengths, mask=255, normalized=(True, True, 128), failure=None):
        state = model.State(self, lengths, mask, normalized, failure)
        success = state.walk()
        self.visited.update(state.sites)
        valid = all(not mask & (1 << lane) or length <= 64 or
                    normalized[0] and normalized[1] and normalized[2] // 16 > lane
                    for lane, length in enumerate(lengths))
        require(success == (valid and failure is None), "pad loop failure/success frontier mismatch")
        if failure is not None:
            require(state.failed and failure in state.calls, "pad fault injection was vacuous")
        if success:
            expected = []
            copies = []
            for lane, length in enumerate(lengths):
                if not mask & (1 << lane):
                    expected.extend([0] * 64)
                    continue
                source, start, size = ("normalized", lane * 16, 16) if length > 64 else ("key" + str(lane), 0, length)
                expected.extend(("xor", (source, start + byte) if byte < size else 0, 54) for byte in range(64))
                if size:
                    copies.append(("copy", lane * 64))
            require(state.bytes == expected, "pad key bytes, zero tail, mask or lane changed")
            require([call for call in state.calls if call[0] == "copy"] == copies, "pad key copy skipped/repeated")
            require([at for op, at in state.calls if op == "xor"] ==
                    [lane * 64 + byte for lane in range(8) if mask & (1 << lane) for byte in range(64)],
                    "pad XOR byte traversal skipped/repeated")
            require(not state.live, "pad mask lifetime left open")
        return state

    def unwind(self):
        for label, index in self.visited:
            line = self.graph[label][index]
            if "invoke " in line:
                edge = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL,
                                    self.graph[label][index + 1])
                require(edge, "pad primitive unwind edge changed")
                reachable = phases.handoff.reachable(self.graph, edge[2])
                require(not reachable & ({self.start} | {label for label, success in self.stops.items() if success}),
                        "pad unwind re-enters work/success")

    def uses(self):
        # No unmodeled branch/frontier may mutate or export pad addresses.
        # Include dependent SSA values conservatively, not just constant GEPs.
        names = {self.pads}
        changed = True
        while changed:
            changed = False
            for lines in self.graph.values():
                for line in lines:
                    definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
                    if definition and definition[1] not in names and set(re.findall(VALUE, definition[2])) & names:
                        names.add(definition[1])
                        changed = True
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                if set(re.findall(VALUE, line)) & names:
                    require((label, index) in self.visited, "unmodeled pad-address use/escape")


def zero_prefixes(llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    for operation in ("authenticate", "authenticate_secret", "verify"):
        _, body = phases.rows.method(definitions, aliases, operation)[1]
        allocs, graph = phases.allocations(body), flow.blocks(body)
        pad = phases.owner(allocs, "pad", 512)
        call = phases.one(body, lambda symbol, args: phases.identity(symbol, "pads"), "pad construction")
        require(syntax.operand(call[3][3]) == pad, "wrong initial pad owner")
        zero = phases.one(body, lambda symbol, args: symbol == "llvm.memset.p0.i64" and
                          syntax.operand(args[0]) == pad, "zero pad initialization")
        require(zero[3][1:] == ["i8 0", "i64 512", "i1 false"], "initial pad is not entirely zero")
        phases.dominates(graph, zero, call)
        pointers = {name for name, (root, _) in syntax.pointers(body, (pad,)).items() if root == pad}
        for label, lines in graph.items():
            for index, line in enumerate(lines):
                if not set(re.findall(VALUE, line)) & pointers or (label, index) in (zero[:2], call[:2]):
                    continue
                if label == call[0] and index > call[1] or label != call[0] and call[0] not in phases.handoff.reachable(graph, label):
                    continue
                invocation = syntax.call(line)
                require(line.startswith(pad + " = alloca ") or re.fullmatch(descriptors.GEP, line) or
                        invocation and invocation[0] == "llvm.lifetime.start.p0" and syntax.operand(invocation[1][-1]) == pad,
                        "initial zero pad overwritten/escaped before construction")


def validate(fixture, llvm):
    for name, digest in PINS.items():
        require(hashlib.sha256((phases.rows.contracts.ROOT / name).read_bytes()).hexdigest() == digest,
                "pad primitive semantic premise changed: " + name)
    descriptors.layout(fixture)
    copy_ok = probes(fixture)
    zero_prefixes(llvm)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    found = [value for name, value in definitions.items() if phases.identity(name, "pads")]
    require(len(found) == 1, "pad construction helper missing/repeated")
    check = Check(*found[0], llvm, copy_ok)
    for seed in range(65):
        check.run(tuple((seed + lane * 7) % 65 for lane in range(8)))
    lengths = (0, 1, 63, 64, 65, 129, 1024, (1 << 61) - 1)
    for mask in range(256):
        check.run(lengths, mask)
    for lane in range(8):
        for normalized in ((False, False, 0), (True, False, 128), (True, True, lane * 16),
                           (True, True, lane * 16 + 15), (True, True, (lane + 1) * 16)):
            check.run((65,) * 8, 1 << lane, normalized)
        check.run((1,) * 8, 1 << lane, failure=("copy", lane * 64))
        for byte in (0, 31, 63):
            check.run((1,) * 8, 1 << lane, failure=("xor", lane * 64 + byte))
    check.unwind()
    check.uses()
    return check
