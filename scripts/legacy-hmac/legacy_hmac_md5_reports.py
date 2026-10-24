"""Normalization report guard scenarios and conditional success transport.

Independent ABI probes bind field meanings. Actual key-shape execution supplies
the expected active count and width; no report field is assumed correct merely
because a digest succeeded. Transport checks stop at the pad-loop entry and use
immutable SSA to bind its eventual success stores. Pad-loop behavior, digest
semantics and cleanup remain separate premises, not whole-caller qualification.
"""
import re

import legacy_hmac_md5_keys as keys

n = keys.normalization
flow, syntax, require, VALUE = n.flow, n.syntax, n.require, n.VALUE
Bits, Pointer, Memory = n.bits.Bits, n.bits.Pointer, n.bits.Memory


def probes(fixture):
    n.layouts(fixture)
    definitions, aliases = flow.definitions_and_aliases(fixture)
    for name, wanted, copied in (
        ("work_report", {0: "i64 %active", 8: "i64 %scalar", 16: "i64 %vector"}, None),
        ("execution_report", {0: "i64 %width", 32: "i8 %backend"}, (8, 24)),
    ):
        body = n.pads.descriptors.admission.probe(definitions, aliases, name)
        graph, stores, copies = flow.blocks(body), {}, []
        require(len(graph) == 1, "normalization report probe gained control flow")
        pointers = syntax.pointers(body, ("%_0",))
        lines = next(iter(graph.values()))
        require(lines[-1] == "ret void", "normalization report probe lacks return")
        for line in lines[:-1]:
            store = re.fullmatch(rf"store ((?:i8|i64) {VALUE}), ptr ({VALUE}), align 8", line)
            call = syntax.call(line)
            if re.fullmatch(n.pads.descriptors.GEP, line):
                require(pointers.get(line.split(" = ")[0], (None,))[0] == "%_0", "report probe address changed")
            elif store:
                root, offset = pointers.get(store[2], (None, None))
                require(root == "%_0" and offset not in stores, "report probe write aliases/escapes")
                stores[offset] = store[1]
            elif call and call[0] == "llvm.memcpy.p0.p0.i64":
                args = call[1]
                require(copied and len(args) == 4 and args[2:] == ["i64 24", "i1 false"]
                        and syntax.operand(args[1]) == "%work", "report probe work copy changed")
                copies.append(pointers.get(syntax.operand(args[0])))
            else:
                require(False, "unparsed normalization report probe")
        require(stores == wanted and copies == ([("%_0", copied[0])] if copied else []),
                "normalization report field ABI changed")


class Check:
    def __init__(self, fixture, llvm):
        probes(fixture)
        self.keys = keys.Check(fixture, llvm)
        definitions, _ = flow.definitions_and_aliases(llvm)
        signature, body = next(value for name, value in definitions.items() if n.phases.identity(name, "pads"))
        self.owner = n.Check(signature, body, llvm, fixture)
        pad = n.pads.Check(signature, body, llvm, n.pads.probes(fixture))
        self.success = next(label for label, good in pad.stops.items() if good)
        pointers = {name: address for name, address in syntax.pointers(body, (pad.result,)).items()
                    if address[0] == pad.result}
        stores, self.fields = {}, {}
        self.sites = set()
        for label in n.phases.handoff.reachable(pad.graph, self.success):
            for index, line in enumerate(pad.graph[label]):
                if not set(re.findall(VALUE, line)) & pointers.keys():
                    continue
                gep = re.fullmatch(n.pads.descriptors.GEP, line)
                if gep:
                    require(pointers.get(gep[1], (None,))[0] == pad.result, "result pointer escapes after report success")
                    continue
                store = re.fullmatch(rf"store (i8|i64|<2 x i64>) ({VALUE}|0), ptr ({VALUE}), align 8", line)
                require(label == self.success and store and pointers.get(store[3], (None,))[0] == pad.result,
                        "unreviewed result effect after report success")
                offset = pointers[store[3]][1]
                require(offset not in stores, "report success overwritten")
                stores[offset] = store[1]
                self.sites.add((label, index))
                if offset == 0:
                    require(store[2] == "0", "report success tag changed")
                else:
                    require(store[2] in self.owner.defs, "normalization report replaced by constant")
                    n.phases.dominates(pad.graph, self.owner.defs[store[2]][0], (pad.start, 0))
                    self.fields[offset] = (store[1], store[2])
        require(stores in ({0: "i8", 8: "i64", 16: "<2 x i64>"},
                           {0: "i8", 8: "i64", 16: "i64", 24: "i64"}), "report success fields missing/changed")
        self.scenarios = 0

    def forwarded(self, state, expected):
        encoded = sum((value.data for value in expected), ())
        for offset, (dtype, name) in self.fields.items():
            start = (offset - 8) * 8
            wanted = Bits(encoded[start:start + n.bits.width(dtype)])
            require(state.value(name, dtype) == wanted, "normalization report field lost provenance")

    def run(self, lengths, backend, *, width=None, active=None, vector=None, reported_backend=None):
        before = self.keys.run(lengths, backend=backend)
        long = sum(length > 64 for length in lengths)
        lane_width = 8 if backend == 0 else 4
        kind = "none" if not long else "simd" if any(
            all(length > 64 for length in lengths[start:start + lane_width])
            for start in range(0, 8, lane_width)) else "scalar"
        self.scenarios += 1
        if kind == "none":
            self.forwarded(before, (Bits.integer(0, 64),) * 3)
            return
        scalar = kind == "scalar"
        extent = 48 if scalar else 56
        memory = Memory({"result": extent})
        offset = 8 if scalar else 0
        memory.store(Pointer("result", offset), Pointer("returned-owner"))
        memory.store(Pointer("result", offset + 8), Bits.token("returned-length"))
        scalar_blocks = Bits.token("scalar-blocks")
        if scalar:
            work = (Bits.token("active-lanes"), scalar_blocks, Bits.token("vector-blocks"))
            memory.store(Pointer("result"), Bits.integer(0, 8))
            expected = True
        else:
            width = lane_width if width is None else width
            active = long if active is None else active
            vector = Bits.token("vector-blocks") if vector is None else Bits.integer(vector, 64)
            reported_backend = backend if reported_backend is None else reported_backend
            work = (Bits.integer(active, 64), scalar_blocks, vector)
            memory.store(Pointer("result", 16), Bits.integer(width, 64))
            memory.store(Pointer("result", 48), Bits.integer(reported_backend, 8))
            expected = width == lane_width and active == long and reported_backend == backend and (
                vector.number() is None or vector.number() >= lane_width)
        for index, value in enumerate(work):
            memory.store(Pointer("result", 24 + index * 8), value)
        data = Bits(tuple(bit for byte in range(extent) for bit in memory.cells.get(("result", byte), (None,) * 8)))
        n.transport.walk(self.owner, self.owner.calls[kind], data, expected, backend,
                         seeds=before.values, on_entry=lambda state: self.forwarded(state, work))


def validate(fixture, llvm):
    check = Check(fixture, llvm)
    for backend in (0, 1):
        for mask in range(256):
            shape = tuple(65 + lane if mask & (1 << lane) else 64 for lane in range(8))
            check.run(shape, backend)
        width = 8 if backend == 0 else 4
        for count in range(width, 9):
            shape = (65,) * count + (64,) * (8 - count)
            for actual in (0, 1, 3, 4, 5, 7, 8, 9, (1 << 64) - 1):
                check.run(shape, backend, width=actual)
                check.run(shape, backend, active=actual)
            for blocks in (0, width - 1, width, width + 1, (1 << 64) - 1):
                check.run(shape, backend, vector=blocks)
            for other in (1 - backend, 2):
                check.run(shape, backend, reported_backend=other)
    return check
