"""Bind scalar/SIMD normalization outputs and returned owner transport.

Backend digest correctness and owner creation are contracts of the unchanged
hash primitives. Key descriptor construction/route selection and the no-long-key
path are separate obligations. Unknown report metadata explores both branches.
"""
import re

import legacy_hmac_md5_normalization_flow as transport
import legacy_hmac_md5_pads as pads

phases, results, bits = transport.phases, transport.results, transport.bits
flow, syntax, require, VALUE = transport.flow, transport.syntax, transport.require, transport.VALUE
Bits, Pointer = bits.Bits, bits.Pointer


def primitive(symbol, scalar):
    path = (r"NtCs\w+_17brynja_legacy_md55batchNtB\w+_16HardenedMd5Batch" if scalar else
            r"NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_5Batch")
    old = "17brynja_legacy_md55batch" + ("16HardenedMd5Batch" if scalar else "18hardened_execution8in_place5Batch")
    return bool(re.fullmatch(r"_RNvMs0_" + path + r"13digest_secret|_ZN" + old + r"13digest_secret17h[0-9a-f]+E", symbol))


def layouts(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    for name, expected, copy in (
        ("normalized_scalar_success", {0: "i8 0", 8: "ptr %region.0", 16: "i64 %region.1"}, (24, 24)),
        ("normalized_scalar_error", {0: "i8 1", 1: "i8 %error"}, None),
        ("normalized_simd_success", {0: "ptr %region.0", 8: "i64 %region.1"}, (16, 40)),
    ):
        body = pads.descriptors.admission.probe(definitions, aliases, name)
        graph = flow.blocks(body)
        require(len(graph) == 1, "normalization Result probe gained control flow")
        lines = next(iter(graph.values()))
        require(lines[-1] == "ret void", "normalization Result probe does not return")
        pointers, stores, copies = syntax.pointers(body, ("%_0",)), {}, []
        for line in lines[:-1]:
            gep = re.fullmatch(pads.descriptors.GEP, line)
            store = re.fullmatch(rf"store ((?:ptr|i8|i64) (?:{VALUE}|\d+)), ptr ({VALUE}), align [18]", line)
            call = syntax.call(line)
            if gep:
                require(pointers.get(gep[1], (None,))[0] == "%_0", "normalization probe address changed")
            elif store:
                root, offset = pointers.get(store[2], (None, None))
                require(root == "%_0" and offset not in stores, "normalization probe store aliases/escapes")
                stores[offset] = store[1]
            elif call and call[0] == "llvm.memcpy.p0.p0.i64":
                args = call[1]
                require(copy and len(args) == 4 and args[2:] == ["i64 " + str(copy[1]), "i1 false"]
                        and syntax.operand(args[1]) == "%report", "normalization report probe changed")
                copies.append(pointers.get(syntax.operand(args[0])))
            else:
                require(False, "unparsed normalization Result probe")
        require(stores == expected and copies == ([("%_0", copy[0])] if copy else []),
                "normalization Result layout changed: " + name)
    return results.rejection(fixture)


def scope_binding(check):
    """Account for every Scope address use that can precede the digest call."""
    target = check.calls["simd"]
    before = transport.errors.ancestors(check.graph, {target[0]})
    pointers = {name: value for name, value in syntax.pointers(check.body, (check.scope,)).items()
                if value[0] == check.scope}
    stores, starts = {}, []
    for label, lines in check.graph.items():
        if label not in before:
            continue
        for index, line in enumerate(lines):
            if label == target[0] and index >= target[1]:
                break
            if not set(re.findall(VALUE, line)) & pointers.keys():
                continue
            if line == check.scope + " = alloca [16 x i8], align 8":
                continue
            gep = re.fullmatch(pads.descriptors.GEP, line)
            if gep:
                require(pointers.get(gep[1]) == (check.scope, 8), "normalization Scope offset changed")
                phases.dominates(check.graph, (label, index), target)
                continue
            call = syntax.call(line)
            if call:
                require(call[0] == "llvm.lifetime.start.p0" and len(call[1]) in (1, 2)
                        and syntax.operand(call[1][-1]) == check.scope
                        and (len(call[1]) == 1 or call[1][0] == "i64 16"),
                        "normalization Scope escapes/expires before digest")
                starts.append((label, index))
                continue
            store = re.fullmatch(rf"store (ptr {re.escape(check.workspace)}|i8 0), ptr ({VALUE}), align 8(?:, !.*)?", line)
            require(store and store[2] in pointers, "unreviewed normalization Scope setup effect")
            offset = pointers[store[2]][1]
            require(offset not in stores and {0: "ptr " + check.workspace, 8: "i8 0"}.get(offset) == store[1],
                    "normalization Scope field overwritten/rebound")
            stores[offset] = (label, index)
    require(set(stores) == {0, 8} and len(starts) == 1, "incomplete normalization Scope setup")
    for site in stores.values():
        phases.dominates(check.graph, starts[0], site)
        phases.dominates(check.graph, site, target)


class Check:
    def __init__(self, signature, body, llvm, fixture):
        after = pads.Check(signature, body, llvm, pads.probes(fixture))
        self.graph, self.body = after.graph, body
        self.allocs = phases.allocations(body)
        self.owner, self.stop = after.owner, after.start
        self.output = phases.owner(self.allocs, "normalized", 128)
        self.secret = phases.owner(self.allocs, "secret", 16)
        self.scope = phases.owner(self.allocs, "scope", 16)
        self.keys = phases.owner(self.allocs, "keys", 256)
        params = syntax.parameters(signature)
        self.workspace, self.control = (syntax.operand(arg) for arg in params[4:])
        backend = re.fullmatch(rf"i8 ({VALUE})", params[1])
        require(backend, "normalization selection field changed")
        self.selection = backend[1]
        self.calls = {kind: phases.one(body, lambda name, args, kind=kind: primitive(name, kind == "scalar"), kind)
                      for kind in ("scalar", "simd")}
        for kind, site in self.calls.items():
            args = [syntax.operand(arg) for arg in site[3]]
            require(len(args) == 5 and args[2:] == [self.keys, self.output, self.control]
                    and self.allocs.get(args[0]) == (48 if kind == "scalar" else 56),
                    "normalization digest input/output/result identity changed")
            require(self.allocs.get(args[1]) == 904 if kind == "scalar" else args[1] == self.workspace,
                    "normalization digest owner/workspace changed")
        # Scope's destructor clears only this distinct workspace, not the
        # separately borrowed normalization destination (source-bound premise).
        scope_binding(self)
        self.defs = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                definition = re.match(rf"({VALUE}) = ", line)
                if definition:
                    require(definition[1] not in self.defs, "duplicate normalization SSA definition")
                    self.defs[definition[1]] = ((label, index), line)
        self.visited = set()

    def run(self, kind, backend=0, error=None, error_tag=None, selection=None):
        scalar = kind == "scalar"
        extent = 48 if scalar else 56
        data = bits.Memory({"result": extent})
        if error is None:
            offset = 8 if scalar else 0
            data.store(Pointer("result", offset), Pointer("returned-owner"))
            data.store(Pointer("result", offset + 8), Bits.token("returned-length"))
            data.store(Pointer("result", 0 if scalar else 48), Bits.integer(0 if scalar else backend, 8))
        else:
            payload = Bits.unknown(8) if error == "unknown" else Bits.integer(error, 8)
            data.store(Pointer("result"), Bits.integer(1, 8) if scalar else payload)
            if scalar:
                data.store(Pointer("result", 1), payload)
            else:
                data.store(Pointer("result", 48), Bits.integer(error_tag, 8))
        actual_selection = backend if selection is None else selection
        expected = error is None and (scalar or backend in (0, 1) and backend == actual_selection)
        value = Bits(tuple(bit for byte in range(extent) for bit in data.cells.get(("result", byte), (None,) * 8)))
        return transport.walk(self, self.calls[kind], value, expected, actual_selection)


def validate(fixture, llvm):
    results.fence.validate_source()
    pads.probes(fixture)
    error_tag = layouts(fixture)
    definitions, _ = flow.definitions_and_aliases(llvm)
    found = [value for name, value in definitions.items() if phases.identity(name, "pads")]
    require(len(found) == 1, "normalization helper missing/repeated")
    check = Check(*found[0], llvm, fixture)
    check.run("scalar")
    for error in (*range(5), "unknown"):
        check.run("scalar", error=error)
    for backend in (0, 1):
        check.run("simd", backend=backend)
        check.run("simd", backend=backend, selection=1 - backend)
        check.run("simd", backend=2, selection=backend)
    for error in (*range(4), "unknown"):
        check.run("simd", error=error, error_tag=error_tag)
    return check
