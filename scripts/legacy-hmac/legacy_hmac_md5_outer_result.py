"""Outer nested-Result admission and owner transport to truncation.

Conditional on the source-bound outer primitive/helper contract. No primitive
correctness, final public/secret output or quarantine claim is made here.
"""
import re

import legacy_hmac_md5_inner_report as inner

n, phases, flow, syntax, require, VALUE = inner.n, inner.phases, inner.flow, inner.syntax, inner.require, inner.VALUE
Bits, Pointer, Memory = inner.Bits, inner.Pointer, inner.Memory


def layouts(fixture):
    """Independent emitted constructors bind nested success and both errors."""
    definitions, aliases = flow.definitions_and_aliases(fixture)
    original = n.pads.descriptors.admission.probe(definitions, aliases, 'normalized_simd_success')
    success = n.pads.descriptors.admission.probe(definitions, aliases, 'outer_success')
    # Reuse the layout parser, not an instruction-text equality assumption.
    inner.reports.probes(fixture.replace(original, success, 1))
    tags = []
    for name in ('outer_inner_error', 'outer_scope_error'):
        body = n.pads.descriptors.admission.probe(definitions, aliases, name)
        graph, stores = flow.blocks(body), {}
        pointers = syntax.pointers(body, ('%_0',))
        require(len(graph) == 1, 'outer error probe gained control flow')
        lines = next(iter(graph.values()))
        require(lines[-1] == 'ret void', 'outer error probe does not return')
        for line in lines[:-1]:
            gep = re.fullmatch(n.pads.descriptors.GEP, line)
            store = re.fullmatch(rf'store i8 ({VALUE}|-?\d+), ptr ({VALUE}), align [18]', line)
            if gep:
                require(pointers.get(gep[1], (None,))[0] == '%_0', 'outer probe address changed')
            else:
                require(store and pointers.get(store[2], (None,))[0] == '%_0', 'unparsed outer error probe')
                offset = pointers[store[2]][1]
                require(offset not in stores, 'duplicate outer error field')
                stores[offset] = store[1]
        require(set(stores) == {0, 1, 48} and stores[0] == '%error.0' and stores[1] == '%error.1'
                and re.fullmatch(r'-?\d+', stores[48]), 'outer error layout changed')
        tags.append(int(stores[48]) % 256)
    require(tags in ([3, 4], [255, 254]), 'outer nested error niches changed')
    return tags


class State(inner.State):
    def value(self, text, dtype):
        if text.startswith('%') and text not in self.values and text in self.check.prior:
            require(text in self.check.defs, 'unbound accepted inner SSA value')
            if text not in self.check.carried:
                phases.dominates(self.check.graph, self.check.defs[text][0], self.start)
                self.check.carried.add(text)
            self.values[text] = self.check.prior[text]
        return super().value(text, dtype)


class Check(inner.Check):
    state_type = State

    def __init__(self, signature, body, llvm):
        super().__init__(signature, body, llvm)
        self.inner = inner.Check(signature, body, llvm)
        self.prior, self.prior_key, self.carried = {}, None, set()
        self.site = n.results.sites(body)[-1]
        self.result, workspace, self.capture = (syntax.operand(a) for a in self.site[3])
        require(workspace == self.workspace and self.allocs.get(self.result) == 56,
                'outer result/workspace geometry changed')
        self.start = n.results.continuation(self.graph, self.site)[0]
        self.owner = phases.owner(self.allocs, 'tags', 16)
        self.output = phases.owner(self.allocs, 'final_tags', 128)
        self.truncated = phases.owner(self.allocs, 'truncated', 128)
        stop = phases.one(body, lambda name, args: name == 'llvm.lifetime.start.p0' and
                          syntax.operand(args[-1]) == self.truncated, 'truncation lifetime')
        require(stop[1] == 0, 'outer result stop moved inside block')
        self.stop, self.scope, self.secret = stop[0], None, self.owner
        self.visited, self.predecessors = set(), set()

    def prepare(self, mask, backend):
        if self.prior_key == (mask, backend):
            return
        states = []
        self.inner.run_report(mask, backend, vector=Bits.token('inner-vector'),
                              on_entry=lambda state: states.append(dict(state.values)))
        require(states and all(state == states[0] for state in states), 'ambiguous accepted inner predecessor')
        self.prior, self.prior_key = states[0], (mask, backend)

    def run_report(self, mask, backend, **kwargs):
        self.prepare(mask, backend)
        return super().run_report(mask, backend, **kwargs)

    def error(self, tag, error):
        self.mask, self.selected_backend = 255, 0
        self.prepare(255, 0)
        memory = Memory({'result': 56})
        memory.store(Pointer('result'), Bits.unknown(16) if error is None else Bits.integer(error, 16))
        memory.store(Pointer('result', 48), Bits.integer(tag, 8))
        payload = Bits(tuple(bit for i in range(56) for bit in memory.cells.get(('result', i), (None,) * 8)))
        return n.transport.walk(self, self.site, payload, False, None, optional_owner=False, state_type=State)


def validate(fixture, llvm):
    tags = layouts(fixture)
    n.results.fence.validate_source()
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation in ('authenticate', 'authenticate_secret', 'verify'):
        check = Check(*phases.rows.method(definitions, aliases, operation)[1], llvm)
        for backend in (0, 1):
            width = 8 if backend == 0 else 4
            for mask in range(256):
                check.run_report(mask, backend)
                check.run_report(mask, backend, active=(mask.bit_count() + 1) % 9)
            for mask in (0, 15, 240, 255):
                for value in (0, width - 1, width, width + 1, 2**64 - 1):
                    check.run_report(mask, backend, vector=value)
                for value in (0, 4, 8, 16, 2**64 - 1):
                    check.run_report(mask, backend, width=value)
                for value in (0, 1, 2):
                    check.run_report(mask, backend, reported_backend=value)
                check.run_report(mask, backend, active=2**64 - 1)
        for tag in tags:
            for error in (0, 1, 2, 3, None):
                check.error(tag, error)
        checks.append(check)
    return checks
