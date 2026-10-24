"""Bind inner digest Result ownership through the actual outer-loop entry.

The unchanged digest's valid returned region is a source-bound premise. This
checks pointer/length transport without assuming either value or report fields.
Unknown report predicates explore both edges; report acceptance and transport,
final output ownership and quarantine remain separate obligations.
"""
import re

import legacy_hmac_md5_normalization as normalization
import legacy_hmac_md5_outer as outer

n = normalization
flow, syntax, phases, require, VALUE = n.flow, n.syntax, n.phases, n.require, n.VALUE
Bits, Pointer, Memory = n.bits.Bits, n.bits.Pointer, n.bits.Memory


class Check:
    def __init__(self, signature, body, llvm):
        downstream = outer.Check(signature, body, llvm)
        self.body, self.graph, self.allocs = body, downstream.graph, downstream.allocs
        _, self.site, _ = n.results.sites(body)
        self.start, _ = n.results.continuation(self.graph, self.site)
        require(downstream.start[1] == 0, "inner owner handoff stop moved inside block")
        self.stop, self.owner = downstream.start[0], downstream.owner
        args = [syntax.operand(arg) for arg in self.site[3]]
        require(len(args) == 6, "inner digest arity changed")
        self.result, self.workspace, _, _, self.output, _ = args
        require(self.allocs.get(self.result) == 56 and self.allocs.get(self.workspace) == 912
                and self.output == phases.owner(self.allocs, "inner", 128),
                "inner result/workspace/output allocation changed")
        reachable = phases.handoff.reachable(self.graph, self.start[0])
        relevant = n.transport.errors.ancestors(self.graph, {self.stop})
        drops = [site for site in phases.calls(body, lambda name, args: n.results.fence.identity(name, "drop"))
                 if site[0] in reachable & relevant]
        require(len(drops) == 1 and len(drops[0][3]) == 1, "inner handoff Scope destructor missing/repeated")
        self.scope = syntax.operand(drops[0][3][0])
        require(self.allocs.get(self.scope) == 16, "inner Scope allocation changed")
        self.calls = {"simd": self.site}
        n.scope_binding(self)
        # Reuse the fail-closed handoff evaluator. Only this owner and Scope
        # may be written; no unrelated scratch owner is granted write access.
        self.secret = self.owner
        self.defs = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                match = re.match(rf"({VALUE}) = ", line)
                if match:
                    require(match[1] not in self.defs, "duplicate inner handoff SSA definition")
                    self.defs[match[1]] = ((label, index), line)
        self.visited = set()

    def run(self, backend=0, error_tag=None, error=None):
        data = Memory({"result": 56})
        if error_tag is None:
            data.store(Pointer("result"), Pointer("returned-owner"))
            data.store(Pointer("result", 8), Bits.token("returned-length"))
            data.store(Pointer("result", 48), Bits.integer(backend, 8))
        else:
            data.store(Pointer("result"), Bits.unknown(8) if error is None else Bits.integer(error, 8))
            data.store(Pointer("result", 48), Bits.integer(error_tag, 8))
        payload = Bits(tuple(bit for byte in range(56) for bit in data.cells.get(("result", byte), (None,) * 8)))
        return n.transport.walk(self, self.site, payload, error_tag is None and backend in (0, 1),
                                None, optional_owner=False)


def validate(fixture, llvm):
    n.results.fence.validate_source()
    error_tag = n.layouts(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation in ("authenticate", "authenticate_secret", "verify"):
        check = Check(*phases.rows.method(definitions, aliases, operation)[1], llvm)
        for backend in (0, 1, 2):
            check.run(backend)
        for error in (*range(4), None):
            check.run(error_tag=error_tag, error=error)
        checks.append(check)
    return checks
