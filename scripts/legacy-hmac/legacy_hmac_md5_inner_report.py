"""Conditional inner-report admission against real selection/input loads.

All activity masks are conditional on reaching the inner digest. This is not
whole-caller eligibility, report return transport, primitive correctness or
quarantine qualification. Unknown instructions fail, rather than supply facts.
"""
import re

import legacy_hmac_md5_inner_owner as owner
import legacy_hmac_md5_reports as reports

n, phases, flow, syntax, require, VALUE = owner.n, owner.phases, owner.flow, owner.syntax, owner.require, owner.VALUE
Bits, Pointer, Memory = owner.Bits, owner.Pointer, owner.Memory
ATOM = n.transport.ATOM


def selection_layout(llvm):
    """Bind the borrowed selection's backend byte to the actual constructor."""
    definitions, aliases = flow.definitions_and_aliases(llvm)
    signature, body = phases.rows.method(definitions, aliases, "with_tag_length")[1]
    params = syntax.parameters(signature)
    require(syntax.operand(params[0]) == "%_0" and syntax.operand(params[1]) == "%executor",
            "inner report selection constructor parameters changed")
    pointers = syntax.pointers(body, ("%_0", "%executor"))
    graph, backend, stores = flow.blocks(body), {}, []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            load = re.fullmatch(rf"({VALUE}) = load i8, ptr ({VALUE}), align \d+(?:, !.*)?", line)
            store = re.fullmatch(rf"store i8 ({VALUE}), ptr ({VALUE}), align 8(?:, !.*)?", line)
            if load and pointers.get(load[2]) == ("%executor", 9):
                backend[load[1]] = (label, index)
            if store and store[1] in backend and pointers.get(store[2], (None,))[0] == "%_0":
                phases.dominates(graph, backend[store[1]], (label, index))
                stores.append(pointers[store[2]][1])
    require(len(backend) == 1 and stores == [16], "selection backend no longer stored from executor byte")
    # The layout witness must not coexist with a second, conflicting write or
    # an escaping output alias. The error niche (2) is not a successful backend.
    output = {name for name, address in pointers.items() if address[0] == "%_0"}
    for lines in graph.values():
        for line in lines:
            if not set(re.findall(VALUE, line)) & output:
                continue
            gep = re.fullmatch(rf"({VALUE}) = getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", line)
            store = re.fullmatch(rf"store (i8|i64|ptr) ({VALUE}|\d+), ptr ({VALUE}), align \d+(?:, !.*)?", line)
            if gep:
                require(gep[1] in output, "selection output alias is unbound")
                continue
            require(store and store[3] in output and store[2] not in output,
                    "selection output escaped or gained an unreviewed effect")
            offset = pointers[store[3]][1]
            require((offset == 0 and store[1] in ("i8", "ptr")) or
                    (offset == 8 and store[1] == "i64") or
                    (offset == 16 and store[1] == "i8" and store[2] in (*backend, "2")),
                    "selection output overlaps or substitutes the backend")
    return stores[0]


class State(n.transport.State):
    def __init__(self, check, start, memory):
        super().__init__(check, start, memory)
        self.memory.sizes.update({check.inputs: 384, check.selection: 24})
        self.values.update({check.inputs: Pointer(check.inputs), check.selection: Pointer(check.selection)})
        self.memory.store(Pointer(check.selection, check.backend_offset), Bits.integer(check.selected_backend, 8))
        for lane in range(8):
            self.memory.store(Pointer(check.inputs, 48 * lane),
                              Pointer("key" + str(lane)) if check.mask & (1 << lane) else Bits.integer(0, 64))
        self.visiting = set()

    def value(self, text, dtype):
        if text.startswith("%") and text not in self.values:
            require(text in self.check.defs and text not in self.visiting, "unknown/cyclic inner-report predecessor")
            site, line = self.check.defs[text]
            if site not in self.check.predecessors:
                phases.dominates(self.check.graph, site, self.start)
            self.visiting.add(text)
            self.values[text] = self.predecessor(line.split(" = ", 1)[1])
            self.visiting.remove(text)
            self.check.predecessors.add(site)
        return super().value(text, dtype)

    def predecessor(self, expression):
        gep = re.fullmatch(rf"getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", expression)
        load = re.fullmatch(rf"load (ptr|i8), ptr ({VALUE}), align \d+(?:, !.*)?", expression)
        compare = re.fullmatch(rf"icmp (eq|ne) ptr ({VALUE}), null", expression)
        add = re.fullmatch(rf"add(?: nuw)?(?: nsw)? i64 ({ATOM}), ({ATOM})", expression)
        if gep:
            base = self.value(gep[1], "ptr")
            require(isinstance(base, Pointer), "unbound inner-report predecessor address")
            pointer = Pointer(base.root, base.offset + int(gep[2]))
            self.memory.bounds(pointer, 0)
            return pointer
        if load:
            pointer = self.address(load[2])
            require((load[1] == "ptr" and pointer.root == self.check.inputs and pointer.offset % 48 == 0)
                    or (load[1] == "i8" and pointer == Pointer(self.check.selection, self.check.backend_offset)),
                    "inner-report predecessor reads unrelated or mutable storage")
            return self.memory.load(pointer, load[1])
        if compare:
            pointer = self.value(compare[2], "ptr")
            require(isinstance(pointer, Pointer) or pointer == Bits.integer(0, 64), "unknown activity pointer")
            return Bits.integer(int((pointer == Bits.integer(0, 64)) == (compare[1] == "eq")), 1)
        if add:
            left, right = (self.value(name, "i64").number() for name in add.groups())
            require(left is not None and right is not None and left + right < 2 ** 64,
                    "unknown/overflowing inner activity sum")
            return Bits.integer(left + right, 64)
        # Restrict lazy evaluation to pure scalar expressions. In particular,
        # no unbound call, phi, payload load or invented predecessor is allowed.
        require(expression.startswith(("zext ", "trunc ", "select ", "and ", "or ", "shl ", "lshr ", "icmp ")),
                "unsupported inner-report predecessor: " + expression)
        return self.expression(expression)


class Check(owner.Check):
    def __init__(self, signature, body, llvm):
        super().__init__(signature, body, llvm)
        params = syntax.parameters(signature)
        self.selection, self.inputs = (syntax.operand(p) for p in params[1:3])
        require(all("noalias" in p and "readonly" in p for p in params[1:3])
                and "dereferenceable(24)" in params[1] and "dereferenceable(384)" in params[2],
                "inner report selection/input immutable borrows changed")
        self.backend_offset = selection_layout(llvm)
        self.predecessors, self.scenarios = set(), 0

    def run_report(self, mask, backend, *, width=None, active=None, vector=None, reported_backend=None):
        self.mask, self.selected_backend = mask, backend
        lane_width = 8 if backend == 0 else 4
        width = lane_width if width is None else width
        active = mask.bit_count() if active is None else active
        vector = lane_width if vector is None else vector
        reported_backend = backend if reported_backend is None else reported_backend
        memory = Memory({"result": 56})
        for offset, value in ((0, Pointer("returned-owner")), (8, Bits.token("returned-length")),
                              (16, Bits.integer(width, 64)), (24, Bits.integer(active, 64)),
                              (32, Bits.token("scalar-blocks")), (40, Bits.integer(vector, 64)),
                              (48, Bits.integer(reported_backend, 8))):
            memory.store(Pointer("result", offset), value)
        payload = Bits(tuple(bit for byte in range(56) for bit in memory.cells.get(("result", byte), (None,) * 8)))
        expected = width == lane_width and active == mask.bit_count() and vector >= lane_width and reported_backend == backend
        self.scenarios += 1
        return n.transport.walk(self, self.site, payload, expected, None, optional_owner=False, state_type=State)


def validate(fixture, llvm):
    n.results.fence.validate_source()
    reports.probes(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation in ("authenticate", "authenticate_secret", "verify"):
        check = Check(*phases.rows.method(definitions, aliases, operation)[1], llvm)
        for backend in (0, 1):
            width = 8 if backend == 0 else 4
            for mask in range(256):
                check.run_report(mask, backend)
                check.run_report(mask, backend, active=(mask.bit_count() + 1) % 9)
            for mask in (0, 15, 240, 255):
                for count in (0, width - 1, width, width + 1, 2 ** 64 - 1):
                    check.run_report(mask, backend, vector=count)
                for count in (0, 4, 8, 16, 2 ** 64 - 1):
                    check.run_report(mask, backend, width=count)
                for value in (0, 1, 2):
                    check.run_report(mask, backend, reported_backend=value)
                check.run_report(mask, backend, active=2 ** 64 - 1)
        checks.append(check)
    return checks
