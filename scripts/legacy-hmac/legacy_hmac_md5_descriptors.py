"""Trace input message bytes into eight inner descriptors in actual LLVM.

All 256 activity masks are checked conditional on reaching construction. This
does not qualify pad contents, outer descriptors, output ownership or cleanup.
Unknown instructions and escaping descriptor addresses fail closed.
"""
import re

import legacy_hmac_md5_admission as admission
import legacy_hmac_md5_phases as phases

flow, syntax, require = phases.flow, phases.syntax, phases.require
VALUE = phases.VALUE
GEP = rf"({VALUE}) = getelementptr (?:inbounds )?(?:nuw )?i8, ptr ({VALUE}), i64 (-?\d+)"
LOAD = rf"({VALUE}) = load ptr, ptr ({VALUE}), align 8(?:, !.*)?"
CMP = rf"({VALUE}) = icmp (eq|ne) ptr ({VALUE}), null"


def layout(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    for name in ("absent_input", "absent_message"):
        body = admission.probe(definitions, aliases, name)
        require(list(flow.blocks(body).values()) == [["store ptr null, ptr %_0, align 8", "ret void"]],
                "MD5 descriptor null niche changed")
    for name, offset in (("input_descriptor", 16), ("message_descriptor", 0)):
        body = admission.probe(definitions, aliases, name)
        graph = flow.blocks(body)
        require(len(graph) == 1, "descriptor layout probe gained control flow")
        pointers = syntax.pointers(body, ("%_0", "%message"))
        stores, copies = {}, []
        for line in next(iter(graph.values())):
            if re.fullmatch(GEP, line) or line == "ret void":
                continue
            store = re.fullmatch(rf"store (ptr %key.0|i64 %key.1), ptr ({VALUE}), align 8", line)
            call = syntax.call(line)
            if store:
                root, at = pointers.get(store[2], (None, None))
                require(root == "%_0" and at not in stores, "descriptor layout store changed")
                stores[at] = store[1]
            elif call and call[0] == "llvm.memcpy.p0.p0.i64":
                args = call[1]
                require(len(args) == 4 and args[2:] == ["i64 32", "i1 false"], "descriptor copy extent changed")
                copies.append((pointers.get(syntax.operand(args[0])), syntax.operand(args[1])))
            else:
                require(False, "unknown descriptor layout instruction: " + line)
        require(copies == [(("%_0", offset), "%message")] and
                stores == ({0: "ptr %key.0", 8: "i64 %key.1"} if offset else {}),
                "descriptor layout changed")


class Trace:
    def __init__(self, signature, body):
        self.graph = flow.blocks(body)
        self.allocs = phases.allocations(body)
        inputs = syntax.parameters(signature)[2]
        require(all(token in inputs.split() for token in ("noalias", "readonly", "dereferenceable(384)")),
                "descriptor input is not an immutable disjoint eight-slot borrow")
        self.inputs = syntax.operand(inputs)
        self.messages = phases.owner(self.allocs, "messages", 256)
        self.pointers = syntax.pointers(body, (*self.allocs, self.inputs))
        self.stop = phases.one(body, lambda name, args: phases.identity(name, "pads"), "pads")[:2]
        inner = phases.one(body, lambda name, args: phases.identity(name, "digest"), "inner")
        require(len(inner[3]) == 6 and syntax.operand(inner[3][3]) == self.messages,
                "inner hash does not consume constructed descriptors")
        self.inner = inner[:2]
        starts = phases.calls(body, lambda name, args: name == "llvm.lifetime.start.p0" and
                              syntax.operand(args[-1]) == self.messages)
        require(len(starts) == 1, "descriptor lifetime start missing/repeated")
        self.start = starts[0][:2]
        phases.dominates(self.graph, self.start, self.stop)
        self.defs = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                match = re.match(rf"({VALUE}) = ", line)
                if match:
                    require(match[1] not in self.defs, "repeated descriptor SSA value")
                    self.defs[match[1]] = ((label, index), line)
        self.writes = set()
        self.executed = set()
        self.address_checks = set()
        self.prechecks = set()

    def address(self, name, site):
        if (name, site) in self.address_checks or name == self.inputs:
            return
        require(name in self.defs, "descriptor address without definition")
        definition, line = self.defs[name]
        phases.dominates(self.graph, definition, site)
        gep = re.fullmatch(GEP, line)
        if gep:
            self.address(gep[2], definition)
        else:
            require(name in self.allocs, "unsupported descriptor address definition")
        self.address_checks.add((name, site))

    def region(self, address, size):
        require(address in self.pointers, "unbound descriptor address: " + address)
        root, offset = self.pointers[address]
        extent = 384 if root == self.inputs else self.allocs.get(root, -1)
        require(0 <= offset <= extent and 0 <= size <= extent - offset, "descriptor access out of bounds")
        return root, offset

    def read(self, address, size):
        root, offset = self.region(address, size)
        require(root in self.live, "descriptor read outside lifetime")
        return self.memory[root][offset:offset + size]

    def write(self, address, data, site):
        self.address(address, site)
        root, offset = self.region(address, len(data))
        require(root != self.inputs and root in self.live, "descriptor write outside owned lifetime")
        self.memory[root][offset:offset + len(data)] = data
        self.writes.add(site)

    def value(self, name, visiting=()):
        if name == "null":
            return [0] * 8
        if name in self.values:
            return self.values[name]
        require(name not in visiting and name in self.defs, "unbound/cyclic descriptor predicate")
        site, line = self.defs[name]
        # Only immutable input niche loads/predicates may be evaluated lazily.
        # They must actually dominate construction, not come from a bypassed arm.
        if name not in self.prechecks:
            phases.dominates(self.graph, site, self.start)
            self.prechecks.add(name)
        load, cmp = re.fullmatch(LOAD, line), re.fullmatch(CMP, line)
        if load:
            self.address(load[2], site)
            root, offset = self.region(load[2], 8)
            require(root == self.inputs and offset % 48 == 0, "unexpected preconstruction descriptor load")
            result = self.read(load[2], 8)
        elif cmp:
            pointer = self.value(cmp[3], (*visiting, name))
            require(pointer == [0] * 8 or len(pointer) == 8 and all(isinstance(x, tuple) for x in pointer),
                    "unknown descriptor branch pointer")
            result = (pointer == [0] * 8) == (cmp[2] == "eq")
        else:
            require(False, "unparsed preconstruction descriptor predicate")
        self.values[name] = result
        return result

    def call(self, call, site):
        name, args = call
        if name == "llvm.experimental.noalias.scope.decl":
            require(len(args) == 1 and re.fullmatch(r"metadata !\d+", args[0]), "unknown alias metadata")
        elif name in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
            root = syntax.operand(args[-1])
            self.address(root, site)
            require(root in self.allocs and len(args) in (1, 2) and
                    (len(args) == 1 or args[0] == "i64 " + str(self.allocs[root])), "descriptor lifetime extent")
            self.memory[root] = [None] * self.allocs[root]
            if name == "llvm.lifetime.start.p0":
                require(root not in self.live, "repeated descriptor lifetime")
                self.live.add(root)
            else:
                require(root in self.live and root != self.messages, "premature descriptor lifetime end")
                self.live.remove(root)
        elif name in ("llvm.memcpy.p0.p0.i64", "llvm.memset.p0.i64"):
            require(len(args) == 4 and re.fullmatch(r"i64 \d+", args[2]) and args[3] == "i1 false",
                    "unknown descriptor memory transfer")
            size, dest = int(args[2].split()[1]), syntax.operand(args[0])
            if name.startswith("llvm.memcpy"):
                source = syntax.operand(args[1])
                self.address(source, site)
                sr, so = self.region(source, size)
                dr, do = self.region(dest, size)
                require(sr != dr or so + size <= do or do + size <= so, "overlapping descriptor memcpy")
                data = self.read(source, size)
            else:
                require(args[1] == "i8 0", "nonzero descriptor memset")
                data = [0] * size
            self.write(dest, data, site)
        else:
            require(False, "unknown call during descriptor construction: " + name)

    def run(self, mask):
        self.memory = {name: [None] * size for name, size in self.allocs.items()}
        self.memory[self.inputs] = [("input", n) for n in range(384)]
        for lane in range(8):
            if not mask & (1 << lane):
                self.memory[self.inputs][48 * lane:48 * lane + 8] = [0] * 8
        self.values, self.live = {}, {self.inputs}
        label, index = self.start
        previous, visited = None, set()
        while True:
            require((label, index) not in visited, "cycle in descriptor construction")
            visited.add((label, index))
            require(label in self.graph, "unknown descriptor edge")
            lines = self.graph[label]
            phis = {}
            while index < len(lines) and " = phi ptr " in lines[index]:
                self.executed.add((label, index))
                line = lines[index]
                match = re.fullmatch(rf"({VALUE}) = phi ptr (.*)", line)
                require(match, "unknown descriptor phi")
                edge_pattern = rf"\[ ({VALUE}|null), %{flow.LABEL} \]"
                require(re.fullmatch(edge_pattern + "(?:, " + edge_pattern + ")*", match[2]),
                        "unparsed descriptor phi operand")
                edges = re.findall(edge_pattern, match[2])
                require(len(edges) == match[2].count("[") and len({edge for _, edge in edges}) == len(edges),
                        "malformed descriptor phi")
                selected = [value for value, edge in edges if edge == previous]
                require(len(selected) == 1, "descriptor phi predecessor missing")
                phis[match[1]] = self.value(selected[0])
                index += 1
            self.values.update(phis)
            while index < len(lines):
                site, line = (label, index), lines[index]
                self.executed.add(site)
                if site == self.stop:
                    for lane in range(8):
                        at = lane * 32
                        actual = self.read(self.messages, 256)[at:at + 32]
                        expected = [("input", n) for n in range(lane * 48 + 16, lane * 48 + 48)]
                        require(actual == expected if mask & (1 << lane) else actual[:8] == [0] * 8,
                                f"MD5 input message descriptor changed: mask={mask}; lane={lane}")
                    return
                load, cmp = re.fullmatch(LOAD, line), re.fullmatch(CMP, line)
                store = re.fullmatch(rf"store ptr ({VALUE}|null), ptr ({VALUE}), align 8(?:, !.*)?", line)
                branch = re.fullmatch(rf"br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}", line)
                jump = re.fullmatch(r"br label %" + flow.LABEL, line)
                call = syntax.call(line)
                if re.fullmatch(GEP, line):
                    pass  # fixed addresses are bounds checked at every access
                elif load:
                    self.address(load[2], site)
                    self.values[load[1]] = self.read(load[2], 8)
                elif cmp:
                    pointer = self.value(cmp[3])
                    require(pointer == [0] * 8 or len(pointer) == 8 and all(isinstance(x, tuple) for x in pointer),
                            "unknown descriptor comparison")
                    self.values[cmp[1]] = (pointer == [0] * 8) == (cmp[2] == "eq")
                elif store:
                    self.write(store[2], self.value(store[1]), site)
                elif call:
                    self.call(call, site)
                elif branch or jump:
                    if branch:
                        decision = self.value(branch[1])
                        require(isinstance(decision, bool), "nonboolean descriptor branch")
                        target = branch[2] if decision else branch[3]
                    else:
                        target = jump[1]
                    previous, label, index = label, target, 0
                    break
                else:
                    require(False, "unknown descriptor instruction: " + line)
                index += 1
            else:
                require(False, "descriptor construction bypasses pads")

    def preservation(self):
        names = {name for name, (root, _) in self.pointers.items() if root == self.messages}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                site = label, index
                if not set(re.findall(VALUE, line)) & names:
                    continue
                if site in self.writes or re.fullmatch(GEP, line) or line.startswith(self.messages + " = alloca "):
                    continue
                call = syntax.call(line)
                if call and call[0] in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
                    require(syntax.operand(call[1][-1]) == self.messages, "aliased descriptor lifetime")
                    if call[0] == "llvm.lifetime.end.p0":
                        require(label == self.inner[0] and index > self.inner[1] or
                                label != self.inner[0] and self.inner[0] not in phases.handoff.reachable(self.graph, label),
                                "descriptor dies before inner dispatch")
                    continue
                require(site == self.inner and call and syntax.operand(call[1][3]) == self.messages and
                        sum(syntax.operand(arg) in names for arg in call[1]) == 1,
                        "descriptor mutation/escape outside construction")


def validate(fixture, llvm):
    layout(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    for operation in ("authenticate", "authenticate_secret", "verify"):
        trace = Trace(*phases.rows.method(definitions, aliases, operation)[1])
        for mask in range(256):
            trace.run(mask)
        trace.preservation()
