"""Conservative post-digest owner transport through the pad-loop preheader."""
import copy
import re

import legacy_hmac_md5_normalization_bits as bits
import legacy_hmac_md5_results as results

phases, errors = results.phases, results.errors
flow, syntax, require, VALUE = phases.flow, phases.syntax, phases.require, phases.VALUE
Bits, Pointer, Memory = bits.Bits, bits.Pointer, bits.Memory
TYPE = r"(?:ptr|i1|i8|i16|i32|i40|i48|i64|<2 x i64>|\{ i8, i8 \})"
ATOM = rf"(?:{VALUE}|-?\d+|true|false|null|undef|poison|zeroinitializer)"


class State:
    def __init__(self, check, start, memory):
        self.check, self.start, self.memory = check, start, memory
        self.values = {name: Pointer(name) for name in check.allocs}
        self.values[check.workspace] = Pointer(check.workspace)
        self.output_live = True
        self.dead = set()

    def address(self, text):
        pointer = self.value(text, "ptr")
        require(isinstance(pointer, Pointer) and pointer.root not in self.dead,
                "expired/unknown normalization memory address")
        return pointer

    def value(self, text, dtype):
        width = bits.width(dtype)
        if text in ("undef", "poison"):
            return Bits.unknown(width)
        if text in ("true", "false", "zeroinitializer", "null") or re.fullmatch(r"-?\d+", text):
            number = int(text == "true") if not re.fullmatch(r"-?\d+", text) else int(text)
            return Bits.integer(number, width)
        if text not in self.values:
            require(text in self.check.defs, "unbound normalization SSA value: " + text)
            site, line = self.check.defs[text]
            phases.dominates(self.check.graph, site, self.start)
            gep = re.fullmatch(rf"{VALUE} = getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", line)
            if gep:
                base = self.value(gep[1], "ptr")
                require(isinstance(base, Pointer), "unknown normalization predecessor address")
                value = Pointer(base.root, base.offset + int(gep[2]))
                self.memory.bounds(value, 0)
            else:
                # Pre-existing public report/selection facts may remain unknown.
                # Never invent values from a skipped post-call basic block.
                value = Bits.unknown(width)
            self.values[text] = value
        value = self.values[text]
        require(len(bits.packed(value).data) == width, "normalization SSA type changed")
        return value

    def expression(self, expression):
        gep = re.fullmatch(rf"getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", expression)
        load = re.fullmatch(rf"load ({TYPE}), ptr ({VALUE}), align \d+(?:, !.*)?", expression)
        cast = re.fullmatch(rf"(zext|trunc)(?: nneg)?(?: nuw)? (i\d+) ({ATOM}) to (i\d+)", expression)
        convert = re.fullmatch(rf"inttoptr i64 ({ATOM}) to ptr", expression)
        binary = re.fullmatch(rf"(shl|lshr|or|and)(?: nuw)?(?: nsw)?(?: disjoint)? (i\d+) ({ATOM}), ({ATOM})", expression)
        compare = re.fullmatch(rf"icmp(?: samesign)? (eq|ne|uge|ugt|ule|ult) (i\d+) ({ATOM}), ({ATOM})", expression)
        select = re.fullmatch(rf"select i1 ({ATOM}), ({TYPE}) ({ATOM}), \2 ({ATOM})", expression)
        extract = re.fullmatch(rf"extractelement <2 x i64> ({ATOM}), i64 ([01])", expression)
        if gep:
            base = self.value(gep[1], "ptr")
            require(isinstance(base, Pointer), "unbound normalization GEP")
            pointer = Pointer(base.root, base.offset + int(gep[2]))
            self.memory.bounds(pointer, 0)
            return pointer
        if load:
            return self.memory.load(self.address(load[2]), load[1])
        if cast:
            return bits.packed(self.value(cast[3], cast[2])).resize(bits.width(cast[4]))
        if convert:
            return bits.unpack(bits.packed(self.value(convert[1], "i64")), "ptr")
        if binary:
            return bits.packed(self.value(binary[3], binary[2])).binary(binary[1], bits.packed(self.value(binary[4], binary[2])))
        if compare:
            return bits.packed(self.value(compare[3], compare[2])).compare(compare[1], bits.packed(self.value(compare[4], compare[2])))
        if select:
            condition = bits.packed(self.value(select[1], "i1")).number()
            left, right = self.value(select[3], select[2]), self.value(select[4], select[2])
            if condition is not None:
                return left if condition else right
            a, b = bits.packed(left), bits.packed(right)
            return bits.unpack(Bits(tuple(x if x == y else None for x, y in zip(a.data, b.data))), select[2])
        if extract:
            value = bits.packed(self.value(extract[1], "<2 x i64>"))
            offset = int(extract[2]) * 64
            return Bits(value.data[offset:offset + 64])
        require(False, "unparsed normalization expression: " + expression)

    def call(self, symbol, args):
        if symbol == "llvm.experimental.noalias.scope.decl":
            require(len(args) == 1 and re.fullmatch(r"metadata !\d+", args[0]), "normalization alias metadata changed")
            return
        if symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
            pointer = self.value(syntax.operand(args[-1]), "ptr")
            require(isinstance(pointer, Pointer) and pointer.root in self.check.allocs and pointer.offset == 0
                    and len(args) in (1, 2) and
                    (len(args) == 1 or args[0] == "i64 " + str(self.check.allocs[pointer.root])),
                    "normalization lifetime extent/identity changed")
            self.memory.invalidate(pointer.root)
            if symbol == "llvm.lifetime.end.p0":
                self.dead.add(pointer.root)
            else:
                self.dead.discard(pointer.root)
            if pointer.root == self.check.output:
                self.output_live = False
            return
        if results.fence.identity(symbol, "drop"):
            require(len(args) == 1 and self.address(syntax.operand(args[0])) == Pointer(self.check.scope)
                    and self.memory.load(Pointer(self.check.scope), "ptr") == Pointer(self.check.workspace)
                    and self.memory.load(Pointer(self.check.scope, 8), "i8") == Bits.integer(1, 8),
                    "normalization Scope destructor rebound")
            return  # source-bound Scope only clears its workspace, not output
        require(False, "unreviewed effect during normalization owner handoff: " + symbol)


def walk(check, site, result_bytes, expected, selection, *, seeds=None, on_entry=None, optional_owner=True):
    """All reachable pad-entry paths preserve owner bits, or errors never enter."""
    start, unwind = results.continuation(check.graph, site)
    memory = Memory({**check.allocs, check.workspace: 912})
    memory.store(Pointer(syntax.operand(site[3][0])), result_bytes)
    memory.store(Pointer(check.scope), Pointer(check.workspace))
    first = State(check, start, memory)
    if seeds is not None:
        first.values.update(seeds)
    if selection is not None:
        first.values[check.selection] = Bits.integer(selection, 8)
    pending = [(start[0], start[1], site[0], first, frozenset())]
    relevant = errors.ancestors(check.graph, {check.stop})
    witnesses, count = 0, 0
    while pending:
        label, index, previous, state, seen = pending.pop()
        if label not in relevant:
            continue
        require((label, index) not in seen, "cycle in normalization owner handoff")
        seen = seen | {(label, index)}
        count += 1
        require(count < 2000, "normalization handoff state bound exceeded")
        if label == check.stop:
            require(expected, "normalization digest failure reaches pad entry")
            offset = 8 if optional_owner else 0
            require(state.output_live and check.owner not in state.dead
                    and (not optional_owner or state.memory.load(Pointer(check.owner), "i64") == Bits.integer(1, 64))
                    and state.memory.load(Pointer(check.owner, offset), "ptr") == Pointer("returned-owner")
                    and state.memory.load(Pointer(check.owner, offset + 8), "i64") == Bits.token("returned-length"),
                    "normalized owner substituted/truncated/expired before pad entry")
            witnesses += 1
            if on_entry is not None:
                on_entry(state)
            continue
        lines = check.graph[label]
        phis = {}
        while index < len(lines) and " = phi " in lines[index]:
            match = re.fullmatch(rf"({VALUE}) = phi ({TYPE}) (.*)", lines[index])
            require(match, "unparsed normalization phi")
            pattern = rf"\[ ({ATOM}), %{flow.LABEL} \]"
            require(re.fullmatch(pattern + "(?:, " + pattern + ")*", match[3]), "malformed normalization phi")
            edges = re.findall(pattern, match[3])
            require(len({edge for _, edge in edges}) == len(edges), "duplicate normalization phi predecessor")
            selected = [value for value, edge in edges if edge == previous]
            require(len(selected) == 1, "normalization phi predecessor missing")
            phis[match[1]] = state.value(selected[0], match[2])
            check.visited.add((label, index))
            index += 1
        state.values.update(phis)
        while index < len(lines):
            check.visited.add((label, index))
            line = lines[index]
            definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
            call = syntax.call(line)
            store = re.fullmatch(rf"store ({TYPE}) ({ATOM}), ptr ({VALUE}), align \d+(?:, !.*)?", line)
            branch = re.fullmatch(rf"br i1 ({ATOM}), label %{flow.LABEL}, label %{flow.LABEL}", line)
            jump = re.fullmatch("br label %" + flow.LABEL, line)
            switch = re.fullmatch(rf"switch (i\d+) ({ATOM}), label %{flow.LABEL} \[", line)
            targets = None
            if call:
                require(not definition, "normalization cleanup call gained a result")
                state.call(*call)
                if "invoke " in line:
                    normal, exceptional = results.continuation(check.graph, (label, index))
                    require(exceptional[0] not in relevant, "normalization cleanup unwind reaches pad entry")
                    targets = [normal[0]]
            elif definition:
                state.values[definition[1]] = state.expression(definition[2])
            elif store:
                address = state.address(store[3])
                require(isinstance(address, Pointer) and address.root in (check.owner, check.scope, check.secret),
                        "unapproved store during normalization owner handoff")
                state.memory.store(address, state.value(store[2], store[1]))
            elif branch:
                decision = bits.packed(state.value(branch[1], "i1")).number()
                targets = [branch[2], branch[3]] if decision is None else [branch[2 if decision else 3]]
            elif jump:
                targets = [jump[1]]
            elif switch:
                value = bits.packed(state.value(switch[2], switch[1])).number()
                edges = []
                for case in lines[index + 1:-1]:
                    match = re.fullmatch(re.escape(switch[1]) + r" (-?\d+), label %" + flow.LABEL, case)
                    require(match, "unparsed normalization switch case")
                    edges.append((int(match[1]) % (1 << bits.width(switch[1])), match[2]))
                require(lines[-1] == "]" and len({value for value, _ in edges}) == len(edges), "malformed normalization switch")
                targets = list({switch[3], *(edge for _, edge in edges)}) if value is None else [dict(edges).get(value, switch[3])]
            else:
                require(False, "unparsed normalization handoff instruction: " + line)
            if targets is not None:
                for target in targets:
                    require(target in check.graph, "unknown normalization CFG edge")
                    child = copy.copy(state)
                    child.values = dict(state.values)
                    child.dead = set(state.dead)
                    child.memory = copy.copy(state.memory)
                    child.memory.cells = dict(state.memory.cells)
                    pending.append((target, 0, label, child, seen))
                break
            index += 1
        else:
            require(False, "normalization handoff lacks terminator")
    require(bool(witnesses) == expected, "normalization success has no non-vacuous pad-entry witness")
    if unwind:
        require(unwind[0] not in relevant, "normalization digest unwind reaches pad entry")
    return witnesses
