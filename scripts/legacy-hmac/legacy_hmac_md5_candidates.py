"""Symbolic candidate admission before executor entry, for all eight lanes.

Reduced ordered decision diagrams quantify input presence, candidate presence
and equality of each candidate length with the selected width (24 booleans).
Only metadata reads and exact TagLength rejection writes are allowed before
entry. No candidate/key bytes are read. Post-admission lifetime and the actual
comparison are separate obligations; constructor/tag-layout checks are composed
by the driver, not replaced here.
"""
from functools import lru_cache
import re

import legacy_hmac_md5_initialization as initialization

r, flow, syntax, require, VALUE = (initialization.r, initialization.flow, initialization.syntax,
                                  initialization.require, initialization.VALUE)


class Decisions:
    def __init__(self):
        self.nodes = [(99, 0, 0), (99, 1, 1)]
        self.unique = {}

    def node(self, var, low, high):
        if low == high:
            return low
        key = var, low, high
        if key not in self.unique:
            self.unique[key] = len(self.nodes)
            self.nodes.append(key)
        return self.unique[key]

    def variable(self, var):
        return self.node(var, 0, 1)

    @lru_cache(maxsize=None)
    def negate(self, value):
        if value < 2:
            return 1 - value
        var, low, high = self.nodes[value]
        return self.node(var, self.negate(low), self.negate(high))

    @lru_cache(maxsize=None)
    def conjunction(self, left, right):
        if not left or not right:
            return 0
        if left == 1 or left == right:
            return right
        if right == 1:
            return left
        var = min(self.nodes[left][0], self.nodes[right][0])
        def edges(value):
            return self.nodes[value][1:] if self.nodes[value][0] == var else (value, value)
        lo, hi = edges(left); other_lo, other_hi = edges(right)
        return self.node(var, self.conjunction(lo, other_lo), self.conjunction(hi, other_hi))

    def disjunction(self, left, right):
        return self.negate(self.conjunction(self.negate(left), self.negate(right)))


def probes(fixture):
    pair = r.layout.probe(fixture, 'candidate_pair', 32, {},
                          {'%value.0': r.Pointer('candidate'), '%value.1': r.Bits.token('length')})
    require(r.layout.read(pair, 0, 8) == r.Pointer('candidate').bits()
            and r.layout.read(pair, 8, 8) == r.Bits.token('length')
            and r.layout.read(pair, 16, 8) == r.Bits.integer(0, 64), 'candidate Option/slice layout changed')
    error = r.layout.probe(fixture, 'verify_tag_error', 96, {}, {})
    require(r.layout.read(error, 0, 1) == r.Bits.integer(1, 8)
            and r.layout.read(error, 88, 1) == r.Bits.integer(2, 8), 'verification TagLength ABI changed')


class Check:
    def __init__(self, signature, body):
        self.signature, self.body, self.graph = signature, body, flow.blocks(body)
        params = syntax.parameters(signature)
        require(len(params) == 5 and all('noalias' in param for param in params)
                and all('readonly' in param for param in params[1:4])
                and all(f'dereferenceable({size})' in param for size, param in zip((96, 24, 384, 128, 24), params)),
                'candidate admission signature changed')
        self.output, self.selection, self.inputs, self.candidates, self.control = map(syntax.operand, params)
        self.ptrs = syntax.pointers(body, [syntax.operand(param) for param in params])
        self.workspace = r.phases.one(body, lambda name, args: r.phases.identity(name, 'new'), 'verify workspace')
        entries = [(label, index) for label, lines in self.graph.items() for index, line in enumerate(lines)
                   if (match := re.fullmatch(rf'{VALUE} = load ptr, ptr ({VALUE}), align 8(?:, ![-\w.]+ !\d+)*', line))
                   and self.ptrs.get(match[1]) == (self.selection, 0)]
        require(len(entries) == 1, 'candidate admission executor entry changed')
        self.entry = entries[0]
        r.phases.dominates(self.graph, self.entry, self.workspace[:2])

    def run(self):
        try:
            return self._run()
        finally:
            # Failed mutations must not retain instance-keyed decision diagrams.
            Decisions.negate.cache_clear()
            Decisions.conjunction.cache_clear()

    def _run(self):
        bdd = Decisions()
        expected = 1
        for lane in range(8):
            inp, candidate, length = (bdd.variable(3 * lane + i) for i in range(3))
            absent = bdd.conjunction(bdd.negate(inp), bdd.negate(candidate))
            present = bdd.conjunction(inp, bdd.conjunction(candidate, length))
            expected = bdd.conjunction(expected, bdd.disjunction(absent, present))
        pending = [(next(iter(self.graph)), {}, 1, frozenset(), frozenset())]
        accepted = rejected = 0
        visited = 0
        while pending:
            label, values, condition, written, trail = pending.pop()
            if condition == 0:
                continue
            require(label not in trail, 'candidate preflight gained a loop')
            trail = trail | {label}
            visited += 1
            require(visited < 10000, 'candidate preflight path bound exceeded')
            lines = self.graph[label]
            def boolean(name):
                value = {'true': ('bool', 1), 'false': ('bool', 0)}.get(name, values.get(name))
                require(value and value[0] == 'bool', 'candidate condition is not bound metadata')
                return value[1]
            for index, line in enumerate(lines):
                if (label, index) == self.entry:
                    require(not written, 'candidate admission overwrote result before execution')
                    accepted = bdd.disjunction(accepted, condition)
                    break
                definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
                call = syntax.call(line)
                if definition:
                    dest, expr = definition.groups()
                    if 'alloca ' in expr:
                        continue
                    if expr.startswith('getelementptr'):
                        root, offset = self.ptrs.get(dest, (None, -1))
                        sizes = {self.output: 96, self.selection: 24, self.inputs: 384, self.candidates: 128}
                        require(root in sizes and 0 <= offset < sizes[root], 'candidate metadata pointer escaped')
                        continue
                    load = re.fullmatch(rf'load (ptr|i64), ptr ({VALUE}), align 8(?:, ![-\w.]+ !\d+)*', expr)
                    compare = re.fullmatch(rf'icmp (eq|ne) (ptr|i64) ({VALUE}), ({VALUE}|null)', expr)
                    select = re.fullmatch(rf'select i1 ({VALUE}), i1 ({VALUE}|true|false), i1 ({VALUE}|true|false)', expr)
                    if load:
                        kind, address = load.groups()
                        root, offset = self.ptrs.get(address, (None, -1))
                        if (root, offset, kind) == (self.selection, 8, 'i64'):
                            values[dest] = ('selected', None)
                        elif root == self.inputs and offset % 48 == 0 and kind == 'ptr':
                            values[dest] = ('pointer', bdd.variable(3 * (offset // 48)))
                        elif root == self.candidates and offset % 16 == 0 and kind == 'ptr':
                            values[dest] = ('pointer', bdd.variable(3 * (offset // 16) + 1))
                        elif root == self.candidates and offset % 16 == 8 and kind == 'i64':
                            # Speculative absent-Option length loads are allowed only as
                            # equality operands; acceptance must not depend on them.
                            values[dest] = ('length', offset // 16)
                        else:
                            require(False, 'preflight reads secret/non-admission storage')
                    elif compare:
                        op, kind, left, right = compare.groups()
                        value = values.get(left)
                        if kind == 'ptr':
                            require(right == 'null' and value and value[0] == 'pointer', 'unbound candidate null check')
                            equal = bdd.negate(value[1])
                        else:
                            other = values.get(right)
                            require(value and other and {value[0], other[0]} == {'length', 'selected'},
                                    'candidate length not compared with selected width')
                            lane = value[1] if value[0] == 'length' else other[1]
                            equal = bdd.variable(3 * lane + 2)
                        values[dest] = ('bool', equal if op == 'eq' else bdd.negate(equal))
                    elif select:
                        cond, yes, no = map(boolean, select.groups())
                        values[dest] = ('bool', bdd.disjunction(bdd.conjunction(cond, yes),
                                                              bdd.conjunction(bdd.negate(cond), no)))
                    else:
                        require(False, 'unparsed candidate admission expression: ' + expr)
                elif call:
                    symbol, _ = call
                    require(symbol == 'llvm.experimental.noalias.scope.decl', 'candidate preflight has a side effect')
                elif line.startswith('store '):
                    store = re.fullmatch(rf'store i8 (\d+), ptr ({VALUE}), align 8', line)
                    require(store and (self.ptrs.get(store[2]), int(store[1])) in (
                        ((self.output, 0), 1), ((self.output, 88), 2)), 'candidate rejection changed error/variant')
                    offset = self.ptrs[store[2]][1]
                    require(offset not in written, 'candidate rejection rewrites result')
                    written = written | {offset}
                elif line == 'ret void':
                    require(written == {0, 88}, 'candidate rejection lacks exact TagLength result')
                    rejected = bdd.disjunction(rejected, condition)
                    break
                elif line.startswith('br '):
                    branch = re.fullmatch(rf'br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}', line)
                    direct = re.fullmatch('br label %' + flow.LABEL, line)
                    require(branch or direct, 'unparsed candidate admission branch')
                    if direct:
                        edges = [(direct[1], condition)]
                    else:
                        flag = boolean(branch[1])
                        edges = [(branch[2], bdd.conjunction(condition, flag)),
                                 (branch[3], bdd.conjunction(condition, bdd.negate(flag)))]
                    pending.extend((child, dict(values), pred, written, trail) for child, pred in edges)
                    break
                else:
                    require(False, 'unparsed candidate admission effect: ' + line)
            else:
                require(False, 'candidate admission block lacks terminator')
        require(accepted == expected and rejected == bdd.negate(expected),
                'candidate presence/length acceptance differs from all-eight-lane contract')
        return visited


def validate(fixture, llvm):
    probes(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    check = Check(*r.phases.rows.method(definitions, aliases, 'verify')[1])
    check.run()
    return check
