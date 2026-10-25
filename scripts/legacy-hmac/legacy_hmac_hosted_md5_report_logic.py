"""Interpret the real report guard over six independent Boolean predicates.

This is not finite sampling of counter values. Only exact equality and unsigned
threshold predicates with the independently typed field meanings are admitted.
Each predicate is abstracted to a free Boolean; all 64 assignments are checked
for both backend identities. Unknown arithmetic/effects fail closed.
"""
import re
from functools import lru_cache

import legacy_hmac_hosted_md5_report_layout as layout

V, L = layout.V, layout.flow.LABEL
require, syntax, flow = layout.require, layout.syntax, layout.flow
TOKEN = V + r'|-?\d+|true|false'
FIELDS = {offset: kind for offset, kind in layout.FIELDS.values()}


class Machine:
    def __init__(self, arguments, body, backend, predicates):
        args = syntax.parameters(arguments)
        require(len(args) == 3 and 'dereferenceable(88)' in args[0]
                and args[1].startswith('i8 ') and args[2].startswith('i64 '), 'MD5 report ABI changed')
        self.values = dict(zip((a.split()[-1] for a in args), (('pointer', 0), backend, ('active',))))
        self.backend, self.predicates = backend, predicates
        self.graph, self.points, self.loads = flow.blocks(body), set(), set()
        definitions = [m[1] for rows in self.graph.values() for line in rows
                       if (m := re.match('(' + V + ') = ', line))]
        require(len(set(definitions)) == len(definitions) and not set(definitions) & self.values.keys(),
                'report SSA redefinition')

    def value(self, token):
        if token in ('true', 'false'):
            return token == 'true'
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in self.values, 'unbound report operand: ' + token)
        return self.values[token]

    def compare(self, operation, kind, left, right):
        if isinstance(left, int) and isinstance(right, int):
            limit = (1 << int(kind[1:])) - 1
            left, right = left & limit, right & limit
            return {'eq': left == right, 'ne': left != right, 'ult': left < right,
                    'uge': left >= right}[operation]
        if operation in ('eq', 'ne') and isinstance(right, tuple) and right[0] == 'field':
            left, right = right, left
        require(isinstance(left, tuple) and left[0] == 'field', 'unreviewed report comparison operands')
        offset = left[1]
        expected = {80: self.backend, 0: 8 if self.backend == 0 else 4,
                    32: ('active',), 56: ('active',),
                    48: 8 if self.backend == 0 else 4, 72: 8 if self.backend == 0 else 4}
        require(FIELDS.get(offset) == kind and right == expected[offset], 'report predicate field/operand changed')
        positive = 'uge' if offset in (48, 72) else 'eq'
        negative = 'ult' if positive == 'uge' else 'ne'
        require(operation in (positive, negative), 'report threshold boundary changed')
        value = bool(self.predicates & (1 << (80, 0, 32, 56, 48, 72).index(offset)))
        return value if operation == positive else not value

    def expression(self, rhs, predecessor, incoming):
        gep = re.fullmatch('getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (\d+)', rhs)
        if gep:
            pointer = self.value(gep[1])
            require(isinstance(pointer, tuple) and pointer[0] == 'pointer', 'report pointer provenance changed')
            offset = pointer[1] + int(gep[2])
            require(offset in FIELDS, 'report address outside admitted fields')
            return ('pointer', offset)
        load = re.fullmatch('load (i8|i64), ptr (' + V + '), align 8', rhs)
        if load:
            pointer = self.value(load[2])
            require(isinstance(pointer, tuple) and pointer[0] == 'pointer'
                    and FIELDS.get(pointer[1]) == load[1], 'report load field/width changed')
            self.loads.add(pointer[1])
            return ('field', pointer[1])
        compare = re.fullmatch('icmp (eq|ne|ult|uge) (i1|i8|i64) (' + TOKEN + '), (' + TOKEN + ')', rhs)
        if compare:
            return self.compare(compare[1], compare[2], self.value(compare[3]), self.value(compare[4]))
        trunc = re.fullmatch('trunc(?: nuw)? i8 (' + V + ') to i1', rhs)
        if trunc:
            value = self.value(trunc[1])
            require(type(value) is int and value in (0, 1), 'report backend truncation has another source')
            return bool(value)
        select = re.fullmatch('select i1 (' + TOKEN + '), (i1|i8|i64) (' + TOKEN + r'), \2 (' + TOKEN + ')', rhs)
        if select:
            condition = self.value(select[1])
            require(type(condition) is bool, 'report select lacks a Boolean')
            return self.value(select[3] if condition else select[4])
        phi = re.fullmatch('phi (i8|i64) (.*)', rhs)
        if phi:
            pairs = re.findall(r'\[ (' + TOKEN + '), %' + L + r' \]', phi[2])
            require(phi[2] == ', '.join('[ ' + item + ', %' + label + ' ]' for item, label in pairs),
                    'report phi has unparsed operands')
            chosen = [item for item, label in pairs if label == predecessor]
            require(len(chosen) == 1, 'report phi predecessor changed')
            require(not chosen[0].startswith('%') or chosen[0] in incoming, 'report phi lacks incoming value')
            return incoming[chosen[0]] if chosen[0] in incoming else self.value(chosen[0])
        require(False, 'unreviewed report expression: ' + rhs)

    def run(self):
        block, previous, visited = next(iter(self.graph)), None, set()
        while True:
            require(block in self.graph and block not in visited and len(visited) < 64, 'report CFG missing/cyclic')
            visited.add(block)
            incoming = dict(self.values)
            lines = self.graph[block]
            for index, raw in enumerate(lines):
                self.points.add((block, index))
                line = raw.split(', !', 1)[0]
                define = re.fullmatch('(' + V + ') = (.*)', line)
                if define:
                    self.values[define[1]] = self.expression(define[2], previous, incoming)
                    continue
                require(index == len(lines) - 1, 'report effect or premature terminator')
                returned = re.fullmatch('ret i8 (' + TOKEN + ')', line)
                if returned:
                    return self.value(returned[1])
                branch = re.fullmatch('br i1 (' + TOKEN + '), label %' + L + ', label %' + L, line)
                direct = re.fullmatch('br label %' + L, line)
                require(branch or direct, 'unreviewed report effect/branch: ' + line)
                if branch:
                    value = self.value(branch[1])
                    require(type(value) is bool, 'report branch lacks a Boolean')
                    target = branch[2] if value else branch[3]
                else:
                    target = direct[1]
                previous, block = block, target
                break
            else:
                require(False, 'report block lacks terminator')


@lru_cache(maxsize=32)
def validate(arguments, body, compiler):
    # Pure validation memoized by exact signature, body and compiler bytes.
    # Repeated caller mutations need not re-interpret an unchanged callee;
    # changed artifact bytes cannot reuse an earlier validation.
    require(compiler in ('1.90.0', '1.99.1'), 'unreviewed report compiler')
    points, loads = set(), set()
    for backend in (0, 1):
        for predicates in range(64):
            machine = Machine(arguments, body, backend, predicates)
            expected = (10 if compiler == '1.90.0' else -1) if predicates == 63 else 8
            require(machine.run() == expected, 'MD5 report accepts malformed metadata or changes error classification')
            points.update(machine.points)
            loads.update(machine.loads)
    require(loads == set(FIELDS) and points == {(b, i) for b, rows in machine.graph.items() for i in range(len(rows))},
            'vacuous/unvisited report fields or instructions')
    return frozenset(points)
