"""Bounded emitted comparison traces, not a general constant-time proof.

Candidate shape/length admission is a caller premise. Primitive comparison and
clearing semantics are source-bound premises; no secret byte is interpreted as
a public branch value. All masks/selected lengths and every full-batch comparison
unwind boundary are exercised. Caller admission and quarantine are separate.
"""
from dataclasses import dataclass
import hashlib
import re

import legacy_hmac_md5_pad_model as model
import legacy_hmac_md5_handoff as handoff

flow, syntax, require, VALUE = model.flow, model.syntax, model.require, model.VALUE
PINS = {
    **handoff.rows.contracts.PINS,
    'crates/brynja-core/src/secret_memory_difference.rs': '6eb3156c9092a90050efe81c8aa5e136a5c6dbc06e59fd296c6a1e46c1148093',
    'crates/brynja-core/src/secret_memory_predicate.rs': 'd5f7b5de2140ce78d09563a2664c10bdaddfc81e9b218dfc56e4fdc4e89ed04c',
    'crates/brynja-core/src/constant_time/choice.rs': '846e876f5f749f361acc5a731e4d2a047b117bddec15a88aa01ce3a6a0dc0a4b',
}


def validate_source(root=handoff.rows.contracts.ROOT):
    for name, digest in PINS.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                'comparison primitive premise changed: ' + name)


@dataclass(frozen=True)
class Decision:
    comparisons: tuple


class Check:
    def __init__(self, signature, body):
        self.graph, self.body = flow.blocks(body), body
        params = syntax.parameters(signature)
        require(len(params) == 3 and 'readonly' in params[0] and 'readonly' in params[2]
                and 'noalias' in params[2], 'comparison input contract changed')
        self.candidates, self.width, self.rows = syntax.operand(params[0]), params[1].split()[-1], syntax.operand(params[2])
        owners = re.findall(rf'({VALUE}) = alloca \[1 x i8\], align ([14])(?:\n|$)', body)
        require(len(owners) == 1, 'comparison accumulator population changed')
        self.local, self.alignment = owners[0]


class State(model.State):
    def __init__(self, check, mask, length, failure):
        self.check, self.mask, self.length, self.failure = check, mask, length, failure
        self.values = {name: (name, 0) for name in (check.candidates, check.rows, check.local)}
        self.values[check.width] = length
        self.live, self.initialized, self.cleared, self.failed = False, False, False, False
        self.comparisons, self.decisions, self.seen = [], [], set()

    def read(self, pointer, kind):
        require(isinstance(pointer, tuple) and pointer[0] == self.check.candidates, 'unbound comparison load')
        lane, field = divmod(pointer[1], 16)
        require(0 <= lane < 8 and (kind, field) in (('ptr', 0), ('i64', 8)), 'comparison candidate field changed')
        active = self.mask & (1 << lane)
        require(field == 0 or active, 'comparison reads absent candidate length')
        return (('candidate' + str(lane), 0) if active else None) if field == 0 else self.length

    def call(self, symbol, args, site):
        if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
            require(syntax.operand(args[-1]) == self.check.local and len(args) in (1, 2)
                    and (len(args) == 1 or args[0] == 'i64 1'), 'comparison lifetime changed')
            if 'start' in symbol:
                require(not self.live and not self.initialized, 'comparison lifetime restarted')
                self.live = True
            else:
                require(self.live and self.cleared, 'comparison ended without clearing')
                self.live = False
            return None
        if symbol == 'llvm.assume':
            require(args and args[0].startswith('i1 ') and self.value(args[0].split()[-1]) == 1,
                    'comparison assumes an unproved predicate')
            return None
        if symbol == 'llvm.umin.i64':
            values = list(map(self.argument, args))
            require(len(values) == 2 and all(isinstance(v, int) for v in values), 'unknown comparison limit')
            return min(values)
        if model.primitive(symbol, 'clear_owned_region'):
            require(list(map(self.argument, args)) == [(self.check.local, 0), 1]
                    and self.live and self.initialized and not self.cleared, 'wrong/repeated comparison clear')
            self.cleared = True
            return 0  # The ignored completion value cannot authorize a decision.
        require(self.live and self.initialized and not self.cleared and not self.failed,
                'comparison uses expired/failed accumulator')
        values = list(map(self.argument, args))
        require(values and values[0] == (self.check.local, 0), 'comparison accumulator substituted')
        if model.primitive(symbol, 'accumulate_secret_byte_difference'):
            require(len(values) == 3 and not self.decisions, 'comparison after decision or wrong arity')
            left, right = values[1:]
            require(isinstance(left, tuple) and left[0] == self.check.rows and 0 <= left[1] < 128,
                    'comparison source leaves tag rows')
            lane, byte = divmod(left[1], 16)
            require(self.mask & (1 << lane) and byte < self.length
                    and right == ('candidate' + str(lane), byte), 'comparison lane/byte provenance changed')
            boundary = len(self.comparisons)
            self.comparisons.append((lane, byte))
        else:
            require(model.primitive(symbol, 'secret_difference_is_zero') and len(values) == 1 and not self.decisions,
                    'unreviewed comparison effect: ' + symbol)
            boundary = 'decision'
            self.decisions.append(Decision(tuple(self.comparisons)))
        if self.failure == boundary:
            self.failed = True
            line = self.check.graph[site[0]][site[1]]
            require('invoke ' in line, 'requested comparison unwind has no invoke edge')
            edge = self.check.graph[site[0]][site[1] + 1]
            match = re.fullmatch('to label %' + flow.LABEL + ' unwind label %' + flow.LABEL, edge)
            require(match, 'comparison unwind edge changed')
            return ('unwind', match[2])
        return self.decisions[-1] if boundary == 'decision' else None

    def run(self):
        label, previous = next(iter(self.check.graph)), None
        for _ in range(5000):
            require(label in self.check.graph, 'unknown comparison edge')
            lines = self.check.graph[label]
            incoming, phis = dict(self.values), {}
            for index, line in enumerate(lines):
                self.seen.add((label, index))
                phi = re.fullmatch(rf'({VALUE}) = phi (ptr|i64|\{{ ptr, i32 \}}) (.*)', line)
                if phi:
                    matches = [value for value, parent in re.findall(r'\[ ([^,]+), %' + flow.LABEL + r' \]', phi[3]) if parent == previous]
                    require(len(matches) == 1, 'comparison phi predecessor changed')
                    saved = self.values; self.values = incoming
                    phis[phi[1]] = ('exception',) if phi[2].startswith('{') else self.value(matches[0])
                    self.values = saved
                    continue
                self.values.update(phis)
                if line == self.check.local + ' = alloca [1 x i8], align ' + self.check.alignment:
                    continue
                if ' = landingpad { ptr, i32 }' in line:
                    require(self.failed, 'comparison landingpad entered normally')
                    self.values[line.split(' = ')[0]] = ('exception',)
                    continue
                if line == 'cleanup':
                    require(self.failed, 'unexpected comparison cleanup')
                    continue
                if line.startswith(('ret ', 'resume ')):
                    expected = [(lane, byte) for lane in range(8) if self.mask & (1 << lane) for byte in range(self.length)]
                    require(self.initialized and self.cleared and (not self.live or line.startswith('resume ')),
                            'comparison exit lacks scratch cleanup')
                    if self.failure is not None:
                        require(self.failed and line.startswith('resume '), 'comparison unwind returned a decision')
                    else:
                        require(line.startswith('ret i8 ') and self.comparisons == expected
                                and self.decisions == [Decision(tuple(expected))]
                                and self.value(line.split()[-1]) == self.decisions[0], 'incomplete or substituted verification decision')
                    return self.seen
                invocation = syntax.call(line)
                if invocation:
                    name = re.match(rf'({VALUE}) = ', line)
                    value = self.call(*invocation, (label, index))
                    if isinstance(value, tuple) and len(value) == 2 and value[0] == 'unwind':
                        previous, label = label, value[1]
                        break
                    if name:
                        self.values[name[1]] = value
                    continue
                store = re.fullmatch(rf'store i8 (\d+), ptr ({VALUE}), align {self.check.alignment}', line)
                if store:
                    require(self.live and not self.initialized and store[1] == '0'
                            and self.value(store[2]) == (self.check.local, 0), 'comparison accumulator reset/substituted')
                    self.initialized = True
                    continue
                boolean = re.fullmatch(rf'({VALUE}) = or i1 ({model.ATOM}), ({model.ATOM})', line)
                freeze = re.fullmatch(rf'({VALUE}) = freeze i64 ({VALUE})', line)
                if freeze:
                    value = self.value(freeze[2])
                    require(isinstance(value, int), 'comparison freeze cannot invent public metadata')
                    self.values[freeze[1]] = value
                    continue
                if boolean:
                    a, b = self.value(boolean[2]), self.value(boolean[3])
                    require(a in (0, 1) and b in (0, 1), 'comparison branch uses secret-derived value')
                    self.values[boolean[1]] = a | b
                    continue
                kind, name, args = model.parse(line)
                # Reuse only public pointer/index/predicate semantics. All
                # loads, stores, calls and lifetime effects are handled above.
                require(kind in ('gep', 'load', 'binary', 'compare', 'select', 'branch', 'jump', 'edge'),
                        'unreviewed comparison instruction')
                if kind == 'gep':
                    require(args[0] == 'i8', 'comparison address stride changed')
                target = super().evaluate(line)
                if kind == 'gep':
                    root, offset = self.values[name]
                    extent = 128 if root in (self.check.candidates, self.check.rows) else self.length if re.fullmatch('candidate[0-7]', root) else 1 if root == self.check.local else None
                    require(extent is not None and 0 <= offset <= extent, 'comparison GEP leaves its allocation')
                if target is not None:
                    previous, label = label, target
                    break
            else:
                require(False, 'unterminated comparison block')
        require(False, 'comparison execution bound exceeded')


def selected(llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    names = [name for name in (*definitions, *aliases) if handoff.closure(name, 'verify')]
    require(len(names) == 1, 'comparison closure missing/ambiguous')
    return Check(*flow.resolve(names[0], definitions, aliases))


def validate(llvm, panic):
    validate_source()
    check = selected(llvm)
    for mask in range(256):
        for length in range(10, 17):
            State(check, mask, length, None).run()
    if panic == 'unwind':
        for length in range(10, 17):
            for failure in (*range(8 * length), 'decision'):
                State(check, 255, length, failure).run()
    return check
