"""Caller initialization creation, affine moves and early-exit destruction.

Walk all normal/exceptional CFG edges, resolving only proven boolean drop flags.
Unrelated computation is overapproximated. The final consumer takes ownership
on entry; its write/finish/unwind behavior is checked separately. This projection
does not establish the lifetime of the OwnedSecretRegion returned by it, or
erasure after fatal termination. Core begin/Drop remain source-pinned premises.
"""
import re

import legacy_hmac_md5_secret_consumer as consumer

r = consumer.r
flow, syntax, require, VALUE = r.flow, r.syntax, r.require, r.VALUE


def probes(fixture):
    success = r.layout.probe(fixture, 'initialization_success', 32, {'%initialization': 24}, {})
    error = r.layout.probe(fixture, 'initialization_error', 32, {}, {'%error': r.Bits.token('error', 8)})
    require(r.layout.read(success, 0, 1) == r.Bits.integer(0, 8)
            and r.layout.read(success, 8, 24) == r.Bits.token('%initialization', 192)
            and r.layout.read(error, 0, 1) == r.Bits.integer(1, 8)
            and r.layout.read(error, 1, 1) == r.Bits.token('error', 8), 'initialization Result ABI changed')


def boolean_flags(graph):
    """Track scalar phi/trunc flags; result atoms stay unknown until a switch."""
    expressions = {match[1]: match[2] for lines in graph.values() for line in lines
                   if (match := re.fullmatch(rf'({VALUE}) = (.*)', line))}
    proven, active = {}, set()

    def visit(name):
        if name in ('0', '1', 'true', 'false'):
            return True
        if name in proven:
            return True
        if name in active or name not in expressions:
            return False
        active.add(name)
        expr = expressions[name]
        phi = re.fullmatch(r'phi i(?:8|1) (.*)', expr)
        trunc = re.fullmatch(rf'trunc(?: nuw)? i8 ({VALUE}) to i1', expr)
        terms = re.findall(rf'\[ ({VALUE}|[01]|true|false), %{flow.LABEL} \]', phi[1]) if phi else []
        if terms and phi[1] == ', '.join(f'[ {value}, %{label} ]' for value, label in terms):
            good = all(visit(value) for value, _ in terms)
            expression = ('phi', tuple(terms))
        elif re.fullmatch(rf'extractvalue \{{ i8, i8 \}} {VALUE}, 0', expr):
            good, expression = True, ('atom', None)
        else:
            good = bool(trunc and visit(trunc[1]))
            expression = ('trunc', trunc[1]) if trunc else None
        active.remove(name)
        if good:
            proven[name] = expression
        return good

    for name in expressions:
        visit(name)
    return proven


class Check:
    def __init__(self, signature, body):
        self.signature, self.body, self.graph = signature, body, flow.blocks(body)
        self.allocs = r.phases.allocations(body)
        params = syntax.parameters(signature)
        require(len(params) == 5 and 'noalias' in params[3] and 'dereferenceable(128)' in params[3],
                'initialization destination is not an exclusive 128-byte region')
        self.destination = syntax.operand(params[3])
        self.begin = r.phases.one(body, lambda name, args: consumer.primitive(name, 'begin'), 'initialization begin')
        label, index, _, args = self.begin
        require(len(args) == 3 and syntax.operand(args[1]) == self.destination
                and args[2] == 'i64 noundef 128' and 'invoke ' not in self.graph[label][index],
                'initialization begin destination/extent changed')
        self.result = syntax.operand(args[0])
        require(self.allocs.get(self.result) == 32, 'initialization result extent changed')
        suffix = self.graph[label][index + 1:]
        require(len(suffix) == 3, 'initialization admission has intervening effects')
        load = re.fullmatch(rf'({VALUE}) = load i8, ptr {re.escape(self.result)}, align 8(?:, ![-\w.]+ !\d+)*', suffix[0])
        trunc = re.fullmatch(rf'({VALUE}) = trunc(?: nuw)? i8 ({VALUE}) to i1', suffix[1])
        branch = re.fullmatch(rf'br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}', suffix[2])
        require(load and trunc and branch and load[1] == trunc[2] and trunc[1] == branch[1],
                'initialization result not admitted by its discriminant')
        self.failed, self.success = branch[2], branch[3]
        workspace = r.phases.one(body, lambda name, args: r.phases.identity(name, 'new'), 'initialization workspace')
        require(workspace[0] not in r.phases.handoff.reachable(self.graph, self.failed),
                'initialization failure reaches workspace/key processing')
        self.release = r.phases.one(body, lambda name, args: r.phases.handoff.closure(name, 'authenticate_secret'),
                                    'initialization final consumer')
        self.capture = syntax.operand(self.release[3][1])
        self.ptrs = syntax.pointers(body, self.allocs)
        copies = r.phases.calls(body, lambda name, args: name == 'llvm.memcpy.p0.p0.i64')
        final = [site for site in copies if syntax.operand(site[3][0]) == self.capture]
        require(len(final) == 1, 'initialization capture has ambiguous moves')
        self.owner = syntax.operand(final[0][3][1])
        require(len({self.result, self.owner, self.capture}) == 3
                and all(self.allocs.get(root) == 24 for root in (self.owner, self.capture)),
                'initialization move geometry changed')
        self.moves, self.roots = {}, {self.result}
        cursor = (self.capture, 0)
        while cursor != (self.result, 8):
            require(len(self.moves) < 4 and cursor[0] not in self.roots, 'cyclic initialization moves')
            self.roots.add(cursor[0])
            incoming = [site for site in copies if self.ptrs.get(site[3][0].split()[-1]) == cursor]
            require(len(incoming) == 1, 'initialization move lacks a unique writer')
            site = incoming[0]
            source = self.ptrs.get(site[3][1].split()[-1])
            require(site[3][2:] == ['i64 24', 'i1 false'] and source
                    and all(root in self.allocs and 0 <= offset <= self.allocs[root] - 24
                            for root, offset in (source, cursor)), 'initialization move source/extent changed')
            self.moves[site[:2]] = (source, cursor)
            cursor = source
        require(len(self.moves) in (2, 3), 'initialization move chain changed')
        r.phases.dominates(self.graph, self.begin[:2], (self.success, -1))
        self.flags = boolean_flags(self.graph)
        self.effects = {}
        self.accesses()
        require(self.begin[0] == next(iter(self.graph)), 'initialization no longer starts at function entry')
        for index, line in enumerate(self.graph[self.begin[0]][:self.begin[1]]):
            require(' = alloca ' in line or self.effects.get((self.begin[0], index), (None,))[0] == 'start',
                    'secret work/effects precede output initialization')

    def accesses(self):
        aliases = {name for name, (root, _) in self.ptrs.items() if root in self.roots}
        self.starts = set()
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                site = label, index
                if not (set(re.findall(VALUE, line)) & aliases):
                    continue
                call = syntax.call(line)
                definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
                if site == self.begin[:2] or site in self.moves or site == self.release[:2]:
                    continue
                if definition and (' = alloca ' in line or ' = getelementptr' in line):
                    root, offset = self.ptrs.get(definition[1], (None, -1))
                    require(root in self.roots and 0 <= offset < self.allocs[root], 'initialization pointer escaped bounds')
                    continue
                if site == (self.begin[0], self.begin[1] + 1):
                    continue
                if call:
                    symbol, args = call
                    if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
                        root = syntax.operand(args[-1])
                        require(root in self.roots and len(args) in (1, 2)
                                and (len(args) == 1 or args[0] == 'i64 ' + str(self.allocs[root])),
                                'initialization lifetime extent changed')
                        self.effects[site] = ('start' if 'start' in symbol else 'end', root)
                        if 'start' in symbol:
                            self.starts.add(root)
                        continue
                    if consumer.drop(symbol):
                        require(len(args) == 1 and syntax.operand(args[0]) == self.owner,
                                'initialization Drop targets another region')
                        self.effects[site] = ('drop', self.owner)
                        continue
                require(False, 'unreviewed initialization alias use: ' + line)

    def run(self):
        # Flags are public ownership bookkeeping. Other branches fork both ways.
        pending = [(next(iter(self.graph)), None, None, frozenset(self.roots - self.starts), ())]
        seen, witnessed, sites = set(), set(), set()
        while pending:
            label, previous, owner, live, raw = state = pending.pop()
            if state in seen:
                continue
            seen.add(state)
            require(len(seen) < 100000, 'initialization CFG projection exceeded bound')
            values, live = dict(raw), set(live)
            lines = self.graph[label]
            for index, line in enumerate(lines):
                site = label, index
                definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
                if definition and definition[1] in self.flags:
                    kind, terms = self.flags[definition[1]]
                    if kind == 'atom':
                        values[definition[1]] = None
                    else:
                        value = dict((parent, value) for value, parent in terms)[previous] if kind == 'phi' else terms
                        literals = {'0': 0, '1': 1, 'true': 1, 'false': 0}
                        require(value in literals or value in values, 'unbound initialization drop flag')
                        values[definition[1]] = literals[value] if value in literals else values[value]
                        if kind == 'trunc' and values[definition[1]] is not None:
                            values[definition[1]] &= 1
                if site in self.moves:
                    source, dest = self.moves[site]
                    require(owner == source and source[0] in live and dest[0] in live,
                            'initialization move lacks a live exclusive source')
                    owner = dest
                    sites.add(site)
                if site in self.effects:
                    effect, root = self.effects[site]
                    if effect == 'start':
                        require(root not in live, 'initialization storage restarted')
                        live.add(root)
                    elif effect == 'end':
                        require(root in live and (owner is None or owner[0] != root), 'live initialization expired')
                        live.remove(root)
                    else:
                        require(owner == (root, 0) and root in live, 'missing/double initialization Drop')
                        owner = None
                        witnessed.add('drop')
                    sites.add(site)
                if site == self.release[:2]:
                    require(owner == (self.capture, 0) and self.capture in live, 'consumer lacks initialization ownership')
                    owner = None
                    witnessed.add('consumer')
                if line.startswith(('ret ', 'resume ')):
                    require(owner is None, 'initialization leaked on return/unwind')
                    witnessed.add('resume' if line.startswith('resume') else 'return')
                    break
                if line == 'unreachable':
                    break  # No fatal/double-panic erasure claim.
                if site == self.begin[:2]:
                    require(owner is None, 'initialization begun twice')
                    for child, new_owner in ((self.failed, None), (self.success, (self.result, 8))):
                        pending.append((child, label, new_owner, frozenset(live), tuple(sorted(values.items()))))
                    witnessed.add('begin')
                    break
                if line.startswith(('br ', 'switch ')) or 'invoke ' in line:
                    edges = re.findall('label %' + flow.LABEL, '\n'.join(lines[index:]))
                    branch = re.fullmatch(rf'br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}', line)
                    if branch and values.get(branch[1]) is not None:
                        edges = [branch[2] if values[branch[1]] else branch[3]]
                    require(edges, 'initialization path lost successors')
                    switch = re.fullmatch(rf'switch i8 ({VALUE}), label %{flow.LABEL} \[', line)
                    cases = re.findall(r'i8 (-?\d+), label %' + flow.LABEL, '\n'.join(lines[index + 1:]))
                    for child in edges:
                        refined = dict(values)
                        if switch and switch[1] in self.flags and child != switch[2]:
                            matched = [int(value) for value, edge in cases if edge == child]
                            require(matched, 'missing drop-flag switch constraint')
                            for value in matched:
                                refined[switch[1]] = value
                                pending.append((child, label, owner, frozenset(live), tuple(sorted(refined.items()))))
                            continue
                        pending.append((child, label, owner, frozenset(live), tuple(sorted(refined.items()))))
                    break
            else:
                require(False, 'initialization path lacks terminator')
        require({'begin', 'drop', 'consumer', 'return'} <= witnessed and self.moves.keys() <= sites,
                'initialization ownership check is vacuous')
        return witnessed


def validate(fixture, llvm):
    probes(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    check = Check(*r.phases.rows.method(definitions, aliases, 'authenticate_secret')[1])
    check.run()
    return check
