"""Scalar cancellation boundaries and error transport in emitted workers.

Compiled SHA-1/MD5 checkpoints construct real backend sessions and need their
separate callee composition; they are deliberately not admitted by this model.
"""
import re

import legacy_hmac_engine_codegen as legacy

shared = legacy.load('hmac_hosted_checkpoints')
require, syntax, V, L = shared.require, shared.syntax, shared.V, shared.L


def owner(target):
    require(target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'),
            'unknown legacy checkpoint target')
    return 'brynja_legacy_hmac_std::' + ('macos_resident' if target == 'aarch64-apple-darwin' else 'strict_execution')


def callee(arguments, body, compiler):
    params = syntax.parameters(arguments)
    require(len(params) == 1, 'legacy cancellation callee arity')
    graph = shared.common.blocks(body)
    require(len(graph) == 1, 'legacy cancellation callee branches')
    lines = next(iter(graph.values()))
    require(len(lines) == 6, 'legacy cancellation callee instruction population')
    ok = '-1' if compiler == '1.99.1' else '10'
    patterns = [r'(' + V + ') = load atomic i8, ptr ' + re.escape(syntax.operand(params[0])) + ' acquire, align 1']
    assigned = []
    for index, line in enumerate(lines):
        if index == 1:
            patterns.append('(' + V + ') = icmp eq i8 ' + re.escape(assigned[0]) + ', 0')
        elif index == 2:
            patterns.append('(' + V + ') = select i1 ' + re.escape(assigned[1]) + ', i8 ' + ok + ', i8 6')
        elif index == 3:
            patterns.append('(' + V + r') = insertvalue \{ i8, i8 \} poison, i8 ' + re.escape(assigned[2]) + ', 0')
        elif index == 4:
            patterns.append('(' + V + r') = insertvalue \{ i8, i8 \} ' + re.escape(assigned[3]) + ', i8 undef, 1')
        elif index == 5:
            patterns.append(r'ret \{ i8, i8 \} ' + re.escape(assigned[4]))
        matched = re.fullmatch(patterns[index], line)
        require(matched, 'legacy cancellation acquire/result semantics changed')
        if index < 5:
            assigned.append(matched[1])


def validate_callees(population, target, compiler):
    definitions, aliases, names = population
    expected = ('<' + owner(target) + '::types::Cancellation>::check', owner(target) + '::worker::checkpoint')
    for name in expected:
        symbols = [symbol for symbol in (*definitions, *aliases) if names.get(symbol) == name]
        require(len(symbols) == 1, 'legacy cancellation callee missing/ambiguous')
        callee(*shared.common.resolve(symbols[0], definitions, aliases), compiler)


class Checkpoints(shared.Checkpoints):
    def __init__(self, flow, output, target, compiler):
        self.m, self.flow, self.output = flow.m, flow, output
        require(not self.m.compiled, 'compiled checkpoint needs distinct authority/callee proof')
        self.ok = -1 if compiler == '1.99.1' else 10
        self.target = target
        self.check_name = owner(target) + '::worker::checkpoint'
        self.points, self.guards = set(), {}

    def check(self):
        m, f, out = self.m, self.flow, self.output
        calls = [(symbol, args, point) for symbol, args, point in m.calls if m.names.get(symbol) == self.check_name]
        require(len(calls) == 6, 'legacy scalar checkpoint population changed')
        for _, args, point in calls:
            require(len(args) == 1, 'legacy scalar checkpoint argument population')
            cancel = syntax.operand(args[0])
            f.field(cancel, 'ptr', 80)
            require(m.before(m.defs[cancel][1], point), 'legacy cancellation capture read too late')
            self.guard(point)
        initial = self.one(lambda p: m.before(p, f.tail.full[2]), 'initial admission')
        self.admitted(initial, f.tail.full[2])
        chunk = self.one(lambda p: p[0] == m.defs[f.chunk_pointer][1][0], 'each selected chunk')
        self.admitted(chunk, (f.part_header, 0))
        part = self.one(lambda p: p[0] == f.nonempty, 'each nonempty bounded part')
        self.admitted(part, f.update)
        final = self.one(lambda p: p[0] == f.finished, 'before finalization')
        self.admitted(final, out.final[1])
        self.admitted(final, out.verify[1])
        copying = self.one(lambda p: m.before(f.returned(out.final[1]), p) and m.before(p, out.copy[1]),
                           'between finalization and output copy')
        self.admitted(copying, out.copy[1])
        self.post = self.one(lambda p: p not in {initial, chunk, part, final, copying}, 'after output/comparison')
        require(m.can_precede(f.returned(out.copy[1]), self.post)
                and m.can_precede(f.returned(out.verify[1]), self.post)
                and not m.can_precede(self.post, out.copy[1]) and not m.can_precede(self.post, out.verify[1]),
                'legacy final checkpoint precedes output/comparison')
        protected = set(self.guards) | {f.update, f.tail.full[2], f.tail.partial[2], out.copy[1],
                                       out.final[1], out.verify[1], *m.factories}
        for _, _, success, failure in self.guards.values():
            require(not any(m.can_precede((failure, -1), use) for use in protected),
                    'legacy cancellation failure resumes work')
            require(not m.can_precede((failure, -1), (success, -1)), 'legacy cancellation failure rejoins success')
        shared.results.check(self)
        return self
