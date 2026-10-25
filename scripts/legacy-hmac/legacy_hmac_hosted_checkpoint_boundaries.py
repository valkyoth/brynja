"""Compose six actual SHA-1 checkpoints with streaming and output landmarks."""
import re

import legacy_hmac_hosted_checkpoints as scalar
import legacy_hmac_hosted_checkpoint_results as results

require, syntax, V, L = scalar.require, scalar.syntax, scalar.V, scalar.L


class Boundaries(scalar.shared.Checkpoints):
    def __init__(self, model, incoming, outgoing, transfer, records, target, compiler):
        self.m, self.flow, self.output = model, incoming, outgoing
        self.ok = -1 if compiler == '1.99.1' else 10
        self.points, self.guards, self.paths = set(), {}, {}
        wanted = scalar.owner(target) + '::sha1_compiled::worker::checkpoint'
        for symbol, args, point in model.calls:
            if model.names.get(symbol) != wanted:
                continue
            require(len(args) == 2 and model.pointer(syntax.operand(args[0]), point) == (transfer.owner, 0),
                    'outlined checkpoint executor mismatch')
            cancel = syntax.operand(args[1])
            incoming.field(cancel, 'ptr', 80)
            require(model.before(model.defs[cancel][1], point), 'outlined checkpoint cancellation capture too late')
            line = model.graph[point[0]][point[1]]
            matched = re.match('(' + V + r') = (?:tail )?(?:call|invoke)(?: fastcc)? i8 @', line)
            require(matched, 'outlined checkpoint narrowed Result ABI changed')
            returned = incoming.returned(point)
            result = matched[1]
            good, bad = self.branch(returned[0], returned[1] + 1, result, self.ok)
            self.guards[point] = result, result, good, bad
            self.paths[point] = (returned[0], result, bad, frozenset({6, 7})),
        for point, normal, rejected in records:
            block, index = normal
            atomic = re.match('(' + V + ') = load atomic ', model.graph[block][index - 1])
            require(atomic, 'inlined checkpoint atomic continuation changed')
            good, bad = self.branch(block, index, atomic[1], 0)
            failure = re.fullmatch('br label %' + L, model.graph[rejected[0]][rejected[1]])
            require(failure and rejected[1] == len(model.graph[rejected[0]]) - 1,
                    'inlined checkpoint rejected constructor resumes effects')
            self.guards[point] = atomic[1], atomic[1], good, bad
            self.paths[point] = ((block, None, bad, frozenset({6})),
                                 (rejected[0], None, failure[1], frozenset({7})))
        require(len(self.guards) == 6, 'accelerated checkpoint boundary population changed')

    def branch(self, block, index, value, expected):
        lines = self.m.graph[block]
        require(len(lines) == index + 2, 'effects between accelerated checkpoint and admission')
        comparison = re.fullmatch('(' + V + ') = icmp eq i8 ' + re.escape(value) + ', ' + str(expected), lines[index])
        require(comparison, 'accelerated checkpoint success discriminator changed')
        branch = re.fullmatch('br i1 ' + re.escape(comparison[1]) + ', label %' + L + ', label %' + L, lines[index + 1])
        require(branch and branch[1] != branch[2], 'accelerated checkpoint admission edges changed')
        self.points.update(((block, index), (block, index + 1)))
        return branch[1], branch[2]

    def check(self):
        m, f, out = self.m, self.flow, self.output
        initial = self.one(lambda p: m.before(p, f.tail.full[2]), 'accelerated initial admission')
        self.admitted(initial, f.tail.full[2])
        chunk = self.one(lambda p: p[0] == m.defs[f.chunk_pointer][1][0], 'accelerated selected chunk')
        self.admitted(chunk, (f.part_header, 0))
        part = self.one(lambda p: p[0] == f.nonempty, 'accelerated nonempty bounded part')
        self.admitted(part, f.update)
        final = self.one(lambda p: p[0] == f.finished, 'accelerated finalization')
        self.admitted(final, out.final[1])
        self.admitted(final, out.verify[1])
        copying = self.one(lambda p: m.before(f.returned(out.final[1]), p) and m.before(p, out.copy[1]),
                           'accelerated pre-copy admission')
        self.admitted(copying, out.copy[1])
        self.post = self.one(lambda p: p not in {initial, chunk, part, final, copying}, 'accelerated post-output admission')
        require(m.can_precede(f.returned(out.copy[1]), self.post)
                and m.can_precede(f.returned(out.verify[1]), self.post)
                and not m.can_precede(self.post, out.copy[1]) and not m.can_precede(self.post, out.verify[1]),
                'accelerated final checkpoint precedes output/comparison')
        protected = set(self.guards) | {f.update, f.tail.full[2], f.tail.partial[2], out.copy[1],
                                       out.final[1], out.verify[1], *m.factories}
        for point, paths in self.paths.items():
            success = self.guards[point][2]
            for predecessor, result, bad, domain in paths:
                require(not any(m.can_precede((bad, -1), use) for use in protected)
                        and not m.can_precede((bad, -1), (success, -1)),
                        'accelerated checkpoint failure resumes work')
                for code in domain:
                    expected = frozenset({code})
                    results.walk(self, bad, predecessor, {result: expected} if result else {}, expected)
        good = self.guards[self.post][2]
        predecessor, result, _, _ = self.paths[self.post][0]
        # An inlined post-check passes through the zero-valued cancellation
        # branch. Its success Result is constructed by the worker, not the load.
        expected = frozenset({self.ok & 255})
        results.walk(self, good, predecessor, {result: expected} if result else {}, expected)
        return self
