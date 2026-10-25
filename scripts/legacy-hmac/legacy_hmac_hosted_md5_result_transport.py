"""Consumer Result bytes and admission through the real MD5 worker report.

Exact split/copy transport, not a source-text hash. Typed downstream Result
projections independently bind the offsets. Lane payloads, tag copying and
whole-host transactions remain separate obligations.
"""
import re

import legacy_hmac_hosted_md5_result_tools as t

require, syntax, health, V = t.require, t.syntax, t.health, t.V


class Transport:
    def __init__(self, model, consumer, report, health_record):
        self.m, self.consumer, self.report, self.health = model, consumer, report, health_record
        self.points, self.roots = set(), set()
        self.calls = {p: (s, a) for s, a, p in model.calls}
        self.source = syntax.operand(self.calls[consumer][1][0])
        self.destination = syntax.operand(self.calls[report][1][0])

    def cursor(self, point):
        return t.Cursor(self.m, point, self.points)

    def root(self, root, size):
        t.allocation(self.m, root, size, self.consumer)
        require(root not in self.roots and root not in {self.m.owner, *self.m.results},
                'MD5 report storage aliases another transfer/selector')
        self.roots.add(root)

    def start(self, extent):
        require('sret([' + str(extent) + ' x i8])' in self.calls[self.consumer][1][0],
                'MD5 consumer Result ABI changed')
        self.root(self.source, extent)
        cursor = self.cursor((self.consumer[0], self.consumer[1] - 1))
        cursor.lifetime('start', self.source)
        cursor.stop(self.consumer)
        self.points.add(self.consumer)
        return self.cursor(health.returned(self.m, self.consumer))

    def join(self, block, offset):
        cursor = self.cursor((block, offset))
        cursor.lifetime('end', self.source)
        health_call = self.health[0]
        health_root = syntax.operand(self.calls[health_call][1][0])
        cursor.lifetime('start', health_root)
        cursor.stop(health_call)
        return self.cursor(self.health[1])

    def verification(self):
        cursor = self.start(96)
        entry = cursor.block
        discriminator = cursor.load(cursor.gep(self.source, 88))
        rejected = cursor.compare(discriminator)
        first = cursor.load(self.source)
        common, success = cursor.branch(rejected)
        cursor = self.cursor((success, 0))
        second = cursor.load(cursor.gep(self.source, 1), 1)
        middle = cursor.copy(cursor.gep(self.source, 2), 86)
        tail = cursor.copy(cursor.gep(self.source, 89), 7)
        self.root(middle, 86)
        self.root(tail, 7)
        cursor.jump(common)
        cursor = self.cursor((common, 0))
        # The map_err pair's order differs between compilers, not its meaning.
        phis = []
        for _ in range(2):
            _, pairs = cursor.take('(' + V + ') = phi i8 (.*)')
            phis.append(pairs)
        require(set(phis) == {f'[ {first}, %{success} ], [ 7, %{entry} ]',
                               f'[ {second}, %{success} ], [ {first}, %{entry} ]'},
                'MD5 verification map_err transport changed')
        cursor = self.join(common, cursor.index)
        bad, good = cursor.branch(rejected)
        require(not self.m.can_precede((bad, -1), self.report), 'failed MD5 verification reaches report')
        cursor = self.cursor((good, 0))
        self.root(self.destination, 88)
        tail_first = cursor.rows[0].endswith(', i64 81')
        if tail_first:
            cursor.copy(tail, 7, cursor.gep(self.destination, 81))
        cursor.copy(cursor.gep(middle, 6), 80, self.destination)
        cursor.store(discriminator, cursor.gep(self.destination, 80))
        if not tail_first:
            cursor.copy(tail, 7, cursor.gep(self.destination, 81))
        cursor.stop(self.report)
        self.points.add(self.report)
        t.audit(self.m, self.roots, self.points, self.consumer, self.report)

    def authentication(self):
        cursor = self.start(120)
        discriminator = cursor.load(self.source)
        rejected = cursor.compare(discriminator)
        error, success = cursor.branch(rejected)
        cursor = self.cursor((success, 0))
        mapped = cursor.copy(self.source, 120)
        self.root(mapped, 120)
        common, = cursor.take('br label %' + t.L)
        cursor.end()
        cursor = self.cursor((self.consumer[0], self.consumer[1] - 2))
        cursor.lifetime('start', mapped)
        cursor.stop((self.consumer[0], self.consumer[1] - 1))
        cursor = self.cursor((error, 0))
        payload = cursor.load(cursor.gep(self.source, 1), 1)
        cursor.store('7', cursor.gep(mapped, 1), 1)
        cursor.store(payload, cursor.gep(mapped, 2), 2)
        cursor.store('2', mapped)
        cursor.jump(common)
        cursor = self.join(common, 0)
        first = cursor.load(mapped)
        second = cursor.load(cursor.gep(mapped, 1), 1)
        third = cursor.load(cursor.gep(mapped, 2), 2)
        rejected = cursor.compare(first)
        bad, good = cursor.branch(rejected)
        require(not self.m.can_precede((bad, -1), self.report), 'failed MD5 authentication reaches report')
        cursor = self.cursor((good, 0))
        source_tail = cursor.gep(mapped, 3)
        report_first = cursor.rows[cursor.index].endswith(', i64 32')
        if report_first:
            report = cursor.gep(mapped, 32)
            call = syntax.call(cursor.rows[cursor.index])
            require(call and call[0] == 'llvm.lifetime.start.p0', 'MD5 tag lifetime missing')
            tags = syntax.operand(call[1][-1])
        else:
            destination, tags = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + '), i64 3')
        t.allocation(self.m, tags, 32, self.consumer)
        require(tags not in self.roots, 'MD5 tag owner aliases report storage')
        cursor.lifetime('start', tags)
        if not report_first:
            cursor.copy(source_tail, 29, destination)
            report = cursor.gep(mapped, 32)
        cursor.store(first, tags)
        cursor.store(second, cursor.gep(tags, 1), 1)
        cursor.store(third, cursor.gep(tags, 2), 2)
        if report_first:
            cursor.copy(source_tail, 29, cursor.gep(tags, 3))
        require(report == self.destination, 'MD5 report not from authenticated consumer Result')
        cursor.stop(self.report)
        self.points.add(self.report)
        t.audit(self.m, self.roots, self.points, self.consumer, self.report, (mapped,))


def check(model, health_result, target):
    prefix = 'brynja_legacy_hmac_std::' + ('macos_resident' if 'apple' in target else 'strict_execution')
    reports = [p for s, _, p in model.calls if model.names.get(s) == prefix + '::md5_compiled::worker::report']
    require(len(reports) == 2, 'MD5 transport report population changed')
    checks = []
    for _, consumer, _ in model.consumers:
        matches = [p for p in reports if model.before(consumer, p)]
        require(len(matches) == 1, 'MD5 consumer/report association changed')
        result = Transport(model, consumer, matches[0], health_result[2][consumer])
        name = model.names[result.calls[consumer][0]]
        if name.endswith('::verify'):
            result.verification()
        else:
            require(name.endswith('::authenticate_secret'), 'unreviewed MD5 consumer')
            result.authentication()
        checks.append(result)
    require(len(checks) == 2 and len({item.report for item in checks}) == 2
            and not checks[0].roots & checks[1].roots, 'MD5 consumers share report transfer storage')
    return checks
