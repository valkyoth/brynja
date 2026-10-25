"""Exact instruction/byte-transfer cursors for hosted MD5 Result transport."""
import re

import legacy_hmac_hosted_md5_health as health

syntax, require, V, L = health.syntax, health.require, health.V, health.L


class Cursor(health.callee.Cursor):
    def __init__(self, model, point, points):
        self.model, self.block, self.offset, self.points = model, point[0], point[1], points
        super().__init__(model.graph[self.block][self.offset:], model.names)

    def take(self, pattern):
        result = super().take(pattern)
        self.points.add((self.block, self.offset + self.index - 1))
        return result

    def call(self, name):
        args = super().call(name)
        self.points.add((self.block, self.offset + self.index - 1))
        return args

    def gep(self, root, offset):
        value, = self.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                           + re.escape(root) + ', i64 ' + str(offset))
        return value

    def load(self, root, align=8):
        value, = self.take('(' + V + ') = load i8, ptr ' + re.escape(root) + ', align ' + str(align))
        return value

    def store(self, value, root, align=8):
        self.take('store i8 ' + re.escape(value) + ', ptr ' + re.escape(root) + ', align ' + str(align))

    def lifetime(self, operation, root):
        args = self.call('llvm.lifetime.' + operation + '.p0')
        require(len(args) in (1, 2) and syntax.operand(args[-1]) == root
                and (len(args) == 1 or args[0] == 'i64 ' + str(self.model.allocs[root])),
                'MD5 report Result lifetime changed')

    def copy(self, source, size, destination=None):
        args = self.call('llvm.memcpy.p0.p0.i64')
        require(len(args) == 4 and syntax.operand(args[1]) == source
                and args[2:] == ['i64 ' + str(size), 'i1 false'], 'MD5 report copy source/extent changed')
        dest = syntax.operand(args[0])
        require(destination is None or dest == destination, 'MD5 report copy destination changed')
        return dest

    def compare(self, value):
        result, = self.take('(' + V + ') = icmp eq i8 ' + re.escape(value) + ', 2')
        return result

    def branch(self, condition):
        bad, good = self.take('br i1 ' + re.escape(condition) + ', label %' + L + ', label %' + L)
        self.end()
        require(bad != good and bad in self.model.graph and good in self.model.graph, 'MD5 Result branch changed')
        return bad, good

    def jump(self, target):
        self.take('br label %' + re.escape(target))
        self.end()

    def stop(self, point):
        require((self.block, self.offset + self.index) == point, 'MD5 report transport has extra/missing instructions')


def allocation(model, root, size, use):
    require(root in model.allocs and model.allocs[root] == size
            and model.before(model.defs[root][1], use), 'MD5 report allocation extent/identity changed')


def audit(model, roots, points, consumer, report, partial=()):
    """No hidden stores/escapes or lifetime changes in the transport slice.

Mapped authentication Results outlive the report for tag/drop handling. Their
post-report reads/cleanup are deliberately outside this report-only check.
"""
    for root in roots:
        starts, ends = [], []
        for symbol, args, point in model.calls:
            if symbol.startswith('llvm.lifetime.') and model.pointer(syntax.operand(args[-1])) == (root, 0):
                operation = 'start' if symbol == 'llvm.lifetime.start.p0' else 'end'
                cursor = Cursor(model, point, points)
                cursor.lifetime(operation, root)
                (starts if operation == 'start' else ends).append(point)
        require(len(starts) == 1 and ends, 'MD5 report storage lifetime absent/duplicated')
        require(not any(a != b and model.can_precede(a, b) for a in ends for b in ends),
                'MD5 report storage lifetime ended twice on one path')
        if root not in partial:
            # Split verification results now end on several success/error
            # edges. One surviving end is not evidence for every other edge.
            # LLVM may omit lifetime.end when unwinding destroys the frame;
            # secret destruction on unwind is a separate cleanup obligation.
            pending = [(starts[0][0], starts[0][1] + 1)]
            visited = set()
            while pending:
                block, offset = pending.pop()
                if (block, offset) in visited:
                    continue
                visited.add((block, offset))
                for index in range(offset, len(model.graph[block])):
                    if (block, index) in ends:
                        break
                    line = model.graph[block][index]
                    require(not line.startswith('ret '),
                            'MD5 report storage escapes an exit without lifetime end: '
                            + root + ' at ' + block)
                    targets = re.findall('label %' + L, line)
                    if 'invoke ' in line:
                        if not targets and index + 1 < len(model.graph[block]):
                            continuation = model.graph[block][index + 1].split(', !', 1)[0]
                            require(re.fullmatch('to label %' + L + ' unwind label %' + L,
                                                 continuation), 'MD5 lifetime invoke continuation changed: ' + continuation)
                            targets = re.findall('label %' + L, continuation)
                        require(len(targets) == 2, 'MD5 lifetime invoke edges changed')
                        targets = targets[:1]
                    if targets:
                        pending.extend((target, 0) for target in targets)
                        break
        for point in tuple(points):
            line = model.graph[point[0]][point[1]]
            if 'llvm.lifetime.' in line:
                continue
            if any((p := model.pointer(token)) and p[0] == root for token in re.findall(V, line)):
                require(model.before(starts[0], point)
                        and not any(model.can_precede(end, point) for end in ends),
                        'MD5 report transfer uses storage outside its lifetime')
    for block, rows in model.graph.items():
        for index, line in enumerate(rows):
            point = block, index
            mentioned = {address[0] for token in re.findall(V, line)
                         if (address := model.pointer(token)) and address[0] in roots}
            if not mentioned or point in points:
                continue
            if re.fullmatch(V + r' = alloca \[\d+ x i8\], align \d+', line):
                continue
            # The only deliberately partial root is the mapped auth Result.
            # Never permit an unparsed modification, even after report use.
            if mentioned <= set(partial) and not model.can_precede(point, report):
                call = syntax.call(line)
                require(not line.startswith('store ') and not (call and call[0].startswith('llvm.mem')),
                        'MD5 report storage has an unreviewed overwrite')
                continue
            require(False, 'unreviewed MD5 report storage use: ' + line)
