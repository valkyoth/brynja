"""Inlined MD5 selector-health probes and post-operation placement.

No secret owner is created here. The 24-byte selector borrows the admitted
executor; no selector payload can escape the short check. Lane, report and
host transaction qualification are distinct composing obligations.
"""
import re

import legacy_hmac_hosted_md5_checkpoint as callee
import legacy_hmac_hosted_md5_status as status

require, syntax, V, L = callee.require, callee.syntax, callee.V, callee.L


def returned(model, point):
    if 'invoke ' not in model.graph[point[0]][point[1]]:
        return point[0], point[1] + 1
    edge = re.fullmatch('to label %' + L + ' unwind label %' + L,
                        model.graph[point[0]][point[1] + 1].split(', !', 1)[0])
    require(edge, 'MD5 health constructor invoke edges changed')
    return edge[1], 0


def mandatory(model, start, target):
    """Every normal consumer-return path must revalidate before using its Result."""
    queue, visited = [(start, frozenset())], set()
    while queue:
        point, path = queue.pop()
        if point == target:
            continue
        require(point not in path, 'MD5 health prevalidation continuation cycles')
        path = path | {point}
        visited.add(point)
        require(len(visited) < 256, 'MD5 health prevalidation continuation exceeds bound')
        block, index = point
        lines = model.graph[block]
        require(index < len(lines), 'MD5 health continuation falls off a block')
        line = lines[index]
        call = syntax.call(line)
        if call:
            require(call[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0',
                                'llvm.memcpy.p0.p0.i64', 'llvm.assume') and 'invoke ' not in line,
                    'MD5 consumer result reaches work before health revalidation')
        require(not line.startswith(('ret ', 'resume ', 'unreachable')),
                'MD5 consumer return bypasses health revalidation')
        if line.startswith('br '):
            edges = re.findall('label %' + L, line)
            require(edges, 'MD5 health continuation branch changed')
            queue.extend(((edge, 0), path) for edge in edges)
        else:
            queue.append(((block, index + 1), path))
    return visited


def check(model, transfer, envelope, compiler):
    calls = [(args, point) for symbol, args, point in model.calls if model.names.get(symbol) == callee.NEW]
    require(len(calls) == 3, 'MD5 health probe population changed')
    records, points, roots = [], set(), set()
    for args, point in calls:
        require(len(args) == 2 and model.pointer(syntax.operand(args[1]), point) == (transfer.owner, 0)
                and 'sret([24 x i8])' in args[0], 'MD5 health executor/result provenance changed')
        destination = model.pointer(syntax.operand(args[0]), point)
        require(destination and destination[1] == 0 and model.allocs.get(destination[0]) == 24
                and destination[0] not in {model.owner, transfer.owner, transfer.result, *model.results, *roots},
                'MD5 health Result aliases persistent/other storage')
        root = destination[0]
        roots.add(root)
        require(model.before(model.defs[root][1], point), 'MD5 health Result not allocated')
        begin = callee.Cursor(model.graph[point[0]][point[1] - 1:point[1]], model.names)
        begin.lifetime('start', root)
        begin.end()
        points.update((point, (point[0], point[1] - 1)))
        if 'invoke ' in model.graph[point[0]][point[1]]:
            points.add((point[0], point[1] + 1))
        block, offset = returned(model, point)
        cursor = callee.Cursor(model.graph[block][offset:], model.names)
        address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + re.escape(root) + ', i64 16')
        loaded, = cursor.take('(' + V + ') = load i8, ptr ' + re.escape(address) + ', align 8')
        condition, = cursor.take('(' + V + ') = icmp eq i8 ' + re.escape(loaded) + ', 2')
        bad, good = cursor.take('br i1 ' + re.escape(condition) + ', label %' + L + ', label %' + L)
        cursor.end()
        points.update((block, i) for i in range(offset, len(model.graph[block])))
        require(good != bad and good in model.graph and bad in model.graph, 'MD5 health admission edges changed')
        failure = callee.Cursor(model.graph[bad], model.names)
        error, = failure.take('(' + V + ') = load i8, ptr ' + re.escape(root) + ', align 8')
        failure.lifetime('end', root)
        failed = (bad, failure.index)
        points.update((bad, i) for i in range(failure.index))
        success = callee.Cursor(model.graph[good], model.names)
        if compiler == '1.90.0':
            callee.nonnull(success, root)
        else:
            success.lifetime('end', root)
        points.update((good, i) for i in range(success.index))
        records.append((point, (good, success.index), (bad, failed, error)))
        points.update(status.walk(model, envelope, bad, block, {error: status.ERROR}, 7, status.ERROR,
                                  offset=failed[1]))
    for block, rows in model.graph.items():
        for index, line in enumerate(rows):
            mentions = [name for name in re.findall(V, line)
                        if (address := model.pointer(name)) and address[0] in roots]
            if not mentions:
                continue
            if re.fullmatch(V + r' = alloca \[24 x i8\], align 8', line):
                continue
            require((block, index) in points, 'MD5 health selector escapes its checked lifetime')
    consumers = [point for _, point, _ in model.consumers]
    after = {}
    for consumer in consumers:
        start = returned(model, consumer)
        following = [record for record in records if model.before((start[0], start[1] - 1), record[0])]
        require(len(following) == 1, 'MD5 terminal health revalidation missing/ambiguous')
        after[consumer] = following[0]
        # Ordering only: the prefix marshals the consumer Result. Its byte
        # provenance is a separate obligation, not a checked-health point.
        mandatory(model, start, following[0][0])
    initial = [record for record in records if record not in after.values()]
    require(len(initial) == 1 and model.before(initial[0][0], transfer.keyed),
            'MD5 initial health admission missing')
    protected = {transfer.keyed, *consumers, *(record[0] for record in records)}
    for _, success, (bad, failed, _) in records:
        require(not any(model.can_precede((failed[0], failed[1] - 1), use) for use in protected)
                and not model.can_precede((failed[0], failed[1] - 1), (success[0], -1)),
                'MD5 health failure resumes keyed work')
    return records, initial[0], after, points
