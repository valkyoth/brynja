"""MD5 initial/pre-copy/final admission in the real optimized worker.

Composition landmarks, not a proof of lane/report correctness or of the host
transaction. The outlined callee and inlined health checks are validated first.
"""
import re

import legacy_hmac_hosted_md5_health as health
import legacy_hmac_hosted_checkpoints as owners

callee, status = health.callee, health.status
V, L, syntax, require = health.V, health.L, health.syntax, health.require


def branch(model, block, offset, value, expected, points, aggregate=None):
    cursor = callee.Cursor(model.graph[block][offset:], model.names)
    condition, = cursor.take('(' + V + ') = icmp eq i8 ' + re.escape(value) + ', ' + str(expected))
    payload = None
    if aggregate is not None:
        payload, = cursor.take('(' + V + r') = extractvalue \{ i8, i8 \} ' + re.escape(aggregate) + ', 1')
    good, bad = cursor.take('br i1 ' + re.escape(condition) + ', label %' + L + ', label %' + L)
    cursor.end()
    require(good != bad and good in model.graph and bad in model.graph, 'MD5 checkpoint admission edges changed')
    points.update((block, i) for i in range(offset, len(model.graph[block])))
    return good, bad, payload


def check(model, transfer, envelope, compiler, target, health_result):
    records, initial, after, _ = health_result
    points, guards = set(), {}
    cancel = envelope['loads'][56][1]
    ok = 10 if compiler == '1.90.0' else -1
    wanted = owners.owner(target) + '::md5_compiled::worker::checkpoint'
    for symbol, args, point in model.calls:
        if model.names.get(symbol) != wanted:
            continue
        require(len(args) == 2 and model.pointer(syntax.operand(args[0]), point) == (transfer.owner, 0)
                and syntax.operand(args[1]) == cancel and model.before(model.defs[cancel][1], point),
                'MD5 checkpoint executor/cancellation capture changed')
        line = model.graph[point[0]][point[1]]
        result = re.match('(' + V + r') = (?:tail )?(?:call|invoke)(?: fastcc)? \{ i8, i8 \} @', line)
        require(result, 'MD5 checkpoint aggregate Result ABI changed')
        block, offset = health.returned(model, point)
        cursor = callee.Cursor(model.graph[block][offset:offset + 1], model.names)
        tag, = cursor.take('(' + V + r') = extractvalue \{ i8, i8 \} ' + re.escape(result[1]) + ', 0')
        good, bad, payload = branch(model, block, offset + 1, tag, ok, points,
                                    result[1] if compiler == '1.90.0' else None)
        points.update((point, (block, offset)))
        guards[point] = (good, bad, block, result[1], tag)
        for code in (6, 7):
            known = {result[1]: (status.literal(code, 8), status.ERROR), tag: status.literal(code, 8)}
            if payload:
                known[payload] = status.ERROR
            points.update(status.walk(model, envelope, bad, block, known, code,
                                      status.ERROR if code == 7 else None))
    require(len(guards) == 2, 'MD5 outlined checkpoint population changed')
    block, offset = initial[1]
    cursor = callee.Cursor(model.graph[block][offset:offset + 1], model.names)
    atomic, = cursor.take('(' + V + ') = load atomic i8, ptr ' + re.escape(cancel) + ' acquire, align 1')
    good, bad, _ = branch(model, block, offset + 1, atomic, 0, points)
    points.add((block, offset))
    require(model.before((good, -1), transfer.keyed), 'MD5 initial cancellation bypassed')
    points.update(status.walk(model, envelope, bad, block, {}, 6))
    copies = [p for s, _, p in model.calls if model.names.get(s) == 'brynja_core::secret_memory::copy_secret_region']
    reports = [p for s, _, p in model.calls if model.names.get(s) == owners.owner(target)
               + '::md5_compiled::worker::report']
    require(copies and len(reports) == 2, 'MD5 output/report landmarks missing')
    pre = [p for p in guards if all(model.before((guards[p][0], -1), use) for use in copies)]
    require(len(pre) == 1, 'MD5 pre-copy checkpoint missing/ambiguous')
    pre = pre[0]
    post, = set(guards) - {pre}
    consumer_calls = {p: model.names[s] for s, _, p in model.calls if p in after}
    auth = [p for p, name in consumer_calls.items() if name.endswith('::authenticate_secret')]
    verify = [p for p, name in consumer_calls.items() if name.endswith('::verify_inner')]
    require(len(auth) == len(verify) == 1, 'MD5 consumer landmark identity changed')
    require(model.before((after[auth[0]][1][0], -1), pre)
            and any(model.before(p, pre) for p in reports), 'MD5 pre-copy admission precedes health/report')
    require(all(model.can_precede(health.returned(model, use), post) and not model.can_precede(post, use)
                for use in (*copies, *reports, *consumer_calls)), 'MD5 final checkpoint precedes terminal work')
    protected = {transfer.keyed, *consumer_calls, *copies, *reports, *guards, *(r[0] for r in records)}
    for _, _, (_, failed, _) in records:
        require(not any(model.can_precede((failed[0], failed[1] - 1), use) for use in protected),
                'MD5 rejected health probe resumes report/output/checkpoint work')
    for success, failure in [(good, bad), *((g[0], g[1]) for g in guards.values())]:
        require(not any(model.can_precede((failure, -1), use) for use in protected)
                and not model.can_precede((failure, -1), (success, -1)), 'MD5 checkpoint rejection resumes work')
    success, _, predecessor, result, tag = guards[post]
    points.update(status.walk(model, envelope, success, predecessor,
                              {result: (status.literal(ok, 8), status.ERROR), tag: status.literal(ok, 8)}, ok))
    return points, guards
