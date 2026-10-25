"""Bind report backend/count operands and rejection paths to the real worker.

Report-byte transport from consumer Results is a separate obligation. Count
provenance proves a sum of eight distinct input-presence bits, not lane payloads.
"""
import re

import legacy_hmac_hosted_md5_boundaries as boundary

health, status = boundary.health, boundary.status
syntax, V, require = boundary.syntax, boundary.V, boundary.require


class Count:
    def __init__(self, model, envelope):
        require(40 in envelope['loads'], 'MD5 report input capture missing')
        self.m, self.input = model, envelope['loads'][40][1]
        self.pointers = syntax.pointers('\n'.join('\n'.join(rows) for rows in model.graph.values()), (self.input,))
        self.points = set()

    def expression(self, value, use, kind='i64', trail=()):
        require(value not in trail and len(trail) < 40, 'cyclic MD5 active-lane count')
        if value == '0' and kind == 'i64':
            return frozenset()
        require(value in self.m.defs, 'unbound MD5 active-lane count')
        rhs, point = self.m.defs[value]
        rhs = rhs.split(', !', 1)[0]
        require(self.m.before(point, use), 'MD5 count operand used before definition')
        self.points.add(point)
        trail = (*trail, value)
        if kind == 'i64':
            add = re.fullmatch('add(?: nuw| nsw)* i64 (' + V + '|0), (' + V + '|0)', rhs)
            if add:
                a, b = (self.expression(token, point, trail=trail) for token in add.groups())
                require(not a & b, 'MD5 active-lane count duplicates a slot')
                return a | b
            extend = re.fullmatch('zext i1 (' + V + ') to i64', rhs)
            require(extend, 'unreviewed MD5 active-count arithmetic')
            return self.expression(extend[1], point, 'i1', trail)
        compare = re.fullmatch('icmp ne ptr (' + V + '), null', rhs)
        require(kind == 'i1' and compare and compare[1] in self.m.defs, 'MD5 slot presence predicate changed')
        loaded, site = self.m.defs[compare[1]]
        loaded = loaded.split(', !', 1)[0]
        load = re.fullmatch('load ptr, ptr (' + V + '), align 8', loaded)
        require(load and self.m.before(site, point), 'MD5 slot presence not from an earlier pointer read')
        pointer = self.pointers.get(load[1])
        require(pointer and pointer[0] == self.input and pointer[1] in range(0, 320, 40),
                'MD5 active count reads a different input/field/slot')
        for address in (load[1], self.input):
            require(address in self.m.defs and self.m.before(self.m.defs[address][1], site),
                    'MD5 count input address used before definition')
            self.points.add(self.m.defs[address][1])
        self.points.add(site)
        return frozenset({pointer[1] // 40})


def check(model, transfer, envelope, compiler, target):
    require(80 in envelope['loads'], 'MD5 report backend capture missing')
    wanted = boundary.owners.owner(target) + '::md5_compiled::worker::report'
    reports = [(args, p) for s, args, p in model.calls if model.names.get(s) == wanted]
    require(len(reports) == 2, 'MD5 report-call population changed')
    counter, points = Count(model, envelope), set()
    protected = {transfer.keyed, *(p for _, p, _ in model.consumers), *(p for _, p in reports)}
    protected.update(p for s, _, p in model.calls if model.names.get(s) == 'brynja_core::secret_memory::copy_secret_region'
                     or model.names.get(s) == boundary.owners.owner(target) + '::md5_compiled::worker::checkpoint')
    ok = 10 if compiler == '1.90.0' else -1
    for args, point in reports:
        require(len(args) == 3 and 'dereferenceable(88)' in args[0]
                and args[1] == 'i8 ' + envelope['loads'][80][1]
                and args[2].startswith('i64 '), 'MD5 report parameters changed')
        require(model.before(envelope['loads'][80][0], point), 'MD5 backend capture used too early')
        require(counter.expression(args[2].split()[-1], point) == frozenset(range(8)),
                'MD5 active-lane count is incomplete')
        line = model.graph[point[0]][point[1]]
        result = re.match('(' + V + r') = (?:tail )?(?:call|invoke)(?: fastcc)? i8 @', line)
        require(result, 'MD5 report Result ABI changed')
        block, offset = health.returned(model, point)
        good, bad, _ = boundary.branch(model, block, offset, result[1], ok, points)
        require(not any(model.can_precede((bad, -1), use) for use in protected)
                and not model.can_precede((bad, -1), (good, -1)), 'MD5 report rejection resumes work')
        points.update(status.walk(model, envelope, bad, block, {result[1]: status.literal(8, 8)}, 8))
        points.add(point)
    return counter, points
