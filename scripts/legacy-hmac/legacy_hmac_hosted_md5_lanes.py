"""Unrolled hosted MD5 slot construction and descriptor provenance.

Each of the eight independent presence branches has the same checked transfer;
this composes for every activity mask, not only sampled lane populations.
BitString::new's validation semantics remain a separately reviewed callee premise.
"""
import re

import legacy_hmac_hosted_md5_result_tools as t

V, require, syntax, health = t.V, t.require, t.syntax, t.health
BITS = '<brynja_hash_core::bit_string::BitString>::new'


class Cursor(t.Cursor):
    def read(self, kind, address, align=8):
        value, = self.take('(' + V + ') = load ' + kind + ', ptr ' + re.escape(address) + ', align ' + str(align))
        return value

    def write(self, kind, value, address, align=8):
        self.take('store ' + kind + ' ' + re.escape(value) + ', ptr ' + re.escape(address) + ', align ' + str(align))

    def null(self, value):
        condition, = self.take('(' + V + ') = icmp eq ptr ' + re.escape(value) + ', null')
        return self.branch(condition)


class Lanes:
    def __init__(self, model, transfer, envelope, health_result):
        self.m, self.transfer, self.envelope = model, transfer, envelope
        require(40 in envelope['loads'], 'MD5 lane inputs not captured')
        self.input = envelope['loads'][40][1]
        self.points, self.fills, self.reads = set(), [], []
        self.parents = {block: set() for block in model.graph}
        for parent, rows in model.graph.items():
            for child in re.findall('label %' + t.L, '\n'.join(rows)):
                require(child in self.parents, 'MD5 lane CFG has a missing target')
                self.parents[child].add(parent)
        self.factories = {p: (s, a) for s, a, p in model.calls if model.names.get(s) == BITS}
        require(len(self.factories) == 8, 'MD5 bit-message constructor population changed')
        self.result, = {syntax.operand(a[0]) for _, a in self.factories.values()}
        consumers = [next(a for _, a, p in model.calls if p == use) for _, use, _ in model.consumers]
        lanes = {syntax.operand(args[2]) for args in consumers}
        require(len(lanes) == 1 and all('dereferenceable(384)' in a[2] for a in consumers),
                'MD5 consumers do not borrow the same complete lane array')
        self.lanes = lanes.pop()
        self.starts = [p for s, a, p in model.calls if s == 'llvm.lifetime.start.p0'
                       and syntax.operand(a[-1]) == self.lanes]
        require(len(self.starts) == 1, 'MD5 lane lifetime entry changed')
        self.start = self.starts[0]
        t.allocation(model, self.lanes, 384, self.start)
        t.allocation(model, self.result, 32, self.start)
        require(model.before(envelope['loads'][40][0], self.start), 'MD5 lanes precede input capture')
        # Initial health/cancellation admission must lead to the construction
        # entry, not skip slots or launch a consumer directly.
        first = health_result[1][1]
        rows = model.graph[first[0]]
        match = re.fullmatch('br i1 ' + V + ', label %' + t.L + ', label %' + t.L, rows[-1])
        require(match and match[1] == self.start[0] and self.start[1] == 0,
                'MD5 initial checkpoint skips lane construction')
        self.require_parents(self.start[0], {first[0]})

    def require_parents(self, block, expected):
        require(self.parents.get(block) == expected, 'MD5 lane chain has a bypass/reentry edge')

    def cursor(self, point):
        return Cursor(self.m, point, self.points)

    def construct(self, index, block, key, next_block, destination):
        m = self.m
        cursor = self.cursor((block, 0))
        call = syntax.call(cursor.rows[0])
        require(call and call[0] == 'llvm.lifetime.start.p0', 'MD5 lane scratch not started')
        scratch = syntax.operand(call[1][-1])
        t.allocation(m, scratch, 22, self.start)
        if index == 0:
            self.scratch = scratch
        require(scratch == self.scratch and scratch not in (self.result, self.lanes), 'MD5 lane scratch alias changed')
        cursor.lifetime('start', scratch)
        length = cursor.read('i64', cursor.gep(self.input, index * 40 + 8))
        cursor.lifetime('start', self.result)
        message = cursor.read('ptr', cursor.gep(self.input, index * 40 + 16))
        message_length = cursor.read('i64', cursor.gep(self.input, index * 40 + 24))
        bits = cursor.read('i8', cursor.gep(self.input, index * 40 + 32))
        site = block, cursor.index
        require(site in self.factories, 'MD5 lane does not call canonical BitString constructor')
        _, args = self.factories[site]
        require(len(args) == 4 and 'sret([32 x i8])' in args[0]
                and [arg.split()[0] for arg in args] == ['ptr', 'ptr', 'i64', 'i8']
                and [arg.split()[-1] for arg in args] == [self.result, message, message_length, bits],
                'MD5 lane message pointer/length/valid-bits substituted')
        self.points.add(site)
        self.reads.append((index, key, length, message, message_length, bits, site))
        returned = health.returned(m, site)
        if returned[0] != block:
            self.require_parents(returned[0], {block})
        cursor = self.cursor(returned)
        descriptor = cursor.read('ptr', self.result)
        bad, good = cursor.null(descriptor)
        self.failures.add(bad)
        self.require_parents(good, {returned[0]})
        cursor = self.cursor((good, 0))
        low = cursor.read('i8', self.result_offsets[0])
        high = cursor.read('i8', self.result_offsets[1], 1)
        cursor.copy(self.result_offsets[2], 22, scratch)
        cursor.lifetime('end', self.result)
        cursor.write('ptr', key, destination)
        cursor.write('i64', length, cursor.gep(self.lanes, index * 48 + 8))
        cursor.write('ptr', descriptor, cursor.gep(self.lanes, index * 48 + 16))
        cursor.write('i8', low, cursor.gep(self.lanes, index * 48 + 24))
        cursor.write('i8', high, cursor.gep(self.lanes, index * 48 + 25), 1)
        cursor.copy(scratch, 22, cursor.gep(self.lanes, index * 48 + 26))
        cursor.lifetime('end', scratch)
        cursor.jump(next_block)
        self.fills.append(good)

    def check(self):
        cursor = self.cursor(self.start)
        cursor.lifetime('start', self.lanes)
        self.result_offsets = [cursor.gep(self.result, offset) for offset in (8, 9, 10)]
        args = cursor.call('llvm.memset.p0.i64')
        require(len(args) == 4 and syntax.operand(args[0]) == self.lanes
                and args[1:] == ['i8 0', 'i64 384', 'i1 false'], 'MD5 inactive lanes not initialized')
        self.failures, gates = set(), []
        for index in range(8):
            destination = self.lanes if index == 0 else cursor.gep(self.lanes, index * 48)
            source = self.input if index == 0 else cursor.gep(self.input, index * 40)
            key = cursor.read('ptr', source)
            gates.append(cursor.block)
            next_block, present = cursor.null(key)
            self.require_parents(present, {cursor.block})
            self.construct(index, present, key, next_block, destination)
            self.require_parents(next_block, {cursor.block, self.fills[-1]})
            cursor = self.cursor((next_block, 0))
        require(len(set(gates + self.fills)) == 16 and len(self.failures) == 1,
                'MD5 lane construction skips/repeats a slot or changes failure merge')
        require(cursor.block == self.transfer.keyed[0], 'MD5 final slot does not lead to selector admission')
        while cursor.index < self.transfer.keyed[1]:
            call = syntax.call(cursor.rows[cursor.index])
            require(call and call[0] == 'llvm.lifetime.start.p0', 'MD5 final lane enters unreviewed work')
            selected = syntax.operand(call[1][-1])
            require(selected in self.m.roots, 'MD5 final lane starts unrelated selector storage')
            cursor.lifetime('start', selected)
        cursor.stop(self.transfer.keyed)
        bad = self.failures.pop()
        cursor = self.cursor((bad, 0))
        cursor.lifetime('end', self.result)
        cursor.lifetime('end', self.scratch)
        target, = cursor.take('br label %' + t.L)
        cursor.end()
        uses = [self.transfer.keyed, *(p for _, p, _ in self.m.consumers), *self.factories]
        require(not any(self.m.can_precede((bad, -1), p) for p in uses), 'invalid MD5 message resumes lane/keyed work')
        self.points.update(health.status.walk(self.m, self.envelope, target, bad, {}, 4))
        self.audit()
        return self

    def audit(self):
        m, roots = self.m, {self.lanes, self.result, self.scratch}
        consumers = {p for _, p, _ in m.consumers}
        require({row[-1] for row in self.reads} == set(self.factories), 'MD5 constructor correspondence incomplete')
        ends = []
        for symbol, args, point in m.calls:
            if symbol == 'llvm.lifetime.end.p0' and syntax.operand(args[-1]) == self.lanes:
                self.cursor(point).lifetime('end', self.lanes)
                ends.append(point)
        require(ends and not any(m.can_precede(end, use) for end in ends for use in consumers | set(self.factories)),
                'MD5 lane array expires before validation/consumer')
        require(not any(a != b and m.can_precede(a, b) for a in ends for b in ends),
                'MD5 lane lifetime ends twice on a path')
        for symbol, args, point in m.calls:
            if point in consumers:
                require(m.pointer(syntax.operand(args[2]), point) == (self.lanes, 0)
                        and not any(m.pointer(syntax.operand(a)) == (self.lanes, 0)
                                    for i, a in enumerate(args) if i != 2), 'MD5 lane array aliases another consumer argument')
                self.points.add(point)
        for block, lines in m.graph.items():
            for index, line in enumerate(lines):
                if not any((p := m.pointer(v)) and p[0] in roots for v in re.findall(V, line)):
                    continue
                if re.fullmatch(V + r' = alloca \[\d+ x i8\], align \d+', line):
                    continue
                require((block, index) in self.points, 'MD5 lane/result storage has unreviewed read/write/escape: ' + line)


def check(model, transfer, envelope, health_result):
    return Lanes(model, transfer, envelope, health_result).check()
