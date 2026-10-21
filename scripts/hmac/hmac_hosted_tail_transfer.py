"""Tail Result admission and exact constructor-to-finalizer representation flow."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax

require, V, L = common.require, syntax.VALUE, common.LABEL


class Transfer:
    def __init__(self, split, call):
        self.split, self.i, self.m = split, split.i, split.m
        self.call = call
        self.result = self.m.pointer(syntax.operand(call[1][0]), call[2])
        require(self.result and self.result[1] == 0 and self.m.allocs[self.result[0]] == 32,
                'tail constructor Result geometry')
        self.returned = self.i.returned(call[2])
        require(not any((address := self.m.pointer(dest, point)) and address[0] == self.result[0]
                        for _, point, dest, _ in self.m.writes), 'tail constructor Result overwritten')

    def guard(self, use):
        m, guards = self.m, []
        for value, (rhs, point) in m.defs.items():
            comparison = re.fullmatch(r'icmp eq ptr (' + V + '), null', rhs)
            if not comparison or comparison[1] not in m.defs:
                continue
            load, at = m.defs[comparison[1]]
            operand = re.match(r'load ptr, ptr (' + V + '),', load)
            if not operand or m.pointer(operand[1], at) != self.result:
                continue
            require(m.before(self.returned, at), 'tail Result read before return')
            require(m.before(at, point), 'tail discriminator read does not dominate guard')
            condition, failure, success = self.i.branch(point[0])
            require(condition == value and m.before((success, -1), use), 'tail use lacks successful admission')
            require(not m.can_precede((failure, -1), use), 'tail error reaches successful consumer')
            self.i.points.update((point, at))
            guards.append(success)
        require(len(guards) == 1, 'tail Result admission absent/ambiguous')
        return guards[0]

    def origins(self, address, size, use, trail=()):
        m = self.m
        require(address and address[0] in m.allocs and 0 <= address[1] <= m.allocs[address[0]] - size,
                'tail transfer outside local representation')
        require(address not in trail and len(trail) < 16, 'cyclic tail representation transfer')
        if address[0] == self.result[0]:
            require(m.before(self.returned, use), 'tail transfer before constructor return')
            return tuple(range(address[1], address[1] + size))
        bytes_ = [None] * size
        for mode, point, dest, data in m.writes:
            at = m.pointer(dest, point)
            if not at or at[0] != address[0]:
                continue
            if mode == 'copy':
                extent = re.fullmatch(r'i64 (\d+)', data[2])
                require(extent, 'dynamic typed-tail transfer')
                count = int(extent[1])
                source = m.pointer(syntax.operand(data[1]), point)
                source_use = point
            else:
                scalar = re.fullmatch(r'(ptr|i8|i64) (' + V + ')', data)
                require(scalar, 'typed-tail store not from constructor bytes')
                count = 1 if scalar[1] == 'i8' else 8
                rhs, source_use = m.defs.get(scalar[2], ('', None))
                load = re.match(r'load ' + scalar[1] + ', ptr (' + V + '),', rhs)
                require(load and m.before(source_use, point), 'typed-tail field not a dominating load')
                source = m.pointer(load[1], source_use)
                self.i.points.add(source_use)
            start, end = at[1] - address[1], at[1] - address[1] + count
            if end <= 0 or start >= size:
                continue
            require(m.before(point, use), 'typed-tail transfer overwritten or conditionally initialized')
            require(0 <= start < end <= size, 'typed-tail transfer straddles requested field')
            values = self.origins(source, count, source_use, (*trail, address))
            require(all(byte is None for byte in bytes_[start:end]), 'overlapping typed-tail initialization')
            bytes_[start:end] = values
            self.i.points.add(point)
        require(all(byte is not None for byte in bytes_), 'incomplete typed-tail representation')
        return tuple(bytes_)


def check(split):
    full, partial = Transfer(split, split.full), Transfer(split, split.partial)
    full.guard(split.m.defs[split.i.split][1])
    for factory in split.m.factories:
        partial.guard(factory)
    partial.guard(split.m.cut)
    terminal_points = {point for _, point, _ in split.m.terminals}
    for _, args, point in split.m.calls:
        if point not in terminal_points:
            continue
        # verify(self, tail, candidate) versus secret(sret, self, tail, staging).
        index = 2 if len(args) == 5 else 1
        address = split.m.pointer(syntax.operand(args[index]), point)
        partial.guard(point)
        require(partial.origins(address, 32, point) == tuple(range(32)),
                'finalizer tail is not the admitted partial-tail representation')
