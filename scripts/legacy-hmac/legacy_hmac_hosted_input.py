"""Legacy streaming-worker input provenance on genuine emitted LLVM.

The shared iterator interpreter is unchanged. Constructor updates are excluded
only when dominated by the separately checked constructor prefix; no instruction
or CFG edge is rewritten. This is not the eight-lane MD5 batch input model.
"""
import copy
import re

import legacy_hmac_engine_codegen as legacy
import legacy_hmac_hosted_construct_model as construction

shared = legacy.load('hmac_hosted_input')
tail = legacy.load('hmac_hosted_tail')
require, syntax, V, L = shared.require, shared.syntax, shared.V, shared.L


class Input(shared.Input):
    def success(self):
        m = self.m
        returned = re.match('(' + V + ') = ', m.graph[self.update[0]][self.update[1]])
        require(returned, 'legacy input update does not return a result')
        # Result<(), legacy_hmac::Error>, not the modern HMAC error enum.
        ok = -1 if self.compiler == '1.99.1' else 8
        success_target = self.latch if self.rotated else self.part_header
        guard = self.returned(self.update)[0] if self.rotated else self.latch
        if self.rotated:
            for predecessor in self.predecessors(self.latch) - {guard}:
                condition, success, failure = self.branch(predecessor)
                self.match(condition, r'icmp eq i8 ' + re.escape(returned[1]) + ', ' + str(ok))
                require(success == self.latch and failure != self.latch, 'legacy rotated input admission bypass')
        lines = m.graph[guard]
        switches = [index for index, line in enumerate(lines) if line.startswith('switch ')]
        if switches:
            require(len(switches) == 1, 'unexpected legacy input update switch')
            start = switches[0]
            self.points.update((guard, index) for index in range(start, len(lines)))
            text = '\n'.join(lines[start:]).split(']', 1)[0] + ']'
            match = re.fullmatch(r'switch i8 ' + re.escape(returned[1]) + ', label %' + L
                                 + r' \[\n((?:i8 -?\d+, label %' + L + r'\n)+)\]', text)
            require(match, 'legacy input update switch result changed')
            cases = re.findall(r'i8 (-?\d+), label %' + L, match[2])
            require(len({value for value, _ in cases}) == len(cases), 'duplicate legacy input result case')
            require([(value, label) for value, label in cases if label == success_target]
                    == [(str(ok), success_target)] and match[1] != success_target,
                    'legacy input update error advances iterator')
        else:
            condition, success, failure = self.branch(guard)
            self.match(condition, r'icmp eq i8 ' + re.escape(returned[1]) + ', ' + str(ok))
            require(success == success_target and failure != success, 'legacy input update success edge changed')
        self.failed_updates(returned[1], ok)


class Split(tail.Split):
    def constructors(self):
        m = self.m
        calls = [(symbol, args, point) for symbol, args, point in m.calls
                 if m.names.get(symbol) == '<brynja_hash_core::bit_string::BitString>::new']
        require(len(calls) == 2 and calls[0][0] == calls[1][0]
                and all(len(args) == 4 for _, args, _ in calls), 'legacy tail constructor population changed')
        whole = [row for row in calls if m.before(row[2], m.defs[self.i.split][1])]
        require(len(whole) == 1, 'legacy whole tail validation does not precede split')
        full = whole[0]
        partial = next(row for row in calls if row != full)
        require(m.before(m.defs[self.i.split][1], partial[2]), 'legacy partial tail constructed before split')
        require(self.arguments(full[1], full[2]) == [self.i.tail_base, self.length, self.bits],
                'legacy whole tail does not validate captured bits')
        pointer, length, bits = self.arguments(partial[1], partial[2])
        self.i.gep(pointer, self.i.tail_base, self.i.split)
        for empty in (False, True):
            for byte in (False, True):
                require(self.value(length, empty, byte) == (0, int(not empty and not byte)),
                        'legacy partial tail length changed')
                expected = (0, 0) if empty or byte else 'non-eight'
                require(self.value(bits, empty, byte) == expected, 'legacy partial tail valid-bit count changed')
        self.i.points.update((full[2], partial[2]))
        self.full, self.partial = full, partial
        tail.transfer.check(self)


def projection(model, envelope, panic):
    require(model.identity in ('sha1', 'md5', 'sha1_compiled'), 'unreviewed legacy streaming identity')
    result = copy.copy(model)
    result.names = dict(model.names)
    if model.compiled:
        name = '<brynja_legacy_hmac::execution::Sha1Hmac>::update'
        symbols = [symbol for symbol, current in model.names.items() if current == name]
        require(len(symbols) == 1, 'legacy SHA-1 message update identity missing/ambiguous')
        # Selector adaptation only: the owner interpreter already checks this
        # exact legacy callee and its owner argument independently.
        result.names[symbols[0]] = '<legacy_Sha1Hmac>::update_cpu'
    else:
        prefix = construction.Model(model, envelope, panic)
        starts = [point for symbol, args, point in model.calls if symbol == 'llvm.lifetime.start.p0'
                  and model.pointer(syntax.operand(args[-1]), point) == prefix.pad]
        require(len(starts) == 1, 'legacy scalar pad lifetime start population')
        result.factories = {starts[0]: prefix.pad}
        updates = [(symbol, args, point) for symbol, args, point in model.calls
                   if legacy.adapter_update(symbol, model.identity)]
        prior = {point for _, _, point in updates if model.can_precede(point, model.cut)
                 and not model.can_precede(model.cut, point)}
        require(len(prior) == 3 and len(updates) == 4, 'legacy constructor/message update population')
        require(all(model.before(starts[0], point) for point in prior), 'legacy prefix update precedes pad lifetime')
        result.calls = [row for row in model.calls if row[2] not in prior]
    return result


def check(model, arguments, envelope, panic, compiler):
    result = Input(projection(model, envelope, panic), arguments, compiler)
    result.parts()
    result.chunks()
    result.success()
    result.iteration()
    result.tail = Split(result)
    result.tail.check()
    result.tail.constructors()
    return result
