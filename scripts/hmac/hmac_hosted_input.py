"""Paired hosted input iterators in emitted LLVM, not message arithmetic proof."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_tail as tail

require, V, L = common.require, syntax.VALUE, common.LABEL


class Input:
    def __init__(self, model, arguments, compiler):
        self.m = model
        self.compiler = compiler
        require(compiler in ('1.90.0', '1.99.1'), 'unreviewed input compiler')
        params = syntax.parameters(arguments)
        require(len(params) == 1, 'input worker parameter population')
        self.job = syntax.operand(params[0])
        self.shift = 8 if model.compiled else 0
        self.points = set()

    def rhs(self, value):
        require(value in self.m.defs, 'missing input SSA value: ' + value)
        rhs, point = self.m.defs[value]
        self.points.add(point)
        return rhs.split(', !', 1)[0]

    def match(self, value, pattern):
        found = re.fullmatch(pattern, self.rhs(value))
        require(found, 'unreviewed input expression: ' + self.rhs(value))
        return found

    def phi(self, value, kind):
        rhs = self.rhs(value)
        require(rhs.startswith('phi ' + kind + ' '), 'input iterator is not a typed phi')
        entries = re.findall(r'\[ (' + V + r'|null|\d+), %' + L + r' \]', rhs)
        require(len(entries) == 2 and len({label for _, label in entries}) == 2,
                'input iterator predecessor population')
        require(rhs == 'phi ' + kind + ' ' + ', '.join('[ ' + item + ', %' + label + ' ]'
                for item, label in entries), 'input phi contains unparsed entries')
        block = self.m.defs[value][1][0]
        predecessors = {label for label, lines in self.m.graph.items()
                        if block in re.findall(r'label %' + L, '\n'.join(lines))}
        require(predecessors == {label for _, label in entries}, 'input phi incoming edges changed')
        for item, label in entries:
            require(block in re.findall(r'label %' + L, '\n'.join(self.m.graph[label])),
                    'input phi predecessor has no edge')
            if item in self.m.defs:
                require(self.m.before(self.m.defs[item][1], (label, len(self.m.graph[label]))),
                        'input phi value does not dominate incoming edge')
        return {label: item for item, label in entries}

    def gep(self, value, base, offset, width='i8'):
        self.match(value, r'getelementptr(?: inbounds)?(?: nuw)? ' + re.escape(width)
                   + r', ptr ' + re.escape(base) + r', i64 ' + re.escape(offset))

    def field(self, value, kind, offset):
        load = self.match(value, r'load ' + kind + r', ptr (' + V + r'), align \d+(?:,.*)?')
        if offset:
            self.gep(load[1], self.job, str(offset + self.shift))
        else:
            require(load[1] == self.job, 'input job field changed')
        return value

    def branch(self, block):
        lines = self.m.graph[block]
        match = re.fullmatch(r'br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?', lines[-1])
        require(match, 'input loop branch changed')
        self.points.add((block, len(lines) - 1))
        return match.groups()

    def pair(self, pointer, length):
        pointers, lengths = self.phi(pointer, 'ptr'), self.phi(length, 'i64')
        require(pointers.keys() == lengths.keys() and self.m.defs[pointer][1][0] == self.m.defs[length][1][0],
                'input pointer/length predecessor mismatch')
        return {label: (value, lengths[label]) for label, value in pointers.items()}

    def returned(self, point):
        line = self.m.graph[point[0]][point[1]]
        if not re.search(r'\binvoke\b', line):
            return point
        edges = self.m.graph[point[0]][point[1] + 1]
        match = re.fullmatch(r'to label %' + L + r' unwind label %' + L + r'(?:, !.*)?', edges)
        require(match, 'input update invoke edges changed')
        return match[1], -1

    def parts(self):
        m = self.m
        calls = [(symbol, args, point) for symbol, args, point in m.calls
                 if m.names.get(symbol, '').endswith(('::Hash>::update', '>::update_cpu',
                                                      '::Sha512T>::update', '::HardenedSha512T>::update'))]
        require(len(calls) == 1 and len(calls[0][1]) == 3, 'hosted input update population')
        self.update = calls[0][2]
        self.update_symbol = calls[0][0]
        args = calls[0][1]
        self.pointer = syntax.operand(args[1])
        length = re.search('(' + V + ')$', args[2])
        require(length and args[2].startswith('i64 '), 'input update length substituted')
        self.amount = length[1]
        minimum = self.match(self.amount, r'call(?: noundef)? i64 @llvm.umin.i64\(i64 (' + V + r'), i64 4096\)')
        self.remaining = minimum[1]
        pair = self.pair(self.pointer, self.remaining)
        back = [label for label in pair if m.before(self.returned(self.update), (label, len(m.graph[label])))]
        require(len(back) == 1, 'input part advance not bound to successful update return')
        self.latch = back[0]
        next_pointer, next_length = pair[self.latch]
        self.gep(next_pointer, self.pointer, self.amount)
        self.match(next_length, r'sub(?: nuw)?(?: nsw)? i64 ' + re.escape(self.remaining) + ', ' + re.escape(self.amount))
        self.part_header = m.defs[self.pointer][1][0]
        entry = next(label for label in pair if label != self.latch)
        self.chunk_pointer, self.chunk_length = pair[entry]
        self.chunk_pair = self.pair(self.chunk_pointer, self.chunk_length)
        self.part_entry = entry
        header_branch = re.fullmatch(r'br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?',
                                     m.graph[self.part_header][-1])
        self.rotated = not (header_branch and m.defs.get(header_branch[1], ('', None))[0]
                            == 'icmp eq i64 ' + self.remaining + ', 0')
        if not self.rotated:
            condition, exhausted, more = self.branch(self.part_header)
            self.match(condition, r'icmp eq i64 ' + re.escape(self.remaining) + ', 0')
            require(m.before((more, -1), self.update), 'update not dominated by nonempty part guard')
            self.outer_header, self.outer_back = exhausted, self.part_header
            self.nonempty = more
        else:
            require(self.compiler == '1.90.0' and m.compiled, 'unreviewed rotated input loop')
            initial, empty_initial, first = self.branch(entry)
            advanced, empty_advanced, again = self.branch(self.latch)
            self.match(initial, r'icmp eq i64 ' + re.escape(self.chunk_length) + ', 0')
            self.match(advanced, r'icmp eq i64 ' + re.escape(next_length) + ', 0')
            require(first == again == self.part_header and empty_initial == empty_advanced,
                    'rotated input emptiness checks disagree')
            bridge = m.graph[empty_initial]
            jump = re.fullmatch('br label %' + L, bridge[0])
            require(len(bridge) == 1 and jump, 'rotated input exit is not a plain bridge')
            require(self.predecessors(empty_initial) == {entry, self.latch}, 'rotated input exit bypass')
            self.points.add((empty_initial, 0))
            self.outer_header, self.outer_back = jump[1], empty_initial
            self.nonempty = self.part_header
        require(m.before(m.defs[self.amount][1], self.update), 'input amount not computed before update')

    def predecessors(self, block):
        return {label for label, lines in self.m.graph.items()
                if block in re.findall(r'label %' + L, '\n'.join(lines))}

    def success(self):
        m = self.m
        returned = re.match('(' + V + ') = ', m.graph[self.update[0]][self.update[1]])
        require(returned, 'input update does not return a result')
        general = m.names[self.update_symbol].endswith(('::Sha512T>::update', '::HardenedSha512T>::update'))
        ok = -1 if self.compiler == '1.99.1' else ((11 if m.compiled else 6) if general else 14)
        success_target = self.latch if self.rotated else self.part_header
        guard = self.returned(self.update)[0] if self.rotated else self.latch
        if self.rotated:
            # LLVM may retain an unreachable second test of the same Result
            # after merged error cleanup. It must still admit only exact Ok.
            for predecessor in self.predecessors(self.latch) - {guard}:
                condition, success, failure = self.branch(predecessor)
                self.match(condition, r'icmp eq i8 ' + re.escape(returned[1]) + ', ' + str(ok))
                require(success == self.latch and failure != self.latch, 'rotated input admission bypass')
        lines = m.graph[guard]
        switches = [index for index, line in enumerate(lines) if line.startswith('switch ')]
        if switches:
            require(len(switches) == 1, 'unexpected input update switch')
            start = switches[0]
            self.points.update((guard, index) for index in range(start, len(lines)))
            text = '\n'.join(lines[start:]).split(']', 1)[0] + ']'
            match = re.fullmatch(r'switch i8 ' + re.escape(returned[1]) + ', label %' + L
                                 + r' \[\n((?:i8 -?\d+, label %' + L + r'\n)+)\]', text)
            require(match, 'input update switch result changed')
            cases = re.findall(r'i8 (-?\d+), label %' + L, match[2])
            require(len({value for value, _ in cases}) == len(cases), 'duplicate input result case')
            require([(value, label) for value, label in cases if label == success_target]
                    == [(str(ok), success_target)] and match[1] != success_target,
                    'input update error advances iterator')
            failures = {match[1], *(label for _, label in cases if label != success_target)}
        else:
            condition, success, failure = self.branch(guard)
            self.match(condition, r'icmp eq i8 ' + re.escape(returned[1]) + ', ' + str(ok))
            require(success == success_target and failure != success, 'input update success edge changed')
            failures = {failure}
        require(failures, 'input update has no error disposition')
        self.failed_updates(returned[1], ok)

    def failed_updates(self, result, ok):
        # Carry exact possible byte discriminants through merged cleanup; plain
        # CFG reachability would misread its redundant Ok edge as an error path.
        m = self.m
        start = self.returned(self.update)
        queue = [(start[0], start[1] + 1, frozenset(set(range(256)) - {ok % 256}))]
        seen = set()
        terminals = {point for _, point, _ in m.terminals}
        while queue:
            label, index, values = queue.pop()
            state = label, index, values
            if not values or state in seen:
                continue
            seen.add(state)
            require(len(seen) < 5000, 'input error graph exceeds bound')
            require(label != self.part_header, 'input update error can restart loop')
            lines = m.graph[label]
            for offset in range(index, len(lines)):
                line, point = lines[offset], (label, offset)
                require(point not in terminals and point != self.update, 'input update error can finalize/repeat')
                if line.startswith('br i1 '):
                    branch = re.fullmatch(r'br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?', line)
                    require(branch, 'input error branch changed')
                    condition, yes, no = branch.groups()
                    rhs = m.defs.get(condition, ('', None))[0]
                    compare = re.fullmatch(r'icmp (eq|ne) i8 ' + re.escape(result) + r', (-?\d+)', rhs)
                    if compare:
                        # Only Ok admission is a must-reject mutation site for
                        # this checker. Selecting between two rejecting error
                        # cleanups can legitimately preserve input provenance.
                        if int(compare[2]) % 256 == ok % 256:
                            self.points.update((m.defs[condition][1], point))
                        equal = values & {int(compare[2]) % 256}
                        unequal = values - equal
                        yes_values, no_values = (equal, unequal) if compare[1] == 'eq' else (unequal, equal)
                        queue += [(yes, 0, frozenset(yes_values)), (no, 0, frozenset(no_values))]
                    else:
                        queue += [(yes, 0, values), (no, 0, values)]
                    break
                if line.startswith('switch i8 ' + result + ','):
                    text = '\n'.join(lines[offset:]).split(']', 1)[0]
                    default = re.match('switch i8 ' + re.escape(result) + ', label %' + L, line)
                    require(default, 'input error switch changed')
                    remaining = values
                    for value, edge in re.findall(r'i8 (-?\d+), label %' + L, text):
                        selected = values & {int(value) % 256}
                        queue.append((edge, 0, frozenset(selected)))
                        remaining = remaining - selected
                    queue.append((default[1], 0, frozenset(remaining)))
                    break
                if line.startswith(('br ', 'switch ', 'to label ')):
                    text = '\n'.join(lines[offset:]) if line.startswith('switch ') else line
                    queue.extend((edge, 0, values) for edge in re.findall(r'label %' + L, text))
                    break

    def iteration(self):
        m, seen = self.m, set()
        queue = [(self.nonempty, False, True)]
        while queue:
            label, updated, initial = queue.pop()
            if not initial and label in (self.part_header, self.outer_header):
                require(updated, 'input iterator advances without update')
                continue
            state = label, updated
            if state in seen:
                continue
            seen.add(state)
            require(len(seen) < 2000, 'input iteration graph exceeds bound')
            lines = m.graph[label]
            for index, line in enumerate(lines):
                point = label, index
                require(point not in {at for _, at, _ in m.terminals}, 'input finalization bypasses loop exit')
                if point == self.update:
                    require(not updated, 'same input part updated more than once before advancing')
                    updated = True
                if line.startswith(('br ', 'switch ', 'to label ')):
                    text = '\n'.join(lines[index:]) if line.startswith('switch ') else line
                    queue.extend((edge, updated, False) for edge in re.findall(r'label %' + L, text))
                    break

    def chunks(self):
        m = self.m
        # One incoming pair is loaded from the slice-of-slices iterator; the
        # other is the complete-byte prefix of the captured final-bit slice.
        loaded = []
        for label, (pointer, length) in self.chunk_pair.items():
            rhs = self.rhs(pointer)
            if rhs.startswith('load ptr,'):
                loaded.append(label)
        require(len(loaded) == 1, 'input chunk/once pairing changed')
        self.chunk_arm = loaded[0]
        self.tail_arm = next(label for label in self.chunk_pair if label != self.chunk_arm)
        pointer, length = self.chunk_pair[self.chunk_arm]
        load = self.match(pointer, r'load ptr, ptr (' + V + r'), align \d+(?:,.*)?')
        self.cursor = load[1]
        extent = self.match(length, r'load i64, ptr (' + V + r'), align \d+(?:,.*)?')
        self.gep(extent[1], self.cursor, '8')
        self.once, self.split = self.chunk_pair[self.tail_arm]
        cursors, once = self.phi(self.cursor, 'ptr'), self.phi(self.once, 'ptr')
        require(cursors.keys() == once.keys() and self.outer_back in cursors,
                'outer iterator cursor/once predecessor mismatch')
        require(m.defs[self.cursor][1][0] == m.defs[self.once][1][0] == self.outer_header,
                'outer iterator header changed')
        entry = next(label for label in cursors if label != self.outer_back)
        self.chunks_base = self.field(cursors[entry], 'ptr', 32)
        self.tail_base = self.field(once[entry], 'ptr', 48)
        next_cursor, next_once = self.phi(cursors[self.outer_back], 'ptr'), self.phi(once[self.outer_back], 'ptr')
        require(set(next_cursor) == set(next_once) == {self.chunk_arm, self.tail_arm}, 'outer cursor advance branches')
        self.gep(next_cursor[self.chunk_arm], self.cursor, '16')
        require(next_cursor[self.tail_arm] == next_once[self.tail_arm] == 'null'
                and next_once[self.chunk_arm] == self.once, 'tail prefix not consumed exactly once')
        condition, tail_arm, chunk_arm = self.branch(self.outer_header)
        require((tail_arm, chunk_arm) == (self.tail_arm, self.chunk_arm), 'outer iterator arms reversed')
        either = self.match(condition, r'select i1 (' + V + r'), i1 true, i1 (' + V + ')')
        self.match(either[1], r'icmp eq ptr ' + re.escape(self.cursor) + ', null')
        endpoint = self.match(either[2], r'icmp eq ptr ' + re.escape(self.cursor) + ', (' + V + ')')[1]
        end = self.match(endpoint, r'getelementptr(?: inbounds)?(?: nuw)? (?:\[16 x i8\]|\{ ptr, i64 \}), ptr '
                         + re.escape(self.chunks_base) + ', i64 (' + V + ')')
        self.field(end[1], 'i64', 40)
        condition, finished, tail_use = self.branch(self.tail_arm)
        self.match(condition, r'icmp eq ptr ' + re.escape(self.once) + ', null')
        require(tail_use == m.defs[self.chunk_pointer][1][0], 'tail once arm does not feed chunk pair')
        self.finished = finished
        require(self.predecessors(finished) == {self.tail_arm}, 'input exhaustion can be bypassed')
        for _, point, _ in m.terminals:
            require(m.before((finished, -1), point), 'finalizer reachable before input exhaustion')


def check(model, arguments, compiler='1.99.1'):
    result = Input(model, arguments, compiler)
    result.parts()
    result.chunks()
    result.success()
    result.iteration()
    tail.check(result)
    return result
