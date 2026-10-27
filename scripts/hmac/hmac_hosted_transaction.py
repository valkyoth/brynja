"""Joined-worker host output admission; worker execution and resource internals are premises."""
import itertools
import re

import hmac_engine_final as syntax
import hmac_hosted_capture as capture
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_transaction_values as values
import hmac_hosted_preentry as preentry

require, V, L = values.require, values.V, values.L


class Transaction:
    def __init__(self, record, compiled, compiler):
        self.r, self.compiled = record, compiled
        self.ok = 255 if compiler == '1.99.1' else 12
        self.owner, self.resource = lifecycle.profile(record.target)
        self.drop = '<' + self.owner + '::Buffers as core::ops::drop::Drop>::drop'
        self.cancel = '<' + self.owner + '::types::Cancellation>::check'
        self.calls = {}
        for label, lines in record.graph.items():
            for index, line in enumerate(lines):
                call = syntax.call(line)
                if call:
                    self.calls[label, index] = (record.names.get(call[0], call[0]), call[1])
        self.guard = self.guard_contract()
        flags = (120 + 8 * compiled, 121 + 8 * compiled)
        self.job = record.destination(record.create[1])[0]
        flag_reads = []
        for name, (rhs, point) in record.defs.items():
            load = re.match(r'load i8, ptr (' + V + '),', rhs)
            if load and record.destination(load[1]) in {(self.job, offset) for offset in flags}:
                flag_reads.append(point)
        require(len(flag_reads) == 2, 'host completion/panic flag population')
        clears = [point for point, (name, args) in self.calls.items()
                  if name == '<' + self.resource + '::Mapping>::clear'
                  and record.destination(syntax.operand(args[0])) == ('self', 80)
                  and all(record.before(point, load) for load in flag_reads)]
        require(len(clears) == 1, 'joined stack clear does not dominate both flags')
        self.start = clears[0]
        self.flags = dict(zip(flags, ('complete', 'panicked')))
        self.covered_writes = set()
        self.check_writes()

    def guard_contract(self):
        r = self.r
        drops = [(point, syntax.operand(args[0])) for point, (name, args) in self.calls.items() if name == self.drop]
        require(drops and len({arg for _, arg in drops}) == 1, 'transaction buffer guard population')
        guard = drops[0][1]
        require(r.allocs.get(guard) == 24, 'transaction buffer guard extent')
        writes = [row for row in r.writes if r.destination(row[2])[0] == guard]
        require(len(writes) == 4, 'transaction guard writes changed')
        for offset, expected in ((0, capture.pointer('self', 192)), (8, capture.pointer('self', 136)),
                                 (16, (('constant', 0),))):
            initial = [row for row in writes if r.destination(row[2])[1] == offset and r.before(row[1], r.create[0])]
            require(len(initial) == 1 and initial[0][0] == 'store'
                    and r.value(initial[0][4], initial[0][5], initial[0][1]) == expected,
                    'transaction guard initial pointer/keep changed')
            require(all(r.before(initial[0][1], point) for point, _ in drops), 'guard drop before initialization')
        initial_clears = []
        for offset in (192, 136):
            matches = [point for point, (name, args) in self.calls.items()
                       if name in ('<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear',
                                   '<' + self.resource + '::Mapping>::clear')
                       and r.destination(syntax.operand(args[0])) == ('self', offset)]
            require(len(matches) == 1, 'initial output/staging clear population')
            initial_clears.extend(matches)
        for label, lines in r.graph.items():
            for index, line in enumerate(lines):
                if line.startswith(('ret ', 'resume ')) or (label, index) == r.create[0]:
                    require(all(r.before(point, (label, index)) for point in initial_clears),
                            'initial output/staging clear missing on an exit/launch')
        return guard

    def check_writes(self):
        r = self.r
        self.keep = []
        self.quarantine = []
        for mode, point, dest, extent, source, kind in r.writes:
            root, offset = r.destination(dest)
            if root == self.guard and offset == 16 and not r.before(point, r.create[0]):
                require(mode == 'store' and kind == 'i8', 'untyped output commit')
                self.keep.append(point)
            if root == '%result':
                require(mode == 'store' and offset == 0 and kind == 'i8' and source == '10'
                        and r.before(point, r.create[0]), 'host overwrites worker Result')
            if root == 'self':
                require(self.compiled and mode == 'store' and offset == 256 and kind == 'i8',
                        'unreviewed host session mutation')
                require(source in ('0', '1'), 'nonboolean quarantine store')
                self.quarantine.append((point, source))
        require(len(self.keep) == 1, 'host output commit population')
        armed = [point for point, source in self.quarantine if source == '1']
        require(len(armed) == int(self.compiled) and all(r.before(point, r.create[0]) for point in armed),
                'executor quarantine not armed before worker')
        # Attribute errors and joined results can share an emitted switch;
        # syntactic dominance no longer proves this. The joined and pre-entry
        # campaigns below must cover every keep/reset store with exact outcomes.

    def run(self, verifying, complete, panicked, result, cancelled, pre=None):
        r = self.r
        env, visited = {}, set()
        keep, quarantine, drops, cancellation = 0, int(self.compiled), 0, 0
        start = pre['start'] if pre else self.start
        block, index = start
        predecessor = None
        # Begin immediately after the source-bound non-unwinding stack clear.
        if 'invoke ' in r.graph[block][index]:
            predecessor = block
            block = re.search(r'to label %' + L, r.graph[block][index + 1])[1]
            index = 0
        else:
            index += 1
        if pre:
            env.update(pre.get('env', {}))
        candidate = next(name for name, value in r.formals.items() if value == capture.pointer('candidate-input'))

        def value(token):
            if token in ('undef', 'poison'):
                return values.Unknown()
            if token in ('true', 'false'):
                return int(token == 'true')
            if token == 'null':
                return None
            if re.fullmatch(r'-?\d+', token):
                return int(token)
            if token == candidate:
                return 'candidate' if verifying else None
            if token in env:
                return env[token]
            require(token in r.defs, 'unbound host transaction SSA: ' + token)
            rhs, definition = r.defs[token]
            require(r.before(definition, start), 'transaction use before definition')
            # Only the pre-launch candidate presence comparison may enter the
            # post-join integer computation. Pointer operands are resolved separately.
            compare = re.fullmatch(r'icmp (eq|ne) ptr (' + V + '), null', rhs)
            require(compare and r.value(compare[2], 'ptr', definition) == capture.pointer('candidate-input'),
                    'unreviewed pre-join transaction value: ' + rhs)
            env[token] = int(verifying if compare[1] == 'ne' else not verifying)
            return env[token]

        while True:
            require(block not in visited and len(visited) < 80, 'cyclic/oversized host transaction')
            visited.add(block)
            lines = r.graph[block]
            while index < len(lines):
                line = lines[index].split(', !', 1)[0]
                point = block, index
                assign = re.match('(' + V + ') = (.*)', line)
                name, rhs = assign.groups() if assign else (None, line)
                call = self.calls.get(point)
                load = re.fullmatch(r'load (i8|ptr), ptr (' + V + r'), align \d+', rhs)
                store = re.fullmatch(r'store i8 (' + values.TOKEN + '), ptr (' + V + r'), align \d+', rhs)
                if call:
                    callee, args = call
                    if callee == self.cancel:
                        require(syntax.operand(args[0]) == r.cancel and cancellation == 0 and drops == 0,
                                'post-worker cancellation binding/population')
                        cancellation += 1
                        env[name] = (6 if cancelled else self.ok, values.Unknown())
                    elif callee == self.drop:
                        require(syntax.operand(args[0]) == self.guard and drops == 0, 'wrong/repeated host guard drop')
                        drops += 1
                    elif pre and callee == '<' + self.resource + '::Mapping>::clear':
                        require(r.destination(syntax.operand(args[0])) == ('self', 80),
                                'pre-entry clear targets wrong stack')
                    elif callee.startswith('llvm.lifetime.') or callee == 'llvm.experimental.noalias.scope.decl':
                        pass
                    elif callee == 'llvm.assume':
                        require(values.integer(value(re.search('(' + V + ')$', args[0])[1]), 1),
                                'transaction reached invalid enum assumption')
                    else:
                        require(('::thread::Attributes' in callee and callee.endswith(('::drop', '>')))
                                or callee in ('__rustc::__rust_dealloc', '__rust_dealloc'),
                                'unreviewed post-join transaction call: ' + callee)
                    if 'invoke ' in line:
                        following = re.search(r'to label %' + L, lines[index + 1])[1]
                        predecessor, block, index = block, following, 0
                        break
                elif load:
                    address = r.destination(load[2])
                    if pre and address in pre.get('memory', {}):
                        env[name] = pre['memory'][address]
                    elif address[0] == self.job and address[1] in self.flags:
                        require(not pre, 'pre-entry path reads worker completion')
                        env[name] = int(complete if self.flags[address[1]] == 'complete' else panicked)
                    elif address[0] == '%result' and address[1] in (0, 1):
                        require(not pre and complete and not panicked, 'worker Result read before completion/panic admission')
                        env[name] = result[address[1]]
                    else:
                        require(load[1] == 'ptr' and address[0] in ('%attr.i', '%attributes.i') and address[1] == 0,
                                'unreviewed host transaction load')
                        env[name] = 'attribute-allocation'
                elif store:
                    number = values.integer(value(store[1]), 8)
                    self.covered_writes.add(point)
                    if r.destination(store[2]) == (self.guard, 16):
                        require(point in self.keep and drops == 0, 'late/unreviewed output keep store')
                        keep = number
                    else:
                        require(self.compiled and r.destination(store[2]) == ('self', 256), 'unreviewed transaction store')
                        quarantine = number
                elif rhs.startswith('getelementptr '):
                    r.destination(name)  # Only statically resolved addresses.
                elif rhs.startswith('br ') or rhs.startswith('switch '):
                    if rhs.startswith('switch '):
                        match = re.fullmatch(r'switch i8 (' + V + '), label %' + L + r' \[', rhs)
                        require(match, 'unparsed transaction switch')
                        following, selector = match[2], values.integer(value(match[1]), 8)
                        index += 1
                        while lines[index] != ']':
                            case = re.fullmatch(r'i8 (-?\d+), label %' + L, lines[index])
                            require(case, 'unparsed transaction switch case')
                            if int(case[1]) & 255 == selector:
                                following = case[2]
                            index += 1
                    else:
                        targets = re.findall('label %' + L, rhs)
                        condition = re.match('br i1 (' + values.TOKEN + '),', rhs)
                        require(len(targets) == (2 if condition else 1), 'unparsed transaction branch')
                        following = targets[0 if not condition or values.integer(value(condition[1]), 1) else 1]
                    predecessor, block, index = block, following, 0
                    break
                elif rhs.startswith('ret i16 '):
                    returned = value(rhs.removeprefix('ret i16 '))
                    category = values.integer(returned, 8)
                    if pre:
                        require(category == 0 and values.integer(returned, 16) >> 8 == pre['error']
                                and keep == 0 and quarantine == 0 and drops == 1 and cancellation == 0,
                                'pre-entry failure result/cleanup/reuse changed: '
                                + repr((r.target, pre, returned, keep, quarantine, drops, cancellation)))
                        return visited
                    success = complete and not panicked and result[0] == self.ok
                    shape = (result[1] != 2) == verifying
                    admitted = success and shape and not cancelled
                    expected_category = (0 if not complete or panicked else result[0] if not success
                                         else 10 if self.compiled and not shape else 6 if cancelled
                                         else 10 if not shape else self.ok)
                    require(category == expected_category and keep == int(admitted and not verifying)
                            and drops == 1, 'host output commit/result/drop transaction changed')
                    if admitted:
                        require(values.integer(returned, 16) >> 8 == result[1], 'host changed verification decision')
                    if success:
                        require(cancellation == int(shape if self.compiled else True), 'post-worker cancellation skipped')
                    else:
                        require(cancellation == 0, 'post-worker cancellation masks failed worker')
                    if complete and not panicked and result[0] != self.ok:
                        require(category == result[0], 'host remapped worker error category')
                        if category in (0, 7, 9):
                            require(values.integer(returned, 16) >> 8 == result[1], 'host remapped worker error payload')
                    if self.compiled:
                        reusable = complete and not panicked and (success and shape or result[0] in (4, 6)
                                    or result[0] == 7 and result[1] == 7)
                        require(quarantine == int(not reusable), 'host executor quarantine classification changed')
                    return visited
                else:
                    require(name is not None, 'unreviewed host transaction instruction: ' + line)
                    env[name] = values.evaluate(rhs, value, predecessor)
                index += 1
            else:
                require(False, 'unterminated host transaction')

    def check(self):
        self.covered_writes.clear()
        results = [(self.ok, value) for value in range(3)]
        # Every current meaningful error payload, not just endpoint samples.
        # Resource has thirteen Linux/fourteen Darwin variants, CPU has seven,
        # and nested HMAC uses ten discriminants (MessageTooLong=7). Unit-error
        # padding stays unknown: it cannot justify a branch or admission.
        domains = {0: range(14), 7: range(10), 9: range(7)}
        results += [(category, payload) for category in range(11)
                    for payload in domains.get(category, (values.Unknown(),))]
        count = 0
        for verifying, cancelled in itertools.product((False, True), repeat=2):
            for result in results:
                self.run(verifying, True, False, result, cancelled)
                count += 1
            for complete, panicked in ((False, False), (False, True), (True, True)):
                self.run(verifying, complete, panicked, (self.ok, 2), cancelled)
                count += 1
        if self.compiled:
            preentry.check(self)
        required = set(self.keep) | {point for point, source in self.quarantine if source == '0'}
        require(required <= self.covered_writes, 'uncovered output/quarantine write')
        return count


def check(record, compiled, compiler):
    model = Transaction(record, compiled, compiler)
    model.check()
    return model
