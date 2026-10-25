"""Post-join output/decision/quarantine transactions for all legacy host routes.

Starts after the independently checked join and stack clear; the shared
pre-entry campaign also covers armed resource/attribute/create rejections.
Worker Result transport and nonthrowing resource/clear internals are composing
premises. Request admission, ordinary setup errors and output loan factories
compose through the outer lifecycle/reconciliation checks.
"""
import itertools
import re

import legacy_hmac_hosted_capture_model as capture

values = capture.shared.load('hmac_hosted_transaction_values')
preentry = capture.shared.load('hmac_hosted_preentry')
require, syntax, V, L = capture.require, capture.syntax, capture.V, capture.flow.LABEL


class Transaction:
    def __init__(self, record, compiler, owner, resource):
        self.r, self.compiler = record, compiler
        self.compiled = record.identity.endswith('_compiled')
        self.batch = record.identity == 'md5_compiled'
        self.ok = 255 if compiler == '1.99.1' else 10
        self.calls = {(b, i): (record.names.get(c[0], c[0]), c[1])
                      for b, rows in record.graph.items() for i, line in enumerate(rows)
                      if (c := syntax.call(line))}
        self.clear = ('<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear'
                      if record.target == 'aarch64-apple-darwin'
                      else '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear')
        self.drop = '<' + owner + '::Buffers as core::ops::drop::Drop>::drop'
        self.cancel = '<' + owner + '::types::Cancellation>::check'
        self.resource = resource
        self.flags = (88, 89) if self.batch else (128, 129) if self.compiled else (120, 121)
        pointers = syntax.pointers('\n'.join('\n'.join(rows) for rows in record.graph.values()), record.allocs)
        reads = [p for rhs, p in record.defs.values() if (m := re.match(r'load i8, ptr (' + V + '),', rhs))
                 and pointers.get(m[1]) in {(record.job, n) for n in self.flags}]
        require(len(reads) == 2, 'legacy transaction completion flag population')
        clears = [p for p, (name, args) in self.calls.items()
                  if name == '<' + resource + '::Mapping>::clear'
                  and record.destination(syntax.operand(args[0])) == ('self', 72)
                  and all(record.before(p, load) for load in reads)]
        require(len(clears) == 1, 'legacy joined stack clear must dominate flags')
        self.start = clears[0]
        self.points, self.covered_writes = set(), set()
        drops = [(p, syntax.operand(args[0])) for p, (name, args) in self.calls.items() if name == self.drop]
        self.guard = None
        if drops:
            require(len({arg for _, arg in drops}) == 1, 'legacy buffer guard identity')
            self.guard = drops[0][1]
            require(record.allocs.get(self.guard) == 24, 'legacy buffer guard extent')
            for offset, expected in ((0, capture.pointer('self', 184)), (8, capture.pointer('self', 128)),
                                     (16, (('constant', 0),))):
                initial = [row for row in record.writes if record.destination(row[2]) == (self.guard, offset)
                           and record.before(row[1], record.create[0])]
                require(len(initial) == 1 and initial[0][0] == 'store'
                        and record.value(initial[0][4], initial[0][5], initial[0][1]) == expected
                        and all(record.before(initial[0][1], point) for point, _ in drops),
                        'legacy guard initial fields/keep changed')
        self.quarantine = []
        self.keeps = set()
        for mode, point, dest, width, source, kind in record.writes:
            root, offset = record.destination(dest)
            if root == self.guard and not record.before(point, record.create[0]):
                require(mode == 'store' and offset == 16 and kind == 'i8', 'legacy late buffer guard overwrite')
                self.keeps.add(point)
            if root == 'self':
                require(self.compiled and mode == 'store' and offset == 241 and kind == 'i8'
                        and source in ('0', '1'), 'legacy transaction unreviewed session write')
                self.quarantine.append((point, source))
            if root == '%result':
                require(mode == 'store' and offset == 0 and kind == 'i8' and source == '8'
                        and record.before(point, record.create[0]), 'legacy host overwrites worker result')
        armed = [p for p, value in self.quarantine if value == '1']
        require(len(armed) == int(self.compiled)
                and all(record.before(p, record.create[0]) for p in armed),
                'legacy quarantine not armed before native launch')
        # Forgetting an old loan must not preserve its bytes on the next call.
        self.initial = []
        for offset in (184, 128):
            points = [p for p, (name, args) in self.calls.items() if name == self.clear
                      and record.destination(syntax.operand(args[0])) == ('self', offset)
                      and record.before(p, record.create[0])]
            require(len(points) == 1, 'legacy initial output/staging clear population')
            self.initial.extend(points)
        for b, rows in record.graph.items():
            for i, line in enumerate(rows):
                if line.startswith(('ret ', 'resume ')):
                    require(all(record.before(p, (b, i)) for p in self.initial),
                            'legacy initial clearing bypassed on exit')

    def run(self, verifying, complete, panicked, result, cancelled, pre=None):
        r = self.r
        env, visited, cleared = {}, set(), []
        quarantine, cancellation, keep, drops = int(self.compiled), 0, 0, 0
        start = pre['start'] if pre else self.start
        block, index = start
        predecessor = None
        if 'invoke ' in r.graph[block][index]:
            predecessor = block
            block = re.search('to label %' + L, r.graph[block][index + 1])[1]
            index = 0
        else:
            index += 1
        if pre:
            env.update(pre.get('env', {}))
        candidate = next(
            name for name, value in r.formals.items() if value == capture.pointer('candidate-input'))

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
            require(token in r.defs, 'unbound legacy transaction value: ' + token)
            rhs, point = r.defs[token]
            comparison = re.fullmatch(r'icmp (eq|ne) ptr (' + V + '), null', rhs)
            require(r.before(point, start) and comparison
                    and r.value(comparison[2], 'ptr', point) == capture.pointer('candidate-input'),
                    'unreviewed pre-join legacy transaction value: ' + rhs)
            return int(verifying if comparison[1] == 'ne' else not verifying)

        while True:
            require(block not in visited and len(visited) < 100, 'cyclic legacy host transaction')
            visited.add(block)
            rows = r.graph[block]
            while index < len(rows):
                point, line = (block, index), rows[index].split(', !', 1)[0]
                self.points.add(point)
                assign = re.fullmatch('(' + V + ') = (.*)', line)
                name, rhs = assign.groups() if assign else (None, line)
                call = self.calls.get(point)
                load = re.fullmatch(r'load (i8|ptr), ptr (' + V + r'), align \d+', rhs)
                atomic = re.fullmatch(r'load atomic i8, ptr (' + V + r') acquire, align 1', rhs)
                store = re.fullmatch(r'store i8 (' + values.TOKEN + '), ptr (' + V + r'), align \d+', rhs)
                if call:
                    callee, args = call
                    if callee == self.clear:
                        require(len(args) == 1, 'legacy transaction clear arity')
                        address = r.destination(syntax.operand(args[0]))
                        require(address in (('self', 128), ('self', 184)), 'legacy transaction clears wrong buffer')
                        cleared.append(address[1])
                    elif callee == self.drop:
                        require(len(args) == 1 and syntax.operand(args[0]) == self.guard and drops == 0,
                                'legacy guard drop identity/population')
                        drops += 1
                        cleared.extend([128] + ([] if keep else [184]))
                    elif callee == self.cancel:
                        require(len(args) == 1 and syntax.operand(args[0]) == r.cancel and cancellation == 0,
                                'legacy transaction cancellation operand/population')
                        cancellation += 1
                        env[name] = (6 if cancelled else self.ok, values.Unknown())
                    elif pre and callee == '<' + self.resource + '::Mapping>::clear':
                        require(len(args) == 1 and r.destination(syntax.operand(args[0])) == ('self', 72),
                                'legacy pre-entry clear targets wrong stack')
                    elif callee.startswith('llvm.lifetime.') or callee == 'llvm.experimental.noalias.scope.decl':
                        pass
                    elif callee == 'llvm.assume':
                        require(values.integer(value(args[0].split()[-1]), 1), 'legacy transaction invalid assumption')
                    else:
                        require(('::thread::Attributes' in callee and callee.endswith(('::drop', '>')))
                                or callee in ('__rustc::__rust_dealloc', '__rust_dealloc'),
                                'unreviewed legacy post-join call: ' + callee)
                    if 'invoke ' in line:
                        target = re.search('to label %' + L, rows[index + 1])[1]
                        predecessor, block, index = block, target, 0
                        break
                elif atomic:
                    require(atomic[1] == r.cancel and cancellation == 0, 'legacy cancellation atomic binding')
                    cancellation += 1
                    env[name] = int(cancelled)
                elif load:
                    address = r.destination(load[2])
                    if pre and address in pre.get('memory', {}):
                        env[name] = pre['memory'][address]
                    elif address[0] == r.job and address[1] in self.flags:
                        require(not pre and load[1] == 'i8', 'legacy transaction flag width/pre-entry access')
                        env[name] = int(complete if address[1] == self.flags[0] else panicked)
                    elif address[0] == '%result' and address[1] in (0, 1):
                        require(not pre and complete and not panicked and load[1] == 'i8', 'legacy premature worker result read')
                        env[name] = result[address[1]]
                    elif self.batch and address == ('%candidates', 0):
                        require(load[1] == 'ptr', 'legacy batch candidate width')
                        env[name] = 'candidate' if verifying else None
                    else:
                        require(load[1] == 'ptr' and address[0] in ('%attr.i', '%attributes.i') and address[1] == 0,
                                'unreviewed legacy host transaction read: ' + repr(address))
                        env[name] = 'attribute-allocation'
                elif store:
                    if self.guard and r.destination(store[2]) == (self.guard, 16):
                        require(drops == 0, 'legacy output commit after guard destruction')
                        keep = values.integer(value(store[1]), 8)
                        require(keep in (0, 1), 'legacy nonboolean keep')
                    else:
                        require(self.compiled and r.destination(store[2]) == ('self', 241), 'unreviewed legacy transaction store')
                        quarantine = values.integer(value(store[1]), 8)
                    self.covered_writes.add(point)
                elif rhs.startswith('getelementptr '):
                    r.destination(name)
                elif rhs.startswith(('br ', 'switch ')):
                    if rhs.startswith('switch '):
                        match = re.fullmatch('switch i8 (' + V + '), label %' + L + r' \[', rhs)
                        require(match, 'legacy transaction switch shape')
                        target, selector = match[2], values.integer(value(match[1]), 8)
                        index += 1
                        while rows[index] != ']':
                            case = re.fullmatch(r'i8 (-?\d+), label %' + L, rows[index])
                            require(case, 'legacy transaction switch case')
                            if int(case[1]) & 255 == selector:
                                target = case[2]
                            index += 1
                    else:
                        targets = re.findall('label %' + L, rhs)
                        condition = re.match('br i1 (' + values.TOKEN + '),', rhs)
                        require(len(targets) == (2 if condition else 1), 'legacy transaction branch')
                        target = targets[0 if not condition or values.integer(value(condition[1]), 1) else 1]
                    predecessor, block, index = block, target, 0
                    break
                elif rhs.startswith('ret i16 '):
                    returned = value(rhs.removeprefix('ret i16 '))
                    category = values.integer(returned, 8)
                    if pre:
                        require(category == 0 and values.integer(returned, 16) >> 8 == pre['error']
                                and cleared == [128, 184] and quarantine == 0 and cancellation == 0,
                                'legacy pre-entry rejection/cleanup/reuse changed')
                        return
                    success = complete and not panicked and result[0] == self.ok
                    shape = (result[1] != 2) == verifying
                    admitted = success and shape and not cancelled
                    expected = (0 if not complete or panicked else result[0] if not success
                                else 8 if self.compiled and not shape else 6 if cancelled
                                else 8 if not shape else self.ok)
                    require(category == expected and cleared == [128] + ([] if admitted and not verifying else [184]),
                            'legacy output clearing/result transaction changed: ' + repr((category, expected, cleared)))
                    require(cancellation == (int(shape if self.compiled else True) if success else 0),
                            'legacy post-join cancellation ordering changed')
                    if admitted or (complete and not panicked and category in (0, 7)):
                        require(values.integer(returned, 16) >> 8 == result[1], 'legacy worker result payload changed')
                    if not complete or panicked:
                        resource = 10 if r.target == 'aarch64-apple-darwin' else 11
                        require(values.integer(returned, 16) >> 8 == resource + int(not panicked),
                                'legacy worker panic/protocol failure payload changed')
                    if self.compiled:
                        benign_mac = (0, 6, 7) if self.batch else (0,)
                        reusable = complete and not panicked and (success and shape or result[0] in (4, 6)
                                    or result[0] == 7 and result[1] in benign_mac)
                        require(quarantine == int(not reusable), 'legacy quarantine classification changed')
                    return
                else:
                    require(name is not None, 'unreviewed legacy transaction instruction: ' + line)
                    nonnegative = re.fullmatch(r'zext nneg i(\d+) (' + values.TOKEN + r') to i\d+', rhs)
                    if nonnegative:
                        require(values.integer(value(nonnegative[2]), int(nonnegative[1])) < 1 << (int(nonnegative[1]) - 1),
                                'legacy transaction violated nonnegative cast')
                        rhs = rhs.replace('zext nneg ', 'zext ', 1)
                    add = re.fullmatch(r'add(?: nuw| nsw)* i8 (' + values.TOKEN + r'), (-?\d+)', rhs)
                    env[name] = ((values.integer(value(add[1]), 8) + int(add[2])) & 255 if add
                                 else values.evaluate(rhs, value, predecessor))
                index += 1
            else:
                require(False, 'unterminated legacy transaction')

    def check(self):
        # Exhaust every currently valid enum payload; unit-error padding stays
        # unknown and cannot justify admission. Source declarations are pinned.
        resource_count = 14 if self.r.target == 'aarch64-apple-darwin' else 13
        results = [(self.ok, n) for n in range(3)]
        results += [(tag, payload) for tag in range(10)
                    for payload in ({0: range(resource_count), 7: range(8)}.get(tag, (values.Unknown(),)))]
        count = 0
        for verifying, cancelled in itertools.product((False, True), repeat=2):
            for result in results:
                self.run(verifying, True, False, result, cancelled)
                count += 1
            for complete, panicked in ((False, False), (False, True), (True, True)):
                self.run(verifying, complete, panicked, (self.ok, 2), cancelled)
                count += 1
        if self.compiled:
            count += preentry.check(self)
        required = self.keeps | {point for point, source in self.quarantine if source == '0'}
        require(required <= self.covered_writes, 'legacy output/quarantine commit without a qualified path')
        return count


def check(record, compiler, owner, resource):
    model = Transaction(record, compiler, owner, resource)
    model.scenarios = model.check()
    return model
