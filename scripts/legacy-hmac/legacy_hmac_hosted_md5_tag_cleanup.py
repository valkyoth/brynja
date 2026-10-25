"""Returned MD5 tags: post-transfer destruction and lifetime paths.

Begins at the already-qualified report call, after transfer into SecretTags.
Core OwnedSecretRegion Drop is a source-bound nonthrowing clearing premise;
this checks its exact dispatch and subsequent uses, not its machine code.
Stops at the independently checked worker Result store or runtime panic
handoff. Pre-transfer Result ownership and full host transactions are separate.
"""
import re

import legacy_hmac_hosted_md5_tag_copy as copy
import legacy_hmac_md5_row_contracts as contracts

require, syntax, V, L = copy.require, copy.syntax, copy.V, copy.L


class Cleanup:
    def __init__(self, copies, panic):
        self.c, self.m, self.panic = copies, copies.m, panic
        require(panic in ('abort', 'unwind'), 'MD5 tag cleanup panic profile changed')
        self.calls = {p: (s, a) for s, a, p in self.m.calls}
        self.points, self.drops, self.ends, self.handoffs = set(), set(), set(), set()
        self.routes = {}
        self.live_calls = set()
        self.visited, self.active = set(), set()
        self.allowed = {copies.auth.report, *copies.copies}
        self.allowed.update(p for s, _, p in self.m.calls
                            if self.m.names.get(s, '').endswith('::md5_compiled::worker::checkpoint')
                            or self.m.names.get(s) == copy.EXPOSE)
        self.owner = copies.tags

    def address(self, value):
        pointer = self.m.pointer(value)
        return pointer if pointer and pointer[0] == self.owner else None

    def walk(self, label, offset, dropped=False, ended=False, unwinding=False):
        state = label, offset, dropped, ended, unwinding
        require(state not in self.active, 'MD5 tag cleanup cycle')
        if state in self.visited:
            return
        require(label in self.m.graph and len(self.visited) < 1500 and len(self.active) < 256,
                'MD5 tag cleanup graph exceeds bound')
        self.active.add(state)
        rows = self.m.graph[label]
        for index in range(offset, len(rows)):
            point, line = (label, index), rows[index].split(', !', 1)[0]
            self.points.add(point)
            call = self.calls.get(point)
            if call:
                symbol, args = call
                name = self.m.names.get(symbol, symbol)
                if name == 'std::panicking::catch_unwind::cleanup':
                    require(unwinding and dropped, 'MD5 panic handoff precedes tag destruction')
                    require(len(args) == 1, 'MD5 panic handoff ABI changed')
                    value = syntax.operand(args[0])
                    definition = self.m.defs.get(value)
                    require(definition and re.fullmatch(r'extractvalue \{ ptr, i32 \} ' + V + ', 0', definition[0])
                            and self.m.before(definition[1], point), 'MD5 panic handoff is not an exception pointer')
                    self.handoffs.add(('unwind', point))
                    break
                if name == copy.DROP:
                    require(not dropped and not ended and len(args) == 1
                            and self.address(syntax.operand(args[0])) == (self.owner, 8),
                            'MD5 tag destruction missing, repeated or retargeted')
                    dropped = True
                    self.drops.add(point)
                    self.routes.setdefault(point, set()).add(unwinding)
                elif symbol == 'llvm.lifetime.end.p0':
                    address = self.address(syntax.operand(args[-1]))
                    if address:
                        require(address[1] == 0 and dropped and not ended and
                                (len(args) == 1 or args == ['i64 32', args[-1]]),
                                'MD5 tag lifetime ends before cleanup or repeats')
                        ended = True
                        self.ends.add(point)
                elif symbol in ('llvm.lifetime.start.p0', 'llvm.assume', 'llvm.experimental.noalias.scope.decl'):
                    require(not any(self.address(v) for v in re.findall(V, line)),
                            'MD5 tag storage escapes through an intrinsic')
                else:
                    require(point in self.allowed, 'unreviewed call in MD5 tag cleanup: ' + name)
                    if not dropped:
                        self.live_calls.add(point)
                    if name in (copy.COPY, copy.EXPOSE):
                        require(not dropped and not ended, 'MD5 tag copied/exposed after destruction')
                    # The pure report helper is qualified separately. Other
                    # live-owner calls must preserve an explicit unwind edge.
                    require(self.panic == 'abort' or dropped or point == self.c.auth.report
                            or 'invoke ' in line, 'MD5 live tag call lost unwind cleanup')
                if 'invoke ' in line:
                    require(index + 1 < len(rows), 'MD5 tag cleanup invoke lost continuation')
                    edge = rows[index + 1].split(', !', 1)[0]
                    match = re.fullmatch('to label %' + L + ' unwind label %' + L, edge)
                    require(match, 'MD5 tag cleanup invoke edges changed')
                    self.points.add((label, index + 1))
                    self.walk(match[1], 0, dropped, ended, unwinding)
                    if name != copy.DROP:
                        self.walk(match[2], 0, dropped, ended, True)
                    break
            elif point == self.c.env['result']:
                require(dropped and ended and not unwinding, 'MD5 result committed before tag cleanup/lifetime end')
                self.handoffs.add(('normal', point))
                break
            elif re.search(r'\b(?:call|invoke)\b', line):
                require(False, 'MD5 tag cleanup gained an indirect call')
            else:
                require(not line.startswith(('store ', 'fence ')) and not re.search(r'\b(?:atomicrmw|cmpxchg)\b', line),
                        'MD5 tag cleanup gained an unreviewed write')
                if re.search(r'\bload\b', line):
                    require(not dropped and not ended and point in self.c.points,
                            'MD5 tag cleanup gained an unreviewed read')
                values = re.findall(V, line)
                addresses = [v for v in values if self.address(v)]
                if addresses:
                    gep = re.fullmatch('(' + V + r') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ('
                                       + V + r'), i64 (\d+)', line)
                    load = re.fullmatch('(' + V + r') = load (?:i8|i64|ptr), ptr (' + V + r'), align \d+', line)
                    require(not dropped and not ended and
                            ((gep and self.address(gep[1]) and 0 <= self.address(gep[1])[1] <= 32)
                             or (load and point in self.c.points)), 'MD5 tag storage modified/used after cleanup')
            if line.startswith('br '):
                branch = re.fullmatch(r'br label %' + L + r'|br i1 [^,]+, label %' + L + ', label %' + L, line)
                require(branch, 'MD5 tag cleanup branch changed')
                for target in branch.groups():
                    if target is not None:
                        self.walk(target, 0, dropped, ended, unwinding)
                break
            require(not line.startswith(('ret ', 'resume ', 'switch ')) and line != 'unreachable',
                    'MD5 tag cleanup bypasses reviewed completion')
        else:
            require(False, 'MD5 tag cleanup path falls off block')
        self.active.remove(state)
        self.visited.add(state)

    def validate(self):
        contracts.validate()
        self.walk(*self.c.auth.report)
        require(self.drops and self.ends and any(k == 'normal' for k, _ in self.handoffs),
                'MD5 tag cleanup has no completed owner')
        require(self.panic != 'unwind' or any(k == 'unwind' for k, _ in self.handoffs),
                'MD5 tag cleanup has no recoverable unwind observation')
        # No unwalked aliases may access or escape the returned owner. Its
        # pre-report initialization is bound by the independent Result transfer.
        allowed = self.points | self.c.auth.points | {self.m.defs[self.owner][1]}
        for block, rows in self.m.graph.items():
            for index, line in enumerate(rows):
                if any(self.address(v) for v in re.findall(V, line)):
                    require((block, index) in allowed, 'MD5 tag has an unreviewed lifetime/use')
        return self


def check(copies, panic):
    return Cleanup(copies, panic).validate()
