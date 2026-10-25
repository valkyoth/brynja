"""Mapped authentication Result ownership before SecretTags transfer.

The preceding Result transport binds successful/error construction and the
nonthrowing move before health revalidation. Here the real discriminant guards
must either transfer the live owner or destroy it on health rejection/unwind.
An Err carries no owner. Core Drop has the existing source-bound clearing
premise; consumer-internal cleanup and host transactions remain separate.
"""
import re

import legacy_hmac_hosted_md5_tag_cleanup as tags

require, syntax, V, L = tags.require, tags.syntax, tags.V, tags.L


class ResultCleanup:
    def __init__(self, copies, post, health, panic):
        self.c, self.m, self.post, self.panic = copies, copies.m, post, panic
        self.auth, self.root = copies.auth, copies.auth.mapped
        self.health = self.auth.health[0]
        self.calls = {point: (symbol, args) for symbol, args, point in self.m.calls}
        self.health_root = syntax.operand(self.calls[self.health][1][0])
        self.health_points = health[3]
        self.points, self.drops, self.ends, self.outcomes = set(), set(), set(), set()

    def address(self, value):
        return self.m.pointer(value)

    def run(self, discriminant, health):
        owned, dropped, dead, tag_started, unwinding = discriminant != 2, False, False, False, False
        known, seen = {}, set()
        label, offset = self.health
        while True:
            require(label in self.m.graph and label not in seen and len(seen) < 150,
                    'MD5 pending Result cleanup cycles/exceeds bound')
            seen.add(label)
            rows = self.m.graph[label]
            for index in range(offset, len(rows)):
                point, line = (label, index), rows[index].split(', !', 1)[0]
                self.points.add(point)
                if point == self.auth.report:
                    require(owned and not dropped and not dead and tag_started and not unwinding
                            and health in (0, 1), 'MD5 Result transfer lost ownership/admission')
                    self.outcomes.add((discriminant, health, 'transfer'))
                    return
                if point == self.c.env['result']:
                    require(dropped == owned and dead and not unwinding,
                            'MD5 rejected Result exits without exact cleanup/lifetime')
                    self.outcomes.add((discriminant, health, 'error'))
                    return
                call = self.calls.get(point)
                if call:
                    symbol, args = call
                    name = self.m.names.get(symbol, symbol)
                    if name == 'std::panicking::catch_unwind::cleanup':
                        require(unwinding and dropped == owned and not tag_started,
                                'MD5 Result panic handoff loses or invents ownership')
                        tags.exception_pointer(self.m, args, point)
                        self.outcomes.add((discriminant, health, 'unwind'))
                        return
                    if name == tags.copy.DROP:
                        require(owned and not dropped and not dead and not tag_started and len(args) == 1
                                and self.address(syntax.operand(args[0])) == (self.root, 8),
                                'MD5 pending Result destroys absent/wrong/repeated owner')
                        dropped = True
                        self.drops.add(point)
                    elif symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
                        address = self.address(syntax.operand(args[-1]))
                        if address and address[0] == self.root:
                            require(symbol == 'llvm.lifetime.end.p0' and address[1] == 0 and not dead
                                    and dropped == owned and not tag_started and
                                    (len(args) == 1 or args == ['i64 120', args[-1]]),
                                    'MD5 pending Result lifetime precedes cleanup or restarts')
                            dead = True
                            self.ends.add(point)
                        elif address == (self.auth.tags, 0):
                            require(symbol == 'llvm.lifetime.start.p0' and owned and not dead and not dropped
                                    and not tag_started and point in self.auth.points,
                                    'MD5 Result starts invalid/transferred tag ownership')
                            tag_started = True
                        else:
                            require(address and address[1] == 0 and address[0] in self.m.allocs
                                    and address[0] != self.auth.source
                                    and (symbol == 'llvm.lifetime.end.p0' or point in self.health_points)
                                    and (len(args) == 1 or args == ['i64 ' + str(self.m.allocs[address[0]]), args[-1]]),
                                    'MD5 Result cleanup changes unrelated lifetime')
                    elif symbol == 'llvm.memcpy.p0.p0.i64':
                        require(owned and not dropped and not dead and tag_started and point in self.auth.points,
                                'MD5 pending Result copied outside the qualified transfer')
                    elif symbol == 'llvm.assume':
                        result = self.c.env['loads'][32][1]
                        bundled = line == 'call void @llvm.assume(i1 true) [ "nonnull"(ptr ' + result + ') ]'
                        definition = self.m.defs.get(args[0].split()[-1]) if len(args) == 1 else None
                        compared = definition and definition[0] == 'icmp ne ptr ' + result + ', null' and self.m.before(definition[1], point)
                        require(point in self.health_points or bundled or compared, 'MD5 pending Result gained an assumption')
                    else:
                        require(point == self.health and not dead and not dropped,
                                'MD5 pending Result gained an unreviewed call')
                        require(self.panic == 'abort' or 'invoke ' in line,
                                'MD5 health call lost Result unwind cleanup')
                    if 'invoke ' in line:
                        edge = rows[index + 1].split(', !', 1)[0]
                        match = re.fullmatch('to label %' + L + ' unwind label %' + L, edge)
                        require(match, 'MD5 pending Result invoke edges changed')
                        self.points.add((label, index + 1))
                        exceptional = point == self.health and health is None
                        unwinding |= exceptional
                        label, offset = match[2 if exceptional else 1], 0
                        break
                elif re.search(r'\b(?:call|invoke)\b', line):
                    require(False, 'MD5 pending Result indirect call')
                elif line.startswith('store '):
                    require(owned and not dropped and not dead and tag_started and point in self.auth.points,
                            'MD5 pending Result modified or escaped')
                elif define := re.fullmatch('(' + V + ') = (.*)', line):
                    value, rhs = define.groups()
                    known[value] = None
                    load = re.fullmatch(r'load (i\d+|ptr), ptr (' + V + r'), align \d+', rhs)
                    if any((p := self.address(v)) and p[0] == self.root for v in re.findall(V, rhs)):
                        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (\d+)', rhs)
                        require(not dead and not dropped and (load or
                                (gep and (address := self.address(value)) and address[0] == self.root
                                 and 0 <= address[1] <= 120)), 'MD5 pending Result pointer reinterpreted/used after cleanup')
                    if load:
                        address = self.address(load[2])
                        if address and address[0] == self.root:
                            require(not dead and not dropped and load[1] == 'i8' and address[1] in (0, 1, 2),
                                    'MD5 pending Result read outside live discriminator/payload')
                            known[value] = discriminant if address[1] == 0 else None
                        else:
                            require(point in self.health_points, 'MD5 pending Result unreviewed read')
                            if address == (self.health_root, 16):
                                require(load[1] == 'i8', 'MD5 health discriminant width changed')
                                known[value] = health
                    elif compare := re.fullmatch(r'icmp (eq|ne) i8 (' + V + r'), (\d+)', rhs):
                        operand = known.get(compare[2])
                        if operand is not None:
                            known[value] = int((operand == int(compare[3])) == (compare[1] == 'eq'))
                    else:
                        require(not re.search(r'\b(?:atomicrmw|cmpxchg|load)\b', rhs), 'MD5 Result unreviewed memory operation')
                elif branch := re.fullmatch('br i1 (' + V + '), label %' + L + ', label %' + L, line):
                    value = known.get(branch[1])
                    require(value in (0, 1), 'MD5 Result cleanup predicate unbound')
                    label, offset = branch[2 if value else 3], 0
                    break
                elif jump := re.fullmatch('br label %' + L, line):
                    label, offset = jump[1], 0
                    break
                elif line not in ('cleanup', 'catch ptr null'):
                    require(False, 'MD5 Result cleanup unexpected instruction: ' + line)
            else:
                require(False, 'MD5 pending Result path falls off block')

    def validate(self):
        tags.contracts.validate()
        for discriminant in (0, 1, 2):
            for health in (0, 1, 2, None) if self.panic == 'unwind' else (0, 1, 2):
                self.run(discriminant, health)
                expected = 'unwind' if health is None else 'transfer' if discriminant != 2 and health != 2 else 'error'
                require((discriminant, health, expected) in self.outcomes, 'MD5 Result ownership outcome changed')
        require(self.drops and self.ends, 'MD5 Result cleanup is vacuous')
        allowed = self.points | self.auth.points | self.post.points | {self.m.defs[self.root][1]}
        for block, rows in self.m.graph.items():
            for index, line in enumerate(rows):
                if any((p := self.address(v)) and p[0] == self.root for v in re.findall(V, line)):
                    require((block, index) in allowed, 'MD5 pending Result has an unreviewed use')
        return self


def check(copies, post, health, panic):
    return ResultCleanup(copies, post, health, panic).validate()
