"""Bounded execution of temporary SHA-1 checkpoint objects in emitted LLVM.

The executor-start and primitive-owner destructor are reviewed callee premises,
not interpreted cryptographic code. Byte provenance proves delivery of the
logical owner to Drop, not erasure of compiler copies, padding or registers.
"""
import re

import legacy_hmac_hosted_authority as authority

syntax, require, V = authority.syntax, authority.require, authority.V
flow = authority.flow
START = '<brynja_legacy_sha1::hardened_execution::Executor>::start'
DROP = '<brynja_legacy_sha1::owner::Sha1Owner as core::ops::drop::Drop>::drop'
TOKEN = V + r'|-?\d+|undef|poison'


class Machine:
    def __init__(self, arguments, body, names, flag=0, cancel=0, mode='checkpoint'):
        self.graph, self.names = (body if isinstance(body, dict) else flow.blocks(body)), names
        self.flag, self.cancel, self.mode = flag, cancel, mode
        params = [syntax.operand(arg) for arg in syntax.parameters(arguments)]
        require(len(params) == (1 if mode in ('discard', 'rejected') else 2), 'checkpoint/probe arity changed')
        self.values = {name: ('argument', index) for index, name in enumerate(params)}
        self.memory, self.live, self.consumed = {}, set(), set()
        self.started, self.dropped, self.cancelled = False, False, False
        self.reads, self.visited = set(), set()
        self.result = None
        self.bytes = [('byte', index) for index in range(448)]
        self.bytes[441] = flag
        if mode in ('accepted', 'rejected'):
            self.memory[('argument', 0)] = [None] * 448
            self.live.add(('argument', 0))
        if mode in ('accepted', 'discard'):
            root = ('argument', 1 if mode == 'accepted' else 0)
            self.memory[root] = self.bytes.copy()
            self.live.add(root)
        # Addresses and byte values are disjoint: a pointer is (root, offset).
        self.values = {name: (root, 0) for name, root in self.values.items()}

    def value(self, token):
        if token in ('undef', 'poison'):
            return None
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in self.values, 'unbound checkpoint SSA: ' + token)
        return self.values[token]

    def region(self, pointer, size):
        require(isinstance(pointer, tuple) and len(pointer) == 2, 'checkpoint pointer lost')
        root, offset = pointer
        require(root in self.memory and root in self.live and root not in self.consumed and type(offset) is int
                and 0 <= offset <= len(self.memory[root]) - size, 'checkpoint inactive/out-of-bounds storage')
        return root, offset

    def read(self, pointer, size):
        root, offset = self.region(pointer, size)
        content = self.memory[root][offset:offset + size]
        require(None not in content, 'checkpoint reads uninitialized storage')
        return content

    def write(self, pointer, data):
        root, offset = self.region(pointer, len(data))
        require(root != self.result, 'checkpoint overwrites the borrowed constructor Result')
        require(all(item is None for item in self.memory[root][offset:offset + len(data)]),
                'checkpoint overlaps initialized storage')
        self.memory[root][offset:offset + len(data)] = data

    def call(self, symbol, args):
        name = self.names.get(symbol, symbol)
        operand = lambda index: self.value(syntax.operand(args[index]))
        if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
            require(len(args) in (1, 2), 'checkpoint lifetime arity')
            root, offset = operand(-1)
            require(root in self.memory and offset == 0, 'checkpoint lifetime base changed')
            if len(args) == 2:
                require(args[0] == 'i64 448', 'checkpoint lifetime extent changed')
            if symbol == 'llvm.lifetime.start.p0':
                require(root not in self.live, 'checkpoint repeated lifetime start')
                self.live.add(root)
            else:
                require(root in self.live, 'checkpoint repeated lifetime end')
                self.live.remove(root)
        elif name == START:
            require(self.mode == 'checkpoint' and len(args) == 2 and not self.started
                    and operand(1) == (('argument', 0), 0) and 'sret([448 x i8])' in args[0],
                    'checkpoint constructor owner/result binding changed')
            root, offset = self.region(operand(0), 448)
            require(offset == 0 and len(self.memory[root]) == 448 and self.memory[root] == [None] * 448,
                    'checkpoint constructor storage changed')
            self.result, self.started = root, True
            self.memory[root] = self.bytes.copy() if self.flag != 2 else [None] * 448
            self.memory[root][441] = self.flag
        elif symbol == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[-1] == 'i1 false' and re.fullmatch(r'i64 \d+', args[2]),
                    'checkpoint copy shape changed')
            width = int(args[2].split()[-1])
            require(0 < width <= 448, 'checkpoint copy extent changed')
            source, destination = operand(1), operand(0)
            require(source[0] != destination[0], 'checkpoint overlapping copy')
            self.write(destination, self.read(source, width))
        elif name == DROP:
            require(len(args) == 1 and 'dereferenceable(433)' in args[0] and not self.dropped
                    and self.mode in ('checkpoint', 'discard') and (self.mode == 'discard' or self.started and self.flag != 2),
                    'checkpoint wrong/duplicate/error-path owner Drop')
            require(self.read(operand(0), 433) == self.bytes[8:441], 'checkpoint Drop lost owner-byte provenance')
            root, offset = operand(0)
            require(offset == 8 and self.read((root, 0), 448) == self.bytes,
                    'checkpoint Stream fields/representation lost provenance')
            self.dropped = True
            self.consumed.add(operand(0)[0])
        else:
            require(False, 'unreviewed checkpoint call: ' + name)

    def run(self, start=None, stop=None, allow_invoke=False):
        label, first = start or (next(iter(self.graph)), 0)
        previous = None
        while True:
            require(label in self.graph and label not in self.visited and len(self.visited) < 16,
                    'cyclic/unknown checkpoint CFG')
            self.visited.add(label)
            for index, original in enumerate(self.graph[label]):
                if index < first:
                    continue
                if stop and stop(self, (label, index)):
                    return label, index
                self.reads.add((label, index))
                line = original.split(', !', 1)[0]
                definition = re.match('(' + V + ') = (.*)', line)
                name, rhs = definition.groups() if definition else (None, line)
                call = syntax.call(line)
                if call:
                    require(name is None and (allow_invoke or 'invoke ' not in line),
                            'checkpoint unexpected result/unwind call')
                    self.call(*call)
                    if 'invoke ' in line:
                        require(self.names.get(call[0]) == DROP, 'unexpected temporary-owner unwind callee')
                        edge = re.fullmatch('to label %' + flow.LABEL + ' unwind label %' + flow.LABEL,
                                            self.graph[label][index + 1].split(', !', 1)[0])
                        require(edge, 'checkpoint Drop invoke edges changed')
                        self.reads.add((label, index + 1))
                        previous, label, first = label, edge[1], 0
                        break
                elif alloc := re.fullmatch(r'alloca \[448 x i8\], align 8', rhs):
                    require(name not in self.values, 'checkpoint duplicate allocation')
                    self.memory[name] = [None] * 448
                    self.values[name] = (name, 0)
                elif gep := re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (\d+)', rhs):
                    root, offset = self.value(gep[1])
                    self.values[name] = (root, offset + int(gep[2]))
                elif load := re.fullmatch(r'load i8, ptr (' + V + r'), align \d+', rhs):
                    self.values[name] = self.read(self.value(load[1]), 1)[0]
                elif atomic := re.fullmatch(r'load atomic i8, ptr (' + V + ') acquire, align 1', rhs):
                    require(self.mode == 'checkpoint' and self.started and self.flag != 2 and self.dropped
                            and not self.cancelled and not self.live and self.value(atomic[1]) == (('argument', 1), 0),
                            'checkpoint cancellation before cleanup/after rejection or wrong capture')
                    self.cancelled = True
                    self.values[name] = self.cancel
                elif store := re.fullmatch(r'store i8 (' + TOKEN + r'), ptr (' + V + r'), align \d+', rhs):
                    self.write(self.value(store[2]), [self.value(store[1])])
                elif compare := re.fullmatch(r'icmp (eq|ne) i8 (' + TOKEN + '), (' + TOKEN + ')', rhs):
                    a, b = self.value(compare[2]), self.value(compare[3])
                    require(type(a) is int and type(b) is int, 'checkpoint branches on unreviewed payload')
                    self.values[name] = int((a == b) == (compare[1] == 'eq'))
                elif select := re.fullmatch(r'select i1 (' + V + '), i8 (' + TOKEN + '), i8 (' + TOKEN + ')', rhs):
                    condition = self.value(select[1])
                    require(type(condition) is int and condition in (0, 1), 'checkpoint unknown selection')
                    self.values[name] = self.value(select[2 if condition else 3])
                elif phi := re.fullmatch(r'phi i8 (.*)', rhs):
                    choices = re.findall(r'\[ (' + TOKEN + '), %' + flow.LABEL + r' \]', phi[1])
                    require(phi[1] == ', '.join('[ ' + v + ', %' + block + ' ]' for v, block in choices),
                            'checkpoint unparsed phi')
                    choices = [v for v, block in choices if block == previous]
                    require(len(choices) == 1, 'checkpoint ambiguous phi predecessor')
                    self.values[name] = self.value(choices[0])
                elif branch := re.fullmatch('br i1 (' + V + '), label %' + flow.LABEL + ', label %' + flow.LABEL, rhs):
                    condition = self.value(branch[1])
                    require(type(condition) is int and condition in (0, 1), 'checkpoint unknown branch')
                    previous, label, first = label, branch[2 if condition else 3], 0
                    break
                elif jump := re.fullmatch('br label %' + flow.LABEL, rhs):
                    previous, label, first = label, jump[1], 0
                    break
                elif rhs.startswith('ret '):
                    require(rhs == 'ret void' or re.fullmatch('ret i8 (' + TOKEN + ')', rhs), 'checkpoint return shape')
                    return None if rhs == 'ret void' else self.value(rhs[7:])
                else:
                    require(False, 'unreviewed checkpoint instruction: ' + rhs)
            else:
                require(False, 'checkpoint unterminated block')


def validate(arguments, body, names, compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unknown checkpoint compiler')
    visited = set()
    for flag in (0, 1, 2):
        for cancel in range(256) if flag != 2 else (0, 255):
            machine = Machine(arguments, body, names, flag, cancel)
            result = machine.run()
            expected = 7 if flag == 2 else (6 if cancel else (-1 if compiler == '1.99.1' else 10))
            require(result == expected and machine.started and not machine.live
                    and machine.dropped == machine.cancelled == (flag != 2),
                    'checkpoint authority/cancellation result or owner cleanup changed')
            visited.update(machine.reads)
    graph = flow.blocks(body)
    require(visited == {(label, i) for label, rows in graph.items() for i in range(len(rows))},
            'checkpoint contains unreviewed/unreachable instructions')


def probes(population):
    definitions, aliases, names = population
    for operation in ('accepted', 'rejected', 'discard'):
        wanted = 'brynja_legacy_hmac_hosted_cleanup::checkpoint::' + operation
        selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
        require(len(selected) == 1, 'checkpoint ABI probe missing/ambiguous')
        signature, body = flow.resolve(selected[0], definitions, aliases)
        require('dereferenceable(448)' in signature and (operation == 'discard' or 'sret([448 x i8])' in signature),
                'checkpoint typed stream/Result extent changed')
        machine = Machine(signature, body, names, mode=operation)
        require(machine.run() is None and not machine.started and not machine.cancelled,
                'checkpoint typed probe effects changed')
        require(machine.reads == {(label, i) for label, rows in machine.graph.items() for i in range(len(rows))},
                'checkpoint probe has unreviewed/unreachable instructions')
        if operation == 'discard':
            require(machine.dropped and machine.live == {('argument', 0)}, 'checkpoint typed Drop contract changed')
        else:
            expected = machine.bytes if operation == 'accepted' else [2] + [None] * 440 + [2] + [None] * 6
            require(machine.memory[('argument', 0)] == expected and not machine.dropped
                    and machine.live == {('argument', i) for i in range(2 if operation == 'accepted' else 1)},
                    'checkpoint typed Result representation changed')
