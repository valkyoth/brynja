"""Bounded Result-to-live-HMAC representation provenance, not inner cleanup."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as destruction
from hmac_hosted_authority import Transfer

require, VALUE = common.require, syntax.VALUE


class Admission(Transfer):
    def __init__(self, body, names, compiler, identity, compiled):
        super().__init__(body, names, compiler)
        self.compiled = compiled
        shape = destruction.layout(identity, 'static')
        self.size = shape.size if compiled else common.layout(identity)[0]
        self.payload = 0 if compiled else 8
        self.discriminator = shape.discriminator if compiled else 0
        self.failure = (3 if compiler == '1.90.0' else -1) if compiled else 1
        self.factories = {point: self.pointer(syntax.operand(args[0]), point)
                          for symbol, args, point in self.calls
                          if 'brynja_mac_hmac::' in names.get(symbol, '')
                          and ('::new_with::<' in names[symbol] or names[symbol].endswith('>::create'))}
        require(len(self.factories) in (1, 2), 'keyed factory population')
        for address in self.factories.values():
            require(address and address[1] == 0
                    and self.allocs[address[0]] == self.size + self.payload, 'keyed result geometry')
        self.results = {address[0] for address in self.factories.values()}
        endings = ('>::verify_bits', '>::finalize_bits_secret') if compiled else ('>::verify', '>::secret')
        algorithm = ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                     else 'brynja_mac_hmac::algorithms::Sha' + identity[3:])
        prefix = '<brynja_mac_hmac::' + ('execution::Hmac<' if compiled else 'engine::Engine<') + algorithm + '>'
        consumers = [(args, point, int(names[symbol].endswith(endings[1])))
                     for symbol, args, point in self.calls
                     if 'brynja_mac_hmac::' in names.get(symbol, '') and names[symbol].endswith(endings)]
        require(len(consumers) == 2, 'keyed terminal consumer population')
        require({names[symbol] for symbol, _, point in self.calls if point in {row[1] for row in consumers}}
                == {prefix + ending for ending in endings}, 'keyed terminal algorithm changed')
        self.terminals = []
        moves = []
        for args, point, argument in consumers:
            destination = self.pointer(syntax.operand(args[argument]), point)
            copies = [(at, self.pointer(syntax.operand(data[1]), at))
                      for mode, at, dest, data in self.writes if mode == 'copy'
                      and self.pointer(dest, at) == destination and self.before(at, point)
                      and data[2] == 'i64 ' + str(self.size)]
            require(len(copies) == 1, 'keyed consumer move absent/ambiguous')
            require(destination and destination[1] == 0 and self.allocs[destination[0]] == self.size,
                    'keyed terminal allocation geometry')
            self.terminals.append((destination[0], point, copies[0][0]))
            moves.append(copies[0])
        owners = {address for _, address in moves}
        require(len(owners) == 1, 'keyed consumers do not share retained state')
        owner = owners.pop()
        require(owner and owner[1] == 0 and owner[0] not in self.results
                and self.allocs[owner[0]] == self.size, 'keyed retained allocation changed')
        self.owner = owner[0]
        self.initial = [point for _, point, dest, _ in self.writes
                        if (address := self.pointer(dest, point)) and address[0] == self.owner
                        and all(self.before(point, use) for use, _ in moves)]
        require(self.initial, 'missing keyed initialization')
        last = [point for point in self.initial if all(other == point or self.before(other, point)
                                                     for other in self.initial)]
        require(len(last) == 1, 'keyed initialization has no common completion point')
        self.cut = last[0]
        self.roots = {self.owner, *self.results}
        # Follow the entire temporary-copy chain, not compiler-local SSA names.
        changed = True
        while changed:
            changed = False
            for mode, point, dest, data in self.writes:
                address = self.pointer(dest, point)
                if (mode == 'copy' and address and address[0] in self.roots
                        and (point == self.cut or self.can_precede(point, self.cut))):
                    source = self.pointer(syntax.operand(data[1]), point)
                    require(source, 'unknown keyed transfer source')
                    if source[0] not in self.roots:
                        self.roots.add(source[0])
                        changed = True
        self.edges = {label: re.findall(r'label %' + common.LABEL, '\n'.join(lines))
                      for label, lines in self.graph.items()}
        self.ancestors = {self.cut[0]}
        while True:
            parents = {label for label, edges in self.edges.items() if set(edges) & self.ancestors}
            if parents <= self.ancestors:
                break
            self.ancestors |= parents
        self.call_map = {point: (symbol, args) for symbol, args, point in self.calls}
        self.write_map = {point: (mode, dest, data) for mode, point, dest, data in self.writes}
        self.aliases = {name for name in self.defs if self.address(name)}
        self.initial_uses()

    def terminal_handoffs(self):
        """Bind the last by-value moves; do not certify the callees' cleanup."""
        for root, consumer, move in self.terminals:
            require(root not in self.roots, 'keyed terminal overlaps admission storage')
            aliases = {name for name in self.defs if (address := self.pointer(name)) and address[0] == root}
            starts = []
            for label, lines in self.graph.items():
                for index, line in enumerate(lines):
                    if not (set(re.findall(VALUE, line)) & aliases):
                        continue
                    point = label, index
                    if point in self.call_map:
                        symbol, args = self.call_map[point]
                        if symbol == 'llvm.lifetime.start.p0':
                            starts.append(point)
                            require(self.pointer(syntax.operand(args[-1])) == (root, 0), 'partial terminal lifetime')
                        elif symbol == 'llvm.lifetime.end.p0':
                            require(not self.can_precede(point, consumer), 'keyed terminal lifetime ends before consumption')
                        else:
                            require(point in (consumer, move), 'keyed terminal modified/escaped before consumption')
                        continue
                    definition = re.match('(' + VALUE + ') = (.*)', line)
                    require(definition and (definition[1] == root or
                            definition[2].startswith('getelementptr') and self.pointer(definition[1]) is not None),
                            'unreviewed keyed terminal pointer use')
            require(len(starts) == 1 and self.before(starts[0], move)
                    and self.before(move, consumer), 'keyed terminal move outside live storage')

    def initial_uses(self):
        """All retained-state reads/callees follow the completed transfer."""
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                if point in self.initial:
                    continue
                load = re.search(r'\bload [^,]+, ptr (' + VALUE + '),', line)
                pointers = [load[1]] if load else []
                if point in self.call_map:
                    symbol, args = self.call_map[point]
                    if symbol.startswith('llvm.lifetime.'):
                        continue
                    pointers += [syntax.operand(arg) for arg in args if arg.startswith('ptr ')]
                if any((address := self.pointer(pointer, point)) and address[0] == self.owner
                       for pointer in pointers):
                    require(self.before(self.cut, point), 'keyed state used before complete initialization')

    def address(self, value):
        address = self.pointer(value)
        return address if address and address[0] in self.roots else None

    def read(self, memory, address, size):
        root, offset = address
        require(root in memory and 0 <= offset <= self.allocs[root] - size,
                'keyed read outside live allocation')
        data = memory[root][offset:offset + size]
        require(all(byte is not None for byte in data), 'keyed read before representation is available')
        return data

    def write(self, memory, address, values):
        root, offset = address
        require(root in memory and 0 <= offset <= self.allocs[root] - len(values),
                'keyed write outside live allocation')
        old = memory[root]
        memory[root] = old[:offset] + tuple(values) + old[offset + len(values):]

    def integer(self, value, values):
        if re.fullmatch(r'-?\d+', value):
            return int(value)
        data = values.get(value)
        if isinstance(data, int):
            return data
        if isinstance(data, tuple) and len(data) == 1:
            byte = data[0]
            if isinstance(byte, int):
                return byte
        return None

    def step(self, line, point, memory, values):
        definition = re.match('(' + VALUE + ') = (.*)', line)
        mentioned = set(re.findall(VALUE, line)) & self.aliases
        if mentioned:
            recognized = False
            if definition:
                name, rhs = definition.groups()
                recognized = (name in self.allocs
                              or rhs.startswith('getelementptr') and self.address(name) is not None
                              or re.match(r'load i(?:8|16|32|64|128), ptr ', rhs) is not None)
            if point in self.write_map:
                mode, dest, _ = self.write_map[point]
                recognized = mode == 'copy' or mentioned == {dest}
            if point in self.call_map:
                recognized = True  # Exact call identities/arguments below.
            require(recognized, 'unreviewed keyed pointer arithmetic/escape: ' + line)
        if definition:
            value, rhs = definition.groups()
            load = re.match(r'load i(8|16|32|64|128), ptr (' + VALUE + '),', rhs)
            if load and (address := self.address(load[2])):
                values[value] = self.read(memory, address, int(load[1]) // 8)
            compare = re.fullmatch(r'icmp (eq|ne) i\d+ (' + VALUE + r'), (-?\d+)', rhs)
            truncate = re.fullmatch(r'trunc(?: nuw)? i8 (' + VALUE + ') to i1', rhs)
            if compare:
                operand = self.integer(compare[2], values)
                if operand is not None:
                    values[value] = int((operand == int(compare[3])) == (compare[1] == 'eq'))
                else:
                    data = values.get(compare[2])
                    # Model only the Result contract: a successful value is not
                    # Err. Do not assume a particular live-engine discriminant.
                    if (self.compiled and isinstance(data, tuple) and len(data) == 1
                            and isinstance(data[0], tuple) and data[0][0] == 'byte'
                            and data[0][2] == self.discriminator
                            and int(compare[3]) == self.failure):
                        values[value] = int(compare[1] == 'ne')
            if truncate:
                operand = self.integer(truncate[1], values)
                if operand is not None:
                    values[value] = operand & 1
        if point in self.write_map:
            mode, dest, data = self.write_map[point]
            if address := self.address(dest):
                if mode == 'copy':
                    length = re.fullmatch(r'i64 (\d+)', data[2])
                    source = self.address(syntax.operand(data[1]))
                    require(length and source, 'unreviewed keyed copy')
                    transferred = self.read(memory, source, int(length[1]))
                else:
                    store = re.fullmatch(r'i(8|16|32|64|128) (' + VALUE + r'|-?\d+)', data)
                    require(store, 'unreviewed keyed scalar store')
                    size = int(store[1]) // 8
                    transferred = values.get(store[2], (None,) * size)
                    if re.fullmatch(r'-?\d+', store[2]):
                        transferred = tuple((int(store[2]) >> (8 * i)) & 255 for i in range(size))
                        if size == 1 and int(store[2]) < 0:
                            transferred = (int(store[2]),)
                    require(isinstance(transferred, tuple) and len(transferred) == size, 'keyed store width changed')
                self.write(memory, address, transferred)
        if point in self.call_map:
            symbol, args = self.call_map[point]
            addresses = [self.address(syntax.operand(arg)) for arg in args if arg.startswith('ptr ')]
            if any(addresses):
                require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0', 'llvm.memcpy.p0.p0.i64')
                        or point in self.factories, 'unreviewed call during keyed admission')
                if symbol == 'llvm.memcpy.p0.p0.i64':
                    require(len(addresses) == 2 and all(addresses), 'keyed representation escapes transfer slots')
            if symbol.startswith('llvm.lifetime.') and addresses and addresses[-1]:
                root, offset = addresses[-1]
                require(offset == 0, 'partial keyed lifetime intrinsic')
                if symbol == 'llvm.lifetime.start.p0':
                    require(root not in memory, 'overlapping keyed lifetime')
                    memory[root] = (None,) * self.allocs[root]
                else:
                    require(root in memory, 'ending absent keyed lifetime')
                    del memory[root]

    def check(self):
        entry = next(iter(self.graph))
        queue = [(entry, 0, {}, {})]
        seen, completed = set(), set()
        while queue:
            label, start, memory, values = queue.pop()
            if label not in self.ancestors:
                continue
            key = (label, start, tuple(sorted(memory.items())), tuple(sorted(values.items())))
            if key in seen:
                continue
            seen.add(key)
            require(len(seen) < 1500, 'keyed admission graph exceeds bound')
            lines = self.graph[label]
            for index in range(start, len(lines)):
                line = lines[index]
                point = label, index
                self.step(line, point, memory, values)
                if point == self.cut:
                    data = memory.get(self.owner, ())
                    require(len(data) == self.size and all(isinstance(byte, tuple) and len(byte) == 3 for byte in data),
                            'keyed state incomplete/not constructor-derived')
                    factory = data[0][1]
                    require(factory in self.factories and data == tuple(('byte', factory, i) for i in range(self.size)),
                            'keyed state reordered/mixed constructor representations')
                    completed.add(factory)
                    break
                if point in self.factories:
                    root = self.factories[point][0]
                    require(root in memory, 'keyed factory outside result lifetime')
                    returned = self.normal_return(point)
                    for success in (True, False):
                        copy = memory.copy()
                        data = [None] * self.allocs[root]
                        if success:
                            data[self.payload:] = [('byte', point, i) for i in range(self.size)]
                            if not self.compiled:
                                data[0] = 0
                        else:
                            data[self.discriminator] = self.failure
                            data[0 if self.compiled else 1] = ('error', point, 0)
                        copy[root] = tuple(data)
                        if returned != point:
                            queue.append((returned[0], 0, copy, values.copy()))
                        else:
                            # Calls (panic=abort) continue in the same basic block.
                            queue.append((label, index + 1, copy, values.copy()))
                    if returned != point:
                        for edge in self.edges[label]:
                            if edge != returned[0]:
                                queue.append((edge, 0, memory.copy(), values.copy()))
                    break
            else:
                branch = re.fullmatch(r'br i1 (' + VALUE + r'), label %' + common.LABEL
                                      + r', label %' + common.LABEL + r'(?:,.*)?', lines[-1])
                edges = self.edges[label]
                if branch and (condition := self.integer(branch[1], values)) is not None:
                    edges = [branch[2] if condition else branch[3]]
                for edge in edges:
                    queue.append((edge, 0, memory.copy(), values.copy()))
        require(completed == set(self.factories), 'keyed factory success population incomplete')
        self.terminal_handoffs()
        return self


def check(body, names, compiler, identity, compiled):
    return Admission(body, names, compiler, identity, compiled).check()
