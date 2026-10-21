"""Worker authority value transfer/admission/lifetime; not keyed-state cleanup."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_capture as capture

require, VALUE = common.require, syntax.VALUE
CHECKPOINTS = {prefix + '::compiled::worker::checkpoint' for prefix in (
    'brynja_crypto_cpu_std::strict_hmac', 'brynja_crypto_cpu_std::macos_resident::hmac')}


class Transfer:
    def __init__(self, body, names, compiler):
        require(compiler in ('1.90.0', '1.99.1'), 'unreviewed authority compiler')
        self.error = 6 if compiler == '1.90.0' else -1
        self.graph = common.blocks(body)
        self.dom = capture.dominates(self.graph)
        self.names = names
        self.defs, self.allocs, self.calls, self.writes = {}, {}, [], []
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                definition = re.match('(' + VALUE + ') = (.*)', line)
                if definition:
                    require(definition[1] not in self.defs, 'duplicate authority SSA')
                    self.defs[definition[1]] = definition[2], point
                    alloc = re.fullmatch(r'alloca \[(\d+) x i8\], align \d+', definition[2])
                    if alloc:
                        self.allocs[definition[1]] = int(alloc[1])
                if re.search(r'\b(?:call|invoke)\b.*?@', line):
                    call = syntax.call(line)
                    self.calls.append((call[0], call[1], point))
                    if call[0] == 'llvm.memcpy.p0.p0.i64':
                        args = call[1]
                        self.writes.append(('copy', point, syntax.operand(args[0]), args))
                if line.startswith('store '):
                    store = re.match(r'store (.+), ptr (' + VALUE + '),', line)
                    require(store, 'unparsed worker store')
                    self.writes.append(('store', point, store[2], store[1]))

    before = capture.Record.before
    can_precede = capture.Record.can_precede

    def pointer(self, name, use=None, trail=()):
        require(name not in trail and len(trail) < 64, 'cyclic authority pointer')
        if name in self.allocs:
            if use is not None:
                require(self.before(self.defs[name][1], use), 'authority allocation does not dominate use')
            return name, 0
        if name not in self.defs:
            return None
        rhs, point = self.defs[name]
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + VALUE + r'), i64 (\d+)', rhs)
        if gep:
            base = self.pointer(gep[1], point, (*trail, name))
            if base:
                if use is not None:
                    require(self.before(point, use), 'authority address does not dominate use')
                return base[0], base[1] + int(gep[2])
        return None

    def normal_return(self, point):
        line = self.graph[point[0]][point[1]]
        if re.search(r'\binvoke\b', line):
            following = self.graph[point[0]][point[1] + 1]
            match = re.fullmatch(r'to label %' + common.LABEL + r' unwind label %' + common.LABEL, following)
            require(match, 'authority factory unwind edges changed')
            return match[1], -1
        return point

    def initialized_before(self, point):
        return self.before(self.factory, point) and self.before(self.returned, point)

    def value(self, name, size, use):
        require(name in self.defs, 'authority byte substituted with constant/unknown value')
        rhs, point = self.defs[name]
        require(self.before(point, use), 'authority load does not dominate store')
        load = re.match(r'load i(8|16|32|64|128), ptr (' + VALUE + '),', rhs)
        require(load and int(load[1]) == size * 8, 'authority scalar transfer changed')
        source = self.pointer(load[2], point)
        require(source and source[0] == self.result and 0 <= source[1] <= 16 - size,
                'authority bytes not from constructor result')
        require(self.initialized_before(point), 'authority read before normal constructor return')
        self.reads.add(point)
        return tuple(range(source[1], source[1] + size))

    def snapshot(self, use):
        result = [None] * 16
        for mode, point, dest, data in self.writes:
            address = self.pointer(dest, point)
            require(not address or address[0] != self.result, 'authority constructor result overwritten')
            if not address or address[0] != self.owner:
                continue
            require(self.before(point, use), 'authority initialization does not dominate borrow or later overwrite')
            if mode == 'copy':
                size = re.fullmatch(r'i64 (\d+)', data[2])
                require(size, 'variable authority transfer size')
                size = int(size[1])
                source = self.pointer(syntax.operand(data[1]), point)
                require(source and source[0] == self.result and 0 < size <= 16 - source[1],
                        'authority copy source/extent changed')
                require(self.initialized_before(point), 'authority copy before constructor return')
                value = tuple(range(source[1], source[1] + size))
                self.reads.add(point)
            else:
                scalar = re.fullmatch(r'i(8|16|32|64|128) (' + VALUE + r'|-?\d+)', data)
                require(scalar, 'unrecognized authority store')
                size = int(scalar[1]) // 8
                value = self.value(scalar[2], size, point)
            require(0 <= address[1] <= 16 - size, 'authority transfer outside allocation')
            for offset, byte in enumerate(value, address[1]):
                require(result[offset] is None, 'overlapping authority initialization')
                result[offset] = byte
        require(tuple(result) == tuple(range(16)), 'incomplete/reordered authority transfer')

    def admission(self, uses):
        guards = []
        for name, (rhs, point) in self.defs.items():
            match = re.fullmatch(r'icmp (eq|ne) i8 (' + VALUE + r'), (6|-1)', rhs)
            if not match:
                continue
            loaded = self.defs.get(match[2])
            if not loaded:
                continue
            load = re.match(r'load i8, ptr (' + VALUE + '),', loaded[0])
            if not load or self.pointer(load[1], loaded[1]) != (self.result, 9):
                continue
            require(self.initialized_before(loaded[1]) and self.before(loaded[1], point),
                    'authority discriminator not loaded after constructor return')
            lines = self.graph[point[0]]
            branch = re.fullmatch(r'br i1 ' + re.escape(name) + r', label %' + common.LABEL
                                  + r', label %' + common.LABEL, lines[-1])
            require(branch, 'authority status branch changed')
            success, failure = (branch[2], branch[1]) if match[1] == 'eq' else (branch[1], branch[2])
            guards.append((success, failure, point))
            require(int(match[3]) == self.error, 'authority error niche changed')
        require(len(guards) == 1, 'missing/ambiguous authority admission guard')
        success, failure, self.guard = guards[0]
        for point in uses:
            require(success in self.dom.get(point[0], set())
                    and not self.can_precede((failure, -1), point),
                    'failed authority construction reaches a borrow')

    def aliases(self, hmac):
        """No hidden pointer arithmetic, escaping stores or unreviewed callees."""
        roots = {self.owner, self.result}
        self.owner_reads = []
        aliases = {name for name in self.defs if (address := self.pointer(name)) and address[0] in roots}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                mentioned = set(re.findall(VALUE, line)) & aliases
                if not mentioned:
                    continue
                point = label, index
                definition = re.match('(' + VALUE + ') = (.*)', line)
                if definition and definition[1] in self.allocs:
                    continue
                if definition and definition[2].startswith('getelementptr'):
                    require(self.pointer(definition[1], (label, index + 1)) is not None,
                            'unreviewed authority pointer arithmetic')
                    continue
                load = re.match('(' + VALUE + r') = load i(8|16|32|64|128), ptr (' + VALUE + '),', line)
                if load:
                    address = self.pointer(load[3], point)
                    require(address and address[0] in roots and 0 <= address[1] <= 16 - int(load[2]) // 8,
                            'authority load outside allocation')
                    if address[0] == self.result:
                        require(self.initialized_before(point), 'authority read before constructor return')
                        self.reads.add(point)
                    else:
                        self.owner_reads.append(point)
                    continue
                store = re.match(r'store i(?:8|16|32|64|128) (?:' + VALUE + r'|-?\d+), ptr (' + VALUE + '),', line)
                if store:
                    require(mentioned == {store[1]}, 'authority pointer stored as a value')
                    continue  # Exact values/extent/order checked by snapshot().
                call = syntax.call(line) if re.search(r'\b(?:call|invoke)\b.*?@', line) else None
                require(call, 'unreviewed authority pointer use/escape: ' + line)
                name = self.names.get(call[0], call[0])
                if call[0] == 'llvm.memcpy.p0.p0.i64':
                    destination = self.pointer(syntax.operand(call[1][0]), point)
                    source = self.pointer(syntax.operand(call[1][1]), point)
                    require(destination and destination[0] == self.owner
                            and source and source[0] == self.result, 'authority copy escapes transfer slots')
                if name in CHECKPOINTS:
                    require(len(call[1]) == 2
                            and self.pointer(syntax.operand(call[1][1]), point) == (self.owner, 0),
                            'checkpoint does not borrow exact authority')
                require(call[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0', 'llvm.memcpy.p0.p0.i64')
                        or name in CHECKPOINTS or point in {candidate for _, candidate in hmac}
                        or name == '<brynja_crypto_cpu::static_execution::Authority>::new',
                        'unreviewed authority pointer callee')

    def check(self):
        factories = [(args, point) for symbol, args, point in self.calls
                     if self.names.get(symbol) == '<brynja_crypto_cpu::static_execution::Authority>::new']
        require(len(factories) == 1, 'authority constructor population')
        args, point = factories[0]
        self.factory = point
        source = self.pointer(syntax.operand(args[0]), point)
        require(source and source[1] == 0 and self.allocs[source[0]] == 16,
                'authority constructor result allocation')
        self.result, self.returned = source[0], self.normal_return(point)
        hmac = [(args, point) for symbol, args, point in self.calls
                if self.names.get(symbol, '').startswith('<brynja_mac_hmac::execution::Hmac<')
                and self.names[symbol].endswith('>::create')]
        require(hmac, 'missing authority consumer')
        owners = {self.pointer(syntax.operand(args[1]), point) for args, point in hmac}
        require(len(owners) == 1, 'different authority borrowed by constructors')
        owner = owners.pop()
        require(owner and owner[1] == 0 and self.allocs[owner[0]] == 16 and owner[0] != self.result,
                'borrowed authority allocation changed')
        self.owner, self.reads = owner[0], set()
        uses = []
        for symbol, args, point in self.calls:
            if any(re.search(r'\bptr\b', arg) and self.pointer(syntax.operand(arg)) == (self.owner, 0)
                   for arg in args):
                name = self.names.get(symbol, symbol)
                if symbol.startswith('llvm.lifetime.'):
                    continue
                require((name in CHECKPOINTS and len(args) == 2
                         and self.pointer(syntax.operand(args[1])) == (self.owner, 0))
                        or any(point == candidate for _, candidate in hmac),
                        'unreviewed authority borrow/escape')
                uses.append(point)
        require(len(uses) > len(hmac), 'authority checkpoints absent')
        self.aliases(hmac)
        uses.extend(self.owner_reads)
        self.admission(uses)
        for use in uses:
            self.snapshot(use)
        # Conservative lifetime ordering, including error and unwind routes.
        # HMAC internals retain their separately checked borrowed-owner contract.
        protected_uses = uses + [point for symbol, _, point in self.calls
                                 if 'brynja_mac_hmac::' in self.names.get(symbol, '')]
        for symbol, args, point in self.calls:
            if symbol == 'llvm.lifetime.end.p0':
                address = self.pointer(syntax.operand(args[-1]))
                targets = protected_uses if address == (self.owner, 0) else self.reads if address == (self.result, 0) else ()
                require(not any(self.can_precede(point, use) for use in targets),
                        'authority lifetime ends before read/borrow/consumer')
        return self


def check(body, names, compiler='1.99.1'):
    return Transfer(body, names, compiler).check()
