"""Hosted comparison/staging/output provenance and returned secret admission."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_storage as storage
import hmac_hosted_output_paths as paths

require, VALUE = common.require, syntax.VALUE
DROP = '<brynja_core::secret_memory::OwnedSecretRegion as core::ops::drop::Drop>::drop'
COPY = 'brynja_core::secret_memory::copy_secret_region'


def scalar(arg):
    match = re.search('(' + VALUE + ')$', arg)
    require(match and arg.startswith('i64 '), 'hosted output length substituted')
    return match[1]


class Output:
    def __init__(self, model, arguments):
        self.model = model
        params = syntax.parameters(arguments)
        require(len(params) == 1, 'output worker parameter population')
        self.job = syntax.operand(params[0])
        self.shift = 8 if model.compiled else 0
        secret = '>::finalize_bits_secret' if model.compiled else '>::secret'
        verify = '>::verify_bits' if model.compiled else '>::verify'
        self.final = self.one(lambda name: name.startswith('<brynja_mac_hmac::') and name.endswith(secret))
        self.verify = self.one(lambda name: name.startswith('<brynja_mac_hmac::') and name.endswith(verify))
        self.copy = self.one(lambda name: name == COPY)
        self.drops = [(args, point) for symbol, args, point in model.calls if model.names.get(symbol) == DROP]
        require(self.drops, 'missing output owner destruction')
        roots = {model.pointer(syntax.operand(args[0]), point) for args, point in self.drops}
        require(len(roots) == 1, 'ambiguous output cleanup owner')
        self.owner = roots.pop()
        self.result = model.pointer(syntax.operand(self.final[0][0]), self.final[1])
        require(self.owner and self.result and self.owner[1] == self.result[1] == 0
                and model.allocs[self.owner[0]] == 16 and model.allocs[self.result[0]] == 24
                and self.owner[0] != self.result[0], 'output owner/result geometry changed')
        self.reads, self.origins = set(), {}
        self.payload, self.transforms = set(), set()
        self.returned = model.normal_return(self.final[1])

    def one(self, predicate):
        rows = [(args, point) for symbol, args, point in self.model.calls
                if predicate(self.model.names.get(symbol, ''))]
        require(len(rows) == 1, 'hosted output callee population changed')
        return rows[0]

    def origin(self, value, kind, use, trail=()):
        m = self.model
        require(value not in trail and len(trail) < 40, 'recursive output provenance')
        if value == self.job:
            require(kind == 'ptr', 'worker record used as output length')
            return 'job', 0
        if value in m.allocs:
            require(kind == 'ptr' and m.before(m.defs[value][1], use), 'output allocation does not dominate use')
            return value, 0
        require(value in m.defs, 'unknown output value')
        rhs, point = m.defs[value]
        require(m.before(point, use), 'output value does not dominate use')
        self.origins[value] = point
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + VALUE + r'), i64 (\d+)', rhs)
        load = re.match(r'load (ptr|i64), ptr (' + VALUE + '),', rhs)
        if gep:
            require(kind == 'ptr', 'output GEP used as length')
            root, offset = self.origin(gep[1], 'ptr', point, (*trail, value))
            return root, offset + int(gep[2])
        if load:
            require(kind == load[1], 'output load width changed')
            source = self.origin(load[2], 'ptr', point, (*trail, value))
            fields = {(72 + self.shift, 'ptr'): 'candidate-descriptor',
                      (80 + self.shift, 'ptr'): 'cancel',
                      (88 + self.shift, 'ptr'): 'staging',
                      (96 + self.shift, 'i64'): 'staging-length',
                      (104 + self.shift, 'ptr'): 'destination',
                      (112 + self.shift, 'i64'): 'destination-length'}
            if source[0] == 'job':
                require((source[1], kind) in fields, 'output uses wrong captured field')
                return fields[source[1], kind], 0
            if source[0] == 'candidate-descriptor':
                require((source[1], kind) in ((0, 'ptr'), (8, 'i64')), 'candidate descriptor geometry')
                return ('candidate' if kind == 'ptr' else 'candidate-length'), 0
            require(source[0] == self.result[0] and (source[1], kind) in ((8, 'ptr'), (16, 'i64')),
                    'output value not from finalizer result')
            require(m.before(self.returned, point), 'output result read before normal finalizer return')
            self.reads.add(point)
            self.payload.add(value)
            return ('tag' if kind == 'ptr' else 'tag-length'), 0
        require(False, 'unsupported output provenance: ' + rhs)

    def exposed(self, value, kind, use):
        m = self.model
        require(value in m.defs, 'missing exposed output value')
        rhs, point = m.defs[value]
        require(m.before(point, use), 'exposed output does not dominate copy')
        zero = r'ptr inttoptr \(i64 1 to ptr\)' if kind == 'ptr' else 'i64 0'
        match = re.fullmatch('select i1 (' + VALUE + '), ' + zero + ', ' + kind + ' (' + VALUE + ')', rhs)
        require(match, 'secret output exposure does not preserve empty/nonempty pair')
        self.origins[value] = point
        condition = m.defs.get(match[1])
        require(condition and m.before(condition[1], point), 'missing output exposure condition')
        test = re.fullmatch('icmp eq ptr (' + VALUE + '), null', condition[0])
        require(test and self.origin(test[1], 'ptr', condition[1]) == ('tag', 0),
                'output exposure condition not from returned pointer')
        require(self.origin(match[2], kind, point) == ('tag' if kind == 'ptr' else 'tag-length', 0),
                'output exposure payload changed')
        self.payload.update((value, match[1]))
        self.transforms.update((point, condition[1]))
        return match[1]

    def guard(self):
        """Success tag zero must dominate admission and live owner use."""
        m, guards = self.model, []
        for name, (rhs, point) in m.defs.items():
            load = re.match(r'load i8, ptr (' + VALUE + '),', rhs)
            if not load or m.pointer(load[1]) != self.result:
                continue
            require(m.before(self.returned, point), 'output tag read before normal return')
            for condition, (expression, at) in m.defs.items():
                truncate = re.fullmatch('trunc(?: nuw)? i8 ' + re.escape(name) + ' to i1', expression)
                compare = re.fullmatch('icmp (eq|ne) i8 ' + re.escape(name) + ', ([01])', expression)
                if not truncate and not compare:
                    continue
                require(m.before(point, at), 'output tag does not dominate guard')
                for label, lines in m.graph.items():
                    for index, line in enumerate(lines):
                        branch = re.fullmatch('br i1 ' + re.escape(condition) + ', label %'
                                              + common.LABEL + ', label %' + common.LABEL + r'(?:,.*)?', line)
                        if branch:
                            require(m.before(at, (label, index)), 'output guard does not dominate branch')
                            failure_true = bool(truncate) or (compare[1] == 'eq') == (compare[2] == '1')
                            guards.append((branch[2 if failure_true else 1], branch[1 if failure_true else 2]))
        require(len(guards) == 1, 'missing/ambiguous output Result admission')
        return guards[0]

    def check(self):
        m = self.model
        verify, verify_at = self.verify
        final, final_at = self.final
        copy, copy_at = self.copy
        require(len(verify) == 4 and len(final) == 5 and len(copy) == 4, 'output signatures changed')
        for argument, kind, expected, point in (
                (verify[2], 'ptr', 'candidate', verify_at), (verify[3], 'i64', 'candidate-length', verify_at),
                (final[3], 'ptr', 'staging', final_at), (final[4], 'i64', 'staging-length', final_at),
                (copy[0], 'ptr', 'destination', copy_at), (copy[1], 'i64', 'destination-length', copy_at)):
            value = syntax.operand(argument) if kind == 'ptr' else scalar(argument)
            require(self.origin(value, kind, point) == (expected, 0), 'hosted output captured provenance changed')
        require(self.exposed(syntax.operand(copy[2]), 'ptr', copy_at)
                == self.exposed(scalar(copy[3]), 'i64', copy_at), 'output exposure conditions differ')
        self.stores = []
        fields = []
        for mode, point, dest, data in m.writes:
            address = m.pointer(dest, point)
            require(not address or address[0] != self.result[0], 'finalizer Result overwritten')
            if not address or address[0] != self.owner[0]:
                continue
            match = re.fullmatch('(ptr|i64) (' + VALUE + ')', data) if mode == 'store' else None
            require(match and (address[1], match[1]) in ((0, 'ptr'), (8, 'i64')),
                    'output owner transfer geometry changed')
            require(self.origin(match[2], match[1], point) == ('tag' if match[1] == 'ptr' else 'tag-length', 0),
                    'output owner transfer does not preserve returned descriptor')
            self.stores.append(point)
            fields.append((address[1], match[1]))
        require(sorted(fields) == [(0, 'ptr'), (8, 'i64')], 'missing/duplicate output owner initialization')
        cut = [point for point in self.stores if all(other == point or m.before(other, point) for other in self.stores)]
        require(len(cut) == 1, 'output owner transfer completion ambiguous')
        self.cut = cut[0]
        success, failure = self.guard()
        for point in set(self.stores) | {copy_at} | {at for _, at in self.drops}:
            require(m.before((success, -1), point) and not m.can_precede((failure, -1), point),
                    'failed output finalization reaches live secret use')
        # LLVM may speculate descriptor loads and pure null normalization above
        # the Result branch. These are not admission: only guarded owner stores
        # and copying may consume them, and no other use may escape the branch.
        for label, lines in m.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                if set(re.findall(VALUE, line)) & self.payload:
                    require(point in self.reads | self.transforms | set(self.stores) | {copy_at},
                            'unreviewed returned output value use/escape')
        for _, point in self.drops:
            require(m.before(self.cut, point), 'output cleanup precedes initialization')
        require(m.before(self.cut, copy_at), 'output copy precedes retained output initialization')
        # Bounds/lifetimes for both actual local allocations, including all
        # error-arm Result reads (which are not interpreted as a live owner).
        roots = {self.owner[0], self.result[0]}
        starts, ends, uses = {r: [] for r in roots}, {r: [] for r in roots}, {r: set() for r in roots}
        allowed = {self.final[1], *(at for _, at in self.drops)}
        aliases = {name for name in m.defs if (address := m.pointer(name)) and address[0] in roots}
        for label, lines in m.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                mentioned = set(re.findall(VALUE, line)) & aliases
                if mentioned:
                    definition = re.match('(' + VALUE + ') = (.*)', line)
                    store = re.match(r'store (ptr|i\d+) (.+), ptr (' + VALUE + '),', line)
                    if definition and definition[1] in m.allocs:
                        continue
                    if definition and definition[2].startswith('getelementptr'):
                        require(m.pointer(definition[1]), 'unknown output pointer arithmetic')
                        continue
                    if store:
                        require(mentioned == {store[3]}, 'output pointer stored as value')
                    else:
                        require(point in m.call_map or re.match('(' + VALUE + r') = load (ptr|i\d+), ptr ', line),
                                'unreviewed output alias/escape')
                if point in m.call_map:
                    symbol, args = m.call_map[point]
                    for arg in args:
                        if not arg.startswith('ptr '):
                            continue
                        address = m.pointer(syntax.operand(arg))
                        if not address or address[0] not in roots:
                            continue
                        if symbol.startswith('llvm.lifetime.'):
                            require(address[1] == 0 and symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'),
                                    'unknown output lifetime')
                            require(len(args) == 1 or len(args) == 2 and args[0] == 'i64 ' + str(m.allocs[address[0]]),
                                    'output lifetime extent changed')
                            (starts if symbol == 'llvm.lifetime.start.p0' else ends)[address[0]].append(point)
                        else:
                            require(point in allowed and address[1] == 0, 'output owner passed to unknown callee')
                            uses[address[0]].add(point)
                load = re.search(r'\bload (ptr|i\d+), ptr (' + VALUE + '),', line)
                if load and (address := m.pointer(load[2])) and address[0] in roots:
                    size = 8 if load[1] == 'ptr' else (int(load[1][1:]) + 7) // 8
                    require(0 <= address[1] <= m.allocs[address[0]] - size, 'output descriptor read out of bounds')
                    uses[address[0]].add(point)
                if point in self.stores:
                    uses[self.owner[0]].add(point)
        for root in roots:
            require(len(starts[root]) == 1 and all(m.before(starts[root][0], point) for point in uses[root]),
                    'output allocation not live at use')
            require(not any(storage.after_end(m, end, starts[root][0], uses[root]) for end in ends[root]),
                    'output allocation used after lifetime end')
        self.ends = ends
        return self


def check(model, arguments, panic='unwind'):
    output = Output(model, arguments).check()
    paths.check(output, panic)
    return output
