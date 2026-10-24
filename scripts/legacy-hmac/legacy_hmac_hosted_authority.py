"""Legacy worker-local authority transfer and constructor admission.

This checks the actual 24-byte result/owner copies, not authority admission
policy, keyed-state cleanup or the full output transaction. Backend matching
and captured constructor inputs are separate composing projections.
"""
import re

import legacy_hmac_engine_codegen as shared

model = shared.load('hmac_hosted_authority')
flow, syntax, require, V = model.common, model.syntax, model.require, model.VALUE
SHA1 = '<brynja_legacy_sha1::hardened_execution::Executor>'
MD5 = '<brynja_legacy_md5::batch::hardened_execution::Executor>'
KEYED = {'sha1_compiled': '<brynja_legacy_hmac::execution::Sha1Hmac>::with_tag_length',
         'md5_compiled': '<brynja_legacy_hmac::md5_batch::Md5Batch>::with_tag_length'}
MODE_FILES = ('crates/brynja-legacy-sha1/src/hardened_execution/mod.rs',
              'crates/brynja-legacy-md5/src/batch/hardened_execution/mod.rs')


def modes(root):
    inventory = shared.load('hmac_inventory')
    for file in MODE_FILES:
        source = inventory.rust.scrub((root / file).read_text())
        _, body = inventory.rust.declaration(source, 'Mode', {'enum'})
        require(re.sub(r'\s+', '', body) == 'Portable,Prefer,Require,', 'legacy compiled mode declaration changed')


class Transfer(model.Transfer):
    def __init__(self, body, names, compiler, identity):
        super().__init__(body, names, compiler)
        require(identity in KEYED, 'unknown legacy authority identity')
        self.identity = identity
        self.kind = SHA1 if identity == 'sha1_compiled' else MD5
        self.tag = 9 if identity == 'sha1_compiled' else 17
        self.error = (3 if compiler == '1.90.0' else -1) if identity == 'sha1_compiled' else 2

    def value(self, name, size, use):
        require(name in self.defs, 'legacy authority byte substituted')
        rhs, point = self.defs[name]
        require(self.before(point, use), 'legacy authority load does not dominate store')
        load = re.match(r'load i(8|16|32|64|128), ptr (' + V + '),', rhs)
        require(load and int(load[1]) == size * 8, 'legacy authority scalar transfer changed')
        source = self.pointer(load[2], point)
        require(source and source[0] == self.result and 0 <= source[1] <= 24 - size,
                'legacy authority bytes not from constructor result')
        require(self.initialized_before(point), 'legacy authority read before normal constructor return')
        self.reads.add(point)
        return tuple(range(source[1], source[1] + size))

    def snapshot(self, use):
        result = [None] * 24
        for mode, point, dest, data in self.writes:
            address = self.pointer(dest, point)
            require(not address or address[0] != self.result, 'legacy authority result overwritten')
            if not address or address[0] != self.owner:
                continue
            require(self.before(point, use), 'legacy authority write after/without dominating borrow')
            if mode == 'copy':
                extent = re.fullmatch(r'i64 (\d+)', data[2])
                require(extent and data[3] == 'i1 false', 'legacy authority copy mode changed')
                size = int(extent[1])
                source = self.pointer(syntax.operand(data[1]), point)
                require(source and source[0] == self.result and 0 <= source[1] < 24
                        and 0 < size <= 24 - source[1], 'legacy authority copy source/extent changed')
                require(self.initialized_before(point), 'legacy authority copy before constructor return')
                value = tuple(range(source[1], source[1] + size))
                self.reads.add(point)
            else:
                scalar = re.fullmatch(r'i(8|16|32|64|128) (' + V + r'|-?\d+)', data)
                require(scalar, 'unrecognized legacy authority store')
                size = int(scalar[1]) // 8
                value = self.value(scalar[2], size, point)
            require(0 <= address[1] <= 24 - size, 'legacy authority transfer outside allocation')
            for offset, byte in enumerate(value, address[1]):
                require(result[offset] is None, 'overlapping legacy authority initialization')
                result[offset] = byte
        require(tuple(result) == tuple(range(24)), 'incomplete/reordered legacy authority transfer')

    def admission(self, uses):
        guards = []
        for name, (rhs, point) in self.defs.items():
            match = re.fullmatch(r'icmp (eq|ne) i8 (' + V + r'), (-?\d+)', rhs)
            if not match or match[2] not in self.defs:
                continue
            loaded, load_site = self.defs[match[2]]
            load = re.match(r'load i8, ptr (' + V + '),', loaded)
            if not load or self.pointer(load[1], load_site) != (self.result, self.tag):
                continue
            require(self.initialized_before(load_site) and self.before(load_site, point),
                    'legacy authority status read before constructor return')
            branch = re.fullmatch(r'br i1 ' + re.escape(name) + r', label %' + flow.LABEL
                                  + r', label %' + flow.LABEL, self.graph[point[0]][-1])
            require(branch and int(match[3]) == self.error, 'legacy authority status branch changed')
            success, failure = (branch[2], branch[1]) if match[1] == 'eq' else (branch[1], branch[2])
            guards.append((success, failure, point))
        require(len(guards) == 1, 'missing/ambiguous legacy authority admission')
        success, failure, self.guard = guards[0]
        for point in uses:
            require(success in self.dom.get(point[0], set())
                    and not self.can_precede((failure, -1), point),
                    'failed legacy authority construction reaches owner')

    def aliases(self, allowed):
        roots = {self.owner, self.result}
        aliases = {name for name in self.defs if (p := self.pointer(name)) and p[0] in roots}
        self.owner_reads = []
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                mentioned = set(re.findall(V, line)) & aliases
                if not mentioned:
                    continue
                point = label, index
                definition = re.match('(' + V + ') = (.*)', line)
                if definition and definition[1] in self.allocs:
                    continue
                if definition and definition[2].startswith('getelementptr'):
                    p = self.pointer(definition[1], (label, index + 1))
                    require(p and 0 <= p[1] < 24, 'unreviewed legacy authority pointer arithmetic')
                    continue
                load = re.match('(' + V + r') = load i(8|16|32|64|128), ptr (' + V + '),', line)
                if load:
                    p = self.pointer(load[3], point)
                    require(p and p[0] in roots and 0 <= p[1] <= 24 - int(load[2]) // 8,
                            'legacy authority load out of bounds')
                    if p[0] == self.result:
                        require(self.initialized_before(point), 'legacy authority result read too early')
                        self.reads.add(point)
                    else:
                        self.owner_reads.append(point)
                    continue
                store = re.match(r'store i(?:8|16|32|64|128) (?:' + V + r'|-?\d+), ptr (' + V + '),', line)
                if store:
                    require(mentioned == {store[1]}, 'legacy authority pointer stored as value')
                    continue  # All writes, including dead/late writes, are checked by snapshot.
                call = syntax.call(line) if re.search(r'\b(?:call|invoke)\b.*?@', line) else None
                require(call, 'unreviewed legacy authority pointer use: ' + line)
                if call[0] == 'llvm.memcpy.p0.p0.i64':
                    dest = self.pointer(syntax.operand(call[1][0]), point)
                    source = self.pointer(syntax.operand(call[1][1]), point)
                    require(dest and dest[0] == self.owner and source and source[0] == self.result,
                            'legacy authority copy escapes slots')
                else:
                    require(call[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0')
                            or point in allowed, 'unreviewed legacy authority callee')
                    if point in allowed:
                        borrowed = [self.pointer(syntax.operand(arg), point) for arg in call[1]
                                    if arg.startswith('ptr ') and self.pointer(syntax.operand(arg))
                                    and self.pointer(syntax.operand(arg))[0] in roots]
                        require(borrowed == [(self.result if point == self.factory else self.owner, 0)],
                                'legacy authority hidden in another argument')

    def check(self):
        factories = [(args, point) for symbol, args, point in self.calls
                     if self.names.get(symbol) == self.kind + '::for_compiled_target']
        require(len(factories) == 1, 'legacy authority factory population')
        args, self.factory = factories[0]
        require(len(args) == 2 and args[1] == 'i8 noundef 2', 'legacy authority must require compiled execution')
        source = self.pointer(syntax.operand(args[0]), self.factory)
        require(source and source[1] == 0 and self.allocs[source[0]] == 24,
                'legacy authority result allocation changed')
        self.result, self.returned = source[0], self.normal_return(self.factory)
        constructors = [(args, point) for symbol, args, point in self.calls
                        if self.names.get(symbol) == KEYED[self.identity]]
        require(len(constructors) == 1, 'legacy authority consumer population')
        args, self.keyed = constructors[0]
        require(len(args) == (5 if self.identity == 'sha1_compiled' else 3), 'legacy keyed constructor arity')
        owner = self.pointer(syntax.operand(args[1]), self.keyed)
        require(owner and owner[1] == 0 and self.allocs[owner[0]] == 24 and owner[0] != self.result,
                'legacy authority owner allocation changed')
        self.owner, self.reads = owner[0], set()
        uses = []
        for symbol, args, point in self.calls:
            borrowed = [i for i, arg in enumerate(args) if re.search(r'\bptr\b', arg)
                        and (p := self.pointer(syntax.operand(arg))) and p[0] == self.owner]
            if not borrowed or symbol.startswith('llvm.'):
                continue
            name = self.names.get(symbol, symbol)
            checkpoint = name in {p + '::' + self.identity + '::worker::checkpoint' for p in (
                'brynja_legacy_hmac_std::strict_execution', 'brynja_legacy_hmac_std::macos_resident')}
            expected = (0, 2) if checkpoint else (0, 1) if name == SHA1 + '::report' else (1, 2)
            if name == KEYED[self.identity]:
                expected = 1, 5 if self.identity == 'sha1_compiled' else 3
            require(checkpoint or name in (KEYED[self.identity], SHA1 + '::report', SHA1 + '::start')
                    and self.identity == 'sha1_compiled'
                    or name in (KEYED[self.identity], '<brynja_legacy_hmac::md5_batch::Md5Batch>::new')
                    and self.identity == 'md5_compiled', 'unreviewed legacy authority borrow')
            require(borrowed == [expected[0]] and len(args) == expected[1]
                    and self.pointer(syntax.operand(args[expected[0]]), point) == (self.owner, 0),
                    'legacy authority borrow argument changed')
            uses.append(point)
        require(len(uses) > 2 and self.keyed in uses, 'legacy authority checkpoints missing')
        self.aliases({self.factory, *uses})
        uses.extend(self.owner_reads)
        self.admission(uses)
        for use in uses:
            self.snapshot(use)
        protected = uses + [point for symbol, _, point in self.calls
                            if 'brynja_legacy_hmac::' in self.names.get(symbol, '')]
        for symbol, args, point in self.calls:
            if symbol == 'llvm.lifetime.end.p0':
                address = self.pointer(syntax.operand(args[-1]))
                targets = protected if address == (self.owner, 0) else self.reads if address == (self.result, 0) else ()
                require(not any(self.can_precede(point, use) for use in targets),
                        'legacy authority lifetime ends before read/borrow/consumer')
        return self


def check(body, names, compiler, identity):
    return Transfer(body, names, compiler, identity).check()
