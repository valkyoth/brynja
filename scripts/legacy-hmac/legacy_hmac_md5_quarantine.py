"""Bind caller quarantine to the returned error, and to every escaping unwind.

Independent emitted probes identify Error variants and Executor::quarantine.
All eight errors and present/absent authority layouts are evaluated at the
actual final classification. Byte provenance equates the classifier and returned
payload through casts and predecessor-matched phi trees. This is not a proof of
every earlier primitive's error mapping or the underlying CPU authority itself.
"""
import re

import legacy_hmac_md5_teardown as teardown

r, flow, syntax, require, VALUE = teardown.r, teardown.flow, teardown.syntax, teardown.require, teardown.VALUE


def error_domain(source):
    # Error is non_exhaustive to downstream Rust consumers, so an external
    # exhaustive match cannot enforce the population of this finite model.
    enum = re.search(r'pub enum Error \{([^{}]*)\}', source)
    require(enum, 'missing/structured HMAC error domain')
    body = re.sub(r'//[^\n]*', '', enum[1])
    require(re.sub(r'\s+', '', body) ==
            'MessageTooLong,TagLength,SecretMemory,ExecutionUnavailable,ExecutionFailed,IneligibleWorkload,WorkLimit,Cancelled,',
            'HMAC error domain changed; reopen quarantine model')


class Bytes:
    def __init__(self, body):
        self.defs = dict(re.findall(rf'^\s*({VALUE}) = (.*)$', body, re.M))
        self.cache = {}

    def origin(self, value, trail=()):
        if value in self.cache:
            return self.cache[value]
        require(value not in trail and len(trail) < 100, 'cyclic error-byte provenance')
        if re.fullmatch(r'-?\d+', value):
            return int(value) & 255
        constant = re.fullmatch(r'inttoptr \(i64 (-?\d+) to ptr\)', value)
        if constant:
            return int(constant[1]) & 255
        expr = self.defs.get(value, '')
        cast = re.fullmatch(rf'(?:inttoptr|ptrtoint|zext|trunc)(?: nneg)?(?: nuw)? (?:i64|i8|ptr) ({VALUE}) to (?:ptr|i64|i8)', expr)
        phi = re.fullmatch(r'phi (?:i8|ptr) (.*)', expr)
        if cast:
            result = self.origin(cast[1], (*trail, value))
        elif phi:
            terms = re.findall(r'\[ (.*?), %' + flow.LABEL + r' \]', phi[1])
            require(terms and len({parent for _, parent in terms}) == len(terms)
                    and phi[1] == ', '.join(f'[ {val}, %{parent} ]' for val, parent in terms),
                    'malformed error-byte phi')
            origins = tuple(sorted((parent, self.origin(val, (*trail, value))) for val, parent in terms))
            result = origins[0][1] if all(item[1] == origins[0][1] for item in origins) else ('phi', origins)
        else:
            result = value  # Opaque bytes can only equal the identical SSA origin.
        self.cache[value] = result
        return result


def evaluate(graph, start, pointers, executor, backend, expected, *, body='', seed=None,
             error=None, output=None, payload=None, niche=None, unwind=False, prewritten=False, workspace=None):
    byte = Bytes(body)
    values, effects, writes, visited = {}, set(), ({payload: error, niche: 2} if prewritten else {}), set()
    label = start
    dropped, expired = set(), set()

    def value(text):
        if re.fullmatch(r'-?\d+', text):
            return int(text) & 255
        if text in values:
            return values[text]
        if seed is not None and byte.origin(text) == byte.origin(seed):
            return error
        require(False, 'unbound quarantine classification value: ' + text)

    while True:
        require(label in graph and label not in visited, 'cyclic/unknown quarantine suffix')
        visited.add(label)
        lines = graph[label]
        for index, line in enumerate(lines):
            definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
            call = syntax.call(line)
            if definition:
                name, expr = definition.groups()
                if expr.startswith('getelementptr'):
                    require(name in pointers, 'unbound quarantine pointer')
                elif expr.startswith('phi ') and label == start:
                    pass  # Classifier entry is parameterized by its computed error.
                elif unwind and expr.startswith('landingpad '):
                    pass
                else:
                    load = re.fullmatch(rf'load i8, ptr ({VALUE}), align 1(?:, !.*)?', expr)
                    add = re.fullmatch(rf'add nsw i8 ({VALUE}), (-?\d+)', expr)
                    compare = re.fullmatch(rf'icmp (eq|ne|ult) i8 ({VALUE}), (-?\d+)', expr)
                    if load:
                        require(pointers.get(load[1]) == (executor, 9), 'quarantine reads another authority tag')
                        values[name] = backend
                    elif add:
                        number = value(add[1]) + int(add[2])
                        require(-128 <= number <= 127, 'quarantine classifier signed overflow')
                        values[name] = number & 255
                    elif compare:
                        left, right = value(compare[2]), int(compare[3]) & 255
                        values[name] = int({'eq': left == right, 'ne': left != right, 'ult': left < right}[compare[1]])
                    else:
                        require(seed is not None and byte.origin(name) == byte.origin(seed),
                                'unreviewed quarantine expression: ' + expr)
                        values[name] = error
            elif call:
                symbol, args = call
                if r.phases.rows.shared.owner_drop(symbol, 'md5'):
                    # Rust 1.90 abort inlines the eight nonthrowing, source-
                    # pinned lane destructors before its final switch.
                    address = pointers.get(syntax.operand(args[0])) if len(args) == 1 else None
                    require(workspace is not None and label == start and address is not None
                            and address[0] == workspace and address[1] in range(8, 912, 113)
                            and workspace not in expired and address[1] not in dropped,
                            'quarantine cleanup escaped/repeated/expired a workspace lane')
                    dropped.add(address[1])
                else:
                    require(symbol == 'llvm.lifetime.end.p0' and pointers.get(syntax.operand(args[-1]), (None,))[0] not in
                            (executor, output), 'quarantine suffix gained a call/effect: ' + line)
                    expired.add(pointers.get(syntax.operand(args[-1]), (None,))[0])
            elif line.startswith('store '):
                store = re.fullmatch(rf'store i8 ({VALUE}|-?\d+), ptr ({VALUE}), align [18](?:, !.*)?', line)
                require(store, 'quarantine store shape changed')
                address, actual = pointers.get(store[2]), value(store[1])
                if address and address[0] == executor:
                    event = address[1], actual
                    require(event in ((16, 1), (8, 0)) and event not in effects, 'quarantine cell write changed/repeated')
                    effects.add(event)
                else:
                    require(output is not None and address and address[0] == output and address[1] in (payload, niche)
                            and address[1] not in writes, 'quarantine suffix writes outside returned error')
                    if address[1] == payload:
                        require(byte.origin(store[1]) == byte.origin(seed), 'quarantine classifier differs from returned error')
                    writes[address[1]] = actual
            elif line.startswith('switch '):
                switch = re.fullmatch(rf'switch i8 ({VALUE}), label %{flow.LABEL} \[', line)
                require(switch and lines[-1] == ']', 'malformed quarantine switch')
                cases = [re.fullmatch(r'i8 (-?\d+), label %' + flow.LABEL, item) for item in lines[index + 1:-1]]
                require(all(cases) and len({int(item[1]) & 255 for item in cases}) == len(cases), 'quarantine case collision')
                label = next((item[2] for item in cases if int(item[1]) & 255 == value(switch[1])), switch[2])
                break
            elif line.startswith('br '):
                branch = re.fullmatch(rf'br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}', line)
                direct = re.fullmatch('br label %' + flow.LABEL, line)
                require(branch or direct, 'malformed quarantine branch')
                label = direct[1] if direct else branch[2] if value(branch[1]) else branch[3]
                break
            elif line == 'cleanup' and unwind:
                pass
            elif line == 'ret void' or line.startswith('resume '):
                require(line.startswith('resume ') == unwind, 'quarantine suffix changed normal/unwind exit')
                wanted = ({(16, 1)} | ({(8, 0)} if backend != 2 else set())) if expected else set()
                require(effects == wanted, 'quarantine did not match the classified outcome/authority')
                require(not dropped or dropped == set(range(8, 912, 113)), 'partial inlined quarantine cleanup')
                require(writes == ({} if output is None else {payload: error, niche: 2}), 'returned error changed after classification')
                return
            else:
                require(False, 'unparsed quarantine suffix: ' + line)
        else:
            require(False, 'quarantine suffix lacks a terminator')


def probes(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    probe = r.n.pads.descriptors.admission.probe
    errors = flow.blocks(probe(definitions, aliases, 'error_order'))
    require(len(errors) == 1 and len(next(iter(errors.values()))) == 1, 'error identity probe gained effects')
    constant = re.fullmatch(r'ret i64 (\d+)', next(iter(errors.values()))[0])
    require(constant and int(constant[1]).to_bytes(8, 'little') == bytes(range(8)), 'error discriminants changed')
    body = probe(definitions, aliases, 'revoke')
    graph = flow.blocks(body)
    pointers = syntax.pointers(body, ('%executor',))
    for backend in range(3):
        evaluate(graph, next(iter(graph)), pointers, '%executor', backend, True)


class Check:
    def __init__(self, signature, body, operation, base, niche, panic):
        self.signature, self.body, self.operation = signature, body, operation
        self.graph, self.allocs, self.bytes = flow.blocks(body), r.phases.allocations(body), Bytes(body)
        self.niche, self.payload = niche, 1 if niche == 0 else 0
        params = syntax.parameters(signature)
        self.output, selection = syntax.operand(params[0]), syntax.operand(params[1])
        load = [(label, index, match[1]) for label, lines in self.graph.items() for index, line in enumerate(lines)
                if (match := re.fullmatch(rf'({VALUE}) = load ptr, ptr {re.escape(selection)}, align 8(?:, !.*)?', line))]
        require(len(load) == 1, 'quarantine executor must come from the selected owner')
        self.executor = load[0][2]
        self.ptrs = syntax.pointers(body, (*self.allocs, self.output, self.executor))
        self.stores = [(label, index) for label, lines in self.graph.items() for index, line in enumerate(lines)
                       if (store := re.fullmatch(rf'store i8 1, ptr ({VALUE}), align 8(?:, !.*)?', line))
                       and self.ptrs.get(store[1]) == (self.executor, 16)]
        require(len(self.stores) == (2 if panic == 'unwind' else 1), 'caller quarantine store population changed')
        normal, self.unwind = [], []
        for site in self.stores:
            r.phases.dominates(self.graph, load[0][:2], site)
            reachable = r.phases.handoff.reachable(self.graph, site[0])
            (normal if any('ret void' in self.graph[label] for label in reachable) else self.unwind).append(site)
        require(len(normal) == 1, 'ambiguous normal quarantine suffix')
        parents = [label for label, lines in self.graph.items() if normal[0][0] in
                   re.findall('label %' + flow.LABEL, '\n'.join(lines))]
        require(len(parents) == 1, 'normal quarantine gained a bypass entry')
        self.entry = parents[0]
        lines = self.graph[self.entry]
        switch = next((re.fullmatch(rf'switch i8 ({VALUE}), label %{flow.LABEL} \[', line)
                       for line in lines if line.startswith('switch ')), None)
        if switch:
            self.seed = switch[1]
        else:
            add = [re.fullmatch(rf'{VALUE} = add nsw i8 ({VALUE}), -?\d+', line) for line in lines if ' = add ' in line]
            require(len(add) == 1 and add[0], 'unrecognized quarantine classifier')
            self.seed = add[0][1]
        self.workspace = r.phases.one(body, lambda name, args: r.phases.identity(name, 'new'), 'quarantine workspace')
        self.writes = teardown.consumer.output.writes(body)
        suffix = r.phases.handoff.reachable(self.graph, self.entry)
        self.prewritten = not any(site[0] in suffix and offset == self.payload for site, offset, _, _, _ in self.writes)
        if self.prewritten:
            require(self.memory(self.entry, self.payload) == self.bytes.origin(self.seed)
                    and self.memory(self.entry, self.niche) == 2, 'prewritten error differs from quarantine classifier')

    def memory(self, label, offset, trail=()):
        # A backedge reached without encountering a write carries the same
        # memory; require an initialized noncyclic entry to determine it.
        if label in trail:
            return None
        require(len(trail) < 100, 'oversized prewritten-error provenance')
        local = [item for item in self.writes if item[0][0] == label
                 and teardown.consumer.output.overlap(item[1], item[2], offset, 1)]
        if local:
            _, position, size, dtype, value = local[-1]
            require((position, size, dtype) == (offset, 1, 'i8'), 'prewritten error is not one exact byte')
            return self.bytes.origin(value)
        parents = [parent for parent, lines in self.graph.items()
                   if label in re.findall('label %' + flow.LABEL, '\n'.join(lines))]
        require(parents, 'prewritten error has an uninitialized predecessor')
        values = tuple(sorted((parent, origin) for parent in parents
                              if (origin := self.memory(parent, offset, (*trail, label))) is not None))
        if not values:
            return None
        return values[0][1] if all(item[1] == values[0][1] for item in values) else ('phi', values)

    def run(self):
        for error in range(8):
            for backend in range(3):
                evaluate(self.graph, self.entry, self.ptrs, self.executor, backend, error in (2, 3, 4),
                         body=self.body, seed=self.seed, error=error, output=self.output, payload=self.payload, niche=self.niche,
                         prewritten=self.prewritten, workspace=r.phases.owner(self.allocs, 'workspace', 912))
        for site in self.unwind:
            for backend in range(3):
                evaluate(self.graph, site[0], self.ptrs, self.executor, backend, True, body=self.body, unwind=True)
        # Every escaping panic after Operation creation must reach its revoke
        # store, irrespective of earlier branches or cleanup invokes.
        variants = {site: value == '2' and dtype == 'i8' for site, offset, size, dtype, value in self.writes
                    if teardown.consumer.output.overlap(offset, size, self.niche, 1)}
        pending, seen = [(next(iter(self.graph)), False, False, False, None)], set()
        while pending:
            label, active, revoked, classified, error = state = pending.pop()
            if state in seen:
                continue
            seen.add(state)
            for index, line in enumerate(self.graph[label]):
                site = label, index
                active |= site == self.workspace[:2]
                revoked |= site in self.stores
                classified |= site == (self.entry, 0)
                if site in variants:
                    error = variants[site]
                if line.startswith('resume '):
                    require(not active or revoked, 'escaping unwind bypasses operation quarantine')
                if line == 'ret void':
                    require(error is not None and (not active or not error or classified), 'operation error bypasses classification')
                    require(not revoked or error, 'quarantined operation returns success')
                if line.startswith(('br ', 'switch ')) or 'invoke ' in line:
                    edges = re.findall('label %' + flow.LABEL, '\n'.join(self.graph[label][index:]))
                    pending.extend((child, active, revoked, classified, error) for child in edges)
                    break


def validate(fixture, llvm, panic):
    teardown.contracts.validate()
    r.n.results.fence.validate_source()
    error_domain((teardown.contracts.ROOT / 'crates/brynja-legacy-hmac/src/lib.rs').read_text())
    probes(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation, (base, niche) in teardown.consumer.header.probes(fixture).items():
        check = Check(*r.phases.rows.method(definitions, aliases, operation)[1], operation, base, niche, panic)
        check.run()
        checks.append(check)
    return checks
