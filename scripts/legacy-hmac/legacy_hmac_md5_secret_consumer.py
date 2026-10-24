"""Exact output-initialization consumption inside the emitted final closure.

The incoming capture is assumed to own the destination; binding its creation and
caller-side moves remains separate. Source-pinned core write/finish/Drop are
premises. All write errors, write unwind, and finish outcomes must either return
the same initialized region or clear it; fatal/double-panic erasure is not claimed.
"""
import re

import legacy_hmac_md5_consumer_return as returned
import legacy_hmac_md5_pad_model as model

r = returned.r
flow, syntax, require, VALUE = r.flow, r.syntax, r.require, r.VALUE


def primitive(symbol, operation):
    return bool(re.fullmatch(r'_RNvMNtCs\w+_11brynja_core13secret_memoryNtB\w+_26SecretRegionInitialization'
                            + str(len(operation)) + operation + r'|_ZN11brynja_core13secret_memory26SecretRegionInitialization'
                            + str(len(operation)) + operation + r'17h[0-9a-f]+E', symbol))


def drop(symbol):
    return (r.phases.rows.contracts.region_drop(symbol) and '26SecretRegionInitialization' in symbol) or bool(re.fullmatch(
        r'_ZN96_\$LT\$brynja_core\.\.secret_memory\.\.SecretRegionInitialization'
        r'\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E', symbol))


def probes(fixture):
    returned.probes(fixture)
    owner = {'%region.0': r.Pointer('destination'), '%region.1': r.Bits.token('extent')}
    success = r.layout.probe(fixture, 'core_region_success', 24, {}, owner)
    error = r.layout.probe(fixture, 'core_region_error', 24, {}, {'%error': r.Bits.token('error', 8)})
    converted = r.layout.probe(fixture, 'region_memory_error', 24, {}, {'%error': r.Bits.token('error', 8)})
    require(r.layout.read(success, 0, 1) == r.Bits.integer(0, 8)
            and r.layout.read(success, 8, 8) == r.Pointer('destination').bits()
            and r.layout.read(success, 16, 8) == r.Bits.token('extent')
            and r.layout.read(error, 0, 1) == r.Bits.integer(1, 8)
            and r.layout.read(error, 1, 1) == r.Bits.token('error', 8)
            and r.layout.read(converted, 0, 1) == r.Bits.integer(1, 8)
            and r.layout.read(converted, 1, 1) == r.Bits.integer(2, 8), 'core region result/conversion ABI changed')
    return r.n.pads.probes(fixture)


class Check:
    def __init__(self, signature, body, ok):
        self.graph, self.body, self.ok = flow.blocks(body), body, ok & 255
        self.allocs = r.phases.allocations(body)
        require(len(self.allocs) == 2 and set(self.allocs.values()) == {24}, 'secret consumer local geometry changed')
        params = syntax.parameters(signature)
        require(len(params) == 3 and all('noalias' in param for param in params)
                and all('dereferenceable(24)' in param for param in params[:2]) and 'readonly' in params[2],
                'secret consumer ownership signature changed')
        self.result, self.capture, self.rows = map(syntax.operand, params)


class State(model.State):
    def __init__(self, check, scenario):
        self.check, self.scenario = check, scenario
        self.values = {root: (root, 0) for root in (*check.allocs, check.result, check.capture, check.rows)}
        self.memory, self.live = {}, {check.result, check.capture}
        self.owner, self.stage, self.cleared, self.unwinding = check.capture, 'initial', False, False
        self.writes, self.finishes, self.drops = 0, 0, 0

    def read(self, address, kind):
        require(address[0] in self.live and (*address, kind) in self.memory, 'secret consumer unbound/expired load')
        return self.memory[*address, kind]

    def call(self, symbol, args, site):
        check = self.check
        if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
            root = syntax.operand(args[-1])
            require(root in check.allocs and len(args) in (1, 2) and (len(args) == 1 or args[0] == 'i64 24'),
                    'secret consumer lifetime changed')
            if 'start' in symbol:
                require(root not in self.live, 'secret consumer storage restarted')
                self.live.add(root)
            else:
                require(root in self.live and root != self.owner, 'live initialization expired without consumption')
                self.live.remove(root)
            return None
        if symbol == 'llvm.memcpy.p0.p0.i64':
            dest, source = (self.value(syntax.operand(arg)) for arg in args[:2])
            require(args[2:] == ['i64 24', 'i1 false'] and source == (self.owner, 0)
                    and dest[0] in check.allocs and dest[1] == 0 and dest[0] in self.live
                    and dest[0] != self.owner and self.stage == 'written', 'initialization move lost capture provenance')
            self.owner = dest[0]
            return None
        if primitive(symbol, 'write'):
            require(list(map(self.argument, args)) == [(self.owner, 0), (check.rows, 0), 128]
                    and self.owner == check.capture and self.stage == 'initial' and self.writes == 0,
                    'consumer write source/extent/order changed')
            self.writes += 1
            if self.scenario == 'write-unwind':
                self.unwinding = True
                _, unwind = r.n.results.continuation(check.graph, site)
                require(unwind, 'consumer write lost unwind cleanup edge')
                return ('unwind', unwind[0])
            if isinstance(self.scenario, int):
                return self.scenario
            self.stage = 'written'
            return check.ok
        if primitive(symbol, 'finish'):
            dest, owner = map(self.argument, args)
            require(self.stage == 'written' and self.writes == 1 and not self.finishes
                    and owner == (self.owner, 0) and self.owner in check.allocs and self.owner in self.live
                    and dest[0] in check.allocs and dest[0] in self.live and dest[0] != self.owner and dest[1] == 0
                    and 'invoke ' not in check.graph[site[0]][site[1]], 'consumer finish ownership/order changed')
            self.finishes += 1; self.owner = None
            failed = self.scenario == 'finish-error'
            self.cleared = failed; self.stage = 'finished'
            self.memory[dest[0], 0, 'i8'] = int(failed)
            if not failed:
                self.memory[dest[0], 8, 'ptr'] = ('destination', 0)
                self.memory[dest[0], 16, 'i64'] = 128
            return None
        require(drop(symbol) and len(args) == 1 and self.argument(args[0]) == (self.owner, 0)
                and self.owner in self.live and self.stage in ('initial', 'written') and self.drops == 0,
                'unknown consumer effect or wrong/repeated initialization Drop')
        self.drops += 1; self.owner = None; self.cleared = True
        return None

    def run(self):
        label, previous = next(iter(self.check.graph)), None
        visited = set()
        while label not in visited:
            require(label in self.check.graph, 'unknown secret consumer edge')
            visited.add(label); incoming = dict(self.values)
            for index, line in enumerate(self.check.graph[label]):
                if re.fullmatch(rf'{VALUE} = alloca \[24 x i8\], align 8', line):
                    continue
                phi = re.fullmatch(rf'({VALUE}) = phi i8 (.*)', line)
                if phi:
                    matches = [value for value, parent in re.findall(r'\[ ([^,]+), %' + flow.LABEL + r' \]', phi[2]) if parent == previous]
                    require(len(matches) == 1, 'secret consumer phi changed')
                    saved = self.values; self.values = incoming
                    value = self.value(matches[0]); self.values = saved; self.values[phi[1]] = value
                    continue
                if ' = landingpad { ptr, i32 }' in line or line == 'cleanup':
                    require(self.unwinding, 'unexpected consumer landingpad')
                    continue
                if line.startswith(('ret ', 'resume ')):
                    require(self.writes == 1 and self.owner is None, 'consumer exit leaks initialization ownership')
                    if self.scenario == 'write-unwind':
                        require(line.startswith('resume ') and self.drops == 1 and self.cleared, 'consumer unwind lacks clearing')
                    else:
                        require(line == 'ret void', 'consumer normal path did not return')
                        failed = self.scenario != 'success'
                        require(self.read((self.check.result, 0), 'i8') == int(failed) and self.cleared == failed,
                                'consumer result/clearing disagrees with primitive outcome')
                        if failed:
                            require(self.read((self.check.result, 1), 'i8') == 2, 'consumer error conversion changed')
                        else:
                            require(self.finishes == 1 and self.drops == 0
                                    and self.read((self.check.result, 8), 'ptr') == ('destination', 0)
                                    and self.read((self.check.result, 16), 'i64') == 128, 'consumer returned different region')
                    return
                invocation = syntax.call(line)
                if invocation:
                    value = self.call(*invocation, (label, index))
                    if isinstance(value, tuple) and value[0] == 'unwind':
                        previous, label = label, value[1]; break
                    name = re.match(rf'({VALUE}) = ', line)
                    if name:
                        self.values[name[1]] = value
                    continue
                load = re.fullmatch(rf'({VALUE}) = load (i8|ptr|i64), ptr ({VALUE}), align [18](?:, !.*)?', line)
                store = re.fullmatch(rf'store (i8|ptr|i64) ({model.ATOM}), ptr ({VALUE}), align [18]', line)
                narrow = re.fullmatch(rf'({VALUE}) = trunc(?: nuw)? i8 ({VALUE}) to i1', line)
                if load:
                    self.values[load[1]] = self.read(self.value(load[3]), load[2]); continue
                if store:
                    dest = self.value(store[3])
                    require(dest[0] == self.check.result and (dest[1], store[1]) in ((0, 'i8'), (1, 'i8'), (8, 'ptr'), (16, 'i64'))
                            and (*dest, store[1]) not in self.memory, 'consumer output overwritten or input modified')
                    self.memory[*dest, store[1]] = self.value(store[2]); continue
                if narrow:
                    value = self.value(narrow[2]); require(value in (0, 1), 'consumer narrows unbound discriminant')
                    self.values[narrow[1]] = value; continue
                kind, name, args = model.parse(line)
                require(kind in ('gep', 'compare', 'branch', 'jump', 'edge') and (kind != 'gep' or args[0] == 'i8'),
                        'unreviewed secret consumer instruction')
                target = super().evaluate(line)
                if kind == 'gep':
                    root, offset = self.values[name]
                    require(root in self.live or root == self.check.rows,
                            'secret consumer derives an expired address')
                    require(0 <= offset <= (128 if root == self.check.rows else 24),
                            'secret consumer GEP leaves its allocation')
                if target is not None:
                    previous, label = label, target; break
            else:
                require(False, 'unterminated secret consumer block')
        require(False, 'cyclic secret consumer')


def selected(fixture, llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    names = [name for name in (*definitions, *aliases) if r.phases.handoff.closure(name, 'authenticate_secret')]
    require(len(names) == 1, 'secret consumer missing/ambiguous')
    return Check(*flow.resolve(names[0], definitions, aliases), probes(fixture))


def validate(fixture, llvm, panic):
    for name, digest in r.n.pads.PINS.items():
        require(r.n.pads.hashlib.sha256((r.n.pads.phases.rows.contracts.ROOT / name).read_bytes()).hexdigest() == digest,
                'secret consumer primitive contract changed: ' + name)
    check = selected(fixture, llvm)
    for scenario in ('success', 'finish-error', 0, 1, 2, 3, *(('write-unwind',) if panic == 'unwind' else ())):
        State(check, scenario).run()
    return check
