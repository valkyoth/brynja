"""Conditional outer-tag truncation through the actual final-readiness call.

The outer digest's valid 128-byte returned region is a source-bound premise;
the outer-result checker separately binds that region's pointer and length.
This checks byte provenance, shape, zero tails and copy failure exclusion, not
the final consumer, return ABI, quarantine or cryptographic correctness.
"""
import hashlib
import re

import legacy_hmac_md5_outer_result as outer
import legacy_hmac_md5_outer_model as model

n, phases, flow, syntax, require, VALUE = outer.n, outer.phases, outer.flow, outer.syntax, outer.require, outer.VALUE
Bits, Pointer, Memory, ATOM = model.Bits, model.Pointer, model.Memory, model.ATOM


class State(model.State):
    def __init__(self, check, mask, tag_bytes, failure):
        self.check, self.mask, self.tag_bytes, self.failure = check, mask, tag_bytes, failure
        self.failed, self.visited, self.copied, self.visiting = False, set(), [], set()
        self.values = {name: Pointer(name) for name in (*check.allocs, check.inputs, check.selection)}
        self.values.update(check.seeds)
        self.memory = Memory({**check.allocs, check.inputs: 384, check.selection: 24, 'tag-data': 128})
        self.live = {check.inputs, check.selection, check.owner, 'tag-data'}
        self.memory.store(Pointer(check.owner), Pointer('tag-data'))
        self.memory.store(Pointer(check.owner, 8), Bits.integer(128, 64))
        self.memory.store(Pointer(check.selection, 8), Bits.integer(tag_bytes, 64))
        for lane in range(8):
            self.memory.store(Pointer(check.inputs, lane * 48),
                              Pointer('key' + str(lane)) if mask & (1 << lane) else Bits.integer(0, 64))
        for offset in range(128):
            self.memory.store(Pointer('tag-data', offset), Bits.token(('outer-byte', offset), 8))

    def value(self, value, dtype):
        if value.startswith('%') and value not in self.values:
            require(value in self.check.defs and value not in self.visiting, 'unbound/cyclic truncation predecessor')
            site, line = self.check.defs[value]
            if site not in self.check.predecessors:
                phases.dominates(self.check.graph, site, self.check.start)
            self.visiting.add(value)
            self.values[value] = self.expression(line.split(' = ', 1)[1])
            self.visiting.remove(value)
            self.check.predecessors.add(site)
        return super().value(value, dtype)

    def expression(self, expression):
        compare = re.fullmatch(rf'icmp (eq|ne) i64 ({VALUE}), 0', expression)
        if compare and self.value(compare[2], 'i64') == Pointer('tag-data').bits():
            return Bits.integer(int(compare[1] == 'ne'), 1)
        load = re.fullmatch(rf'load (i64|ptr), ptr ({VALUE}), align \d+(?:, !.*)?', expression)
        if load:
            pointer = self.address(load[2], 8)
            require((pointer == Pointer(self.check.selection, 8) and load[1] == 'i64') or
                    (pointer.root == self.check.inputs and pointer.offset % 48 == 0 and load[1] == 'ptr'),
                    'truncation reads unrelated/inactive storage')
        return super().expression(expression)

    def call(self, name, args):
        if phases.handoff.copy_region(name):
            require(not self.failed and len(args) == 4, 'copy after failure or changed arity')
            counts = [re.fullmatch(rf'i64 noundef ({ATOM})', args[i]) for i in (1, 3)]
            require(all(counts), 'truncation copy count changed')
            counts = [self.integer(match[1]) for match in counts]
            require(counts == [self.tag_bytes] * 2, 'truncation source/destination lengths changed')
            dest = self.address(syntax.operand(args[0]), counts[0], True)
            source = self.address(syntax.operand(args[2]), counts[1])
            require(dest.root == self.check.truncated and source.root == 'tag-data'
                    and dest.offset % 16 == source.offset % 16 == 0 and dest.offset == source.offset,
                    'truncation copies wrong lane or owner')
            lane = source.offset // 16
            require(self.mask & (1 << lane) and lane not in self.copied, 'inactive/repeated truncation copy')
            self.copied.append(lane)
            if self.failure == lane:
                self.failed = True
                return Bits.integer(0, 8)
            for offset in range(counts[0]):
                self.memory.store(Pointer(dest.root, dest.offset + offset),
                                  self.memory.load(Pointer(source.root, source.offset + offset), 'i8'))
            return Bits.integer(self.check.copy_ok, 8)
        # Use the shared lifetime/intrinsic implementation without its outer
        # descriptor/XOR-specific write permissions.
        if name in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
            require(syntax.operand(args[-1]) == self.check.truncated, 'truncation changes unrelated lifetime')
        if name == 'llvm.memset.p0.i64':
            require(self.value(syntax.operand(args[0]), 'ptr') == Pointer(self.check.truncated)
                    and args[1:] == ['i8 0', 'i64 128', 'i1 false'], 'truncation initialization changed')
        require(name in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0', 'llvm.memset.p0.i64',
                         'llvm.experimental.noalias.scope.decl', 'llvm.umin.i64'), 'unreviewed truncation effect')
        return model.model.State.call(self, name, args)


class Check(outer.Check):
    results = n.results
    constructor = staticmethod(lambda name: False)

    def __init__(self, signature, body, llvm, copy_ok):
        super().__init__(signature, body, llvm)
        self.start, self.copy_ok = (self.stop, 0), copy_ok
        self.stop = phases.one(body, lambda name, args: n.results.fence.helper(name) and len(args) == 1,
                               'final readiness')[:2]
        self.relevant = n.transport.errors.ancestors(self.graph, {self.stop[0]})
        pointers = syntax.pointers(body, (self.owner,))
        stores = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                match = re.fullmatch(rf'store (ptr|i64) ({VALUE}), ptr ({VALUE}), align 8(?:, !.*)?', line)
                if match and pointers.get(match[3], (None,))[0] == self.owner:
                    offset = pointers[match[3]][1]
                    require(offset not in stores and (match[1], offset) in (('ptr', 0), ('i64', 8)),
                            'outer tag owner stores changed')
                    phases.dominates(self.graph, (label, index), self.start)
                    stores[offset] = match[2]
        require(set(stores) == {0, 8}, 'outer owner premise lacks actual stores')
        self.seeds = {stores[0]: Pointer('tag-data'), stores[8]: Bits.integer(128, 64)}
        definition = re.search(rf'{re.escape(stores[0])} = inttoptr i64 ({VALUE}) to ptr', body)
        if definition:
            self.seeds[definition[1]] = Pointer('tag-data').bits()
        self.writable = {self.truncated}
        self.types = {}
        dtype = '%"core::option::Option<md5_batch::Input<\'_>>"'
        if dtype in body:
            require(dtype + ' = type { ptr, [5 x i64] }' in llvm, 'truncation input stride changed')
            self.types[dtype] = 48

    def run(self, mask, tag_bytes, failure=None):
        state = State(self, mask, tag_bytes, failure)
        success = state.walk()
        self.visited.update(state.visited)
        self.scenarios += 1
        require(success == (failure is None) and state.failed == (failure is not None), 'truncation failure reaches readiness')
        if success:
            require(self.truncated in state.live and self.owner in state.live, 'truncation owner expired')
            require(state.copied == [i for i in range(8) if mask & (1 << i)], 'truncation lane population changed')
            for offset in range(128):
                expected = Bits.token(('outer-byte', offset), 8) if mask & (1 << (offset // 16)) and offset % 16 < tag_bytes else Bits.integer(0, 8)
                require(state.memory.load(Pointer(self.truncated, offset), 'i8') == expected, 'truncated bytes/tails lost provenance')
        return state


def validate(fixture, llvm):
    n.results.fence.validate_source()
    for name, digest in n.pads.PINS.items():
        require(hashlib.sha256((phases.rows.contracts.ROOT / name).read_bytes()).hexdigest() == digest,
                'truncation copy/owner semantic premise changed')
    copy_ok = n.pads.probes(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation in ('authenticate', 'authenticate_secret', 'verify'):
        check = Check(*phases.rows.method(definitions, aliases, operation)[1], llvm, copy_ok)
        for count in range(10, 17):
            for mask in range(256):
                check.run(mask, count)
            for lane in range(8):
                check.run(255, count, lane)
        checks.append(check)
    return checks
