"""Scalar constructor roles and byte/lifetime state from actual worker LLVM."""
import re

import legacy_hmac_engine_construct as base
import legacy_hmac_hosted_keyed as keyed

require, syntax, V = keyed.require, keyed.syntax, keyed.V


class State(base.State):
    def __init__(self):
        super().__init__()
        self.live, self.scratch, self.events = set(), {}, ()
        self.normalized, self.key_updated = False, False
        self.unwinding = False
        self.trail = ()  # Bounded diagnostics only; not part of semantic identity.

    def key(self):
        return (super().key(), frozenset(self.live), tuple(sorted(self.scratch.items())),
                self.events, self.normalized, self.key_updated, self.unwinding)


class Model:
    def __init__(self, retained, envelope, panic):
        self.m, self.panic = retained, panic
        self.width, _, self.fields = base.final.geometry(retained.identity)
        self.address = lambda name: retained.pointer(name) or (name, 0)
        require({16, 24} <= set(envelope['loads']), 'scalar constructor key capture missing')
        self.key, self.length = (envelope['loads'][offset][1] for offset in (16, 24))
        finalizers = [(symbol, args, point) for symbol, args, point in retained.calls
                      if base.final.hash_finalizer(symbol, retained.identity)]
        require(len(finalizers) == 1, 'scalar constructor normalization finalizer population')
        _, args, self.finish = finalizers[0]
        require(len(args) == 4 and args[3].split()[-1] == ('20' if retained.identity == 'sha1' else '16'),
                'scalar normalization output width changed')
        self.digest = self.address(syntax.operand(args[2]))
        require(self.digest[1] == 0 and retained.allocs.get(self.digest[0]) == 20, 'scalar normalization scratch geometry')
        origins = {0: self.origin(self.address(syntax.operand(args[1])), self.finish)}
        for mode, point, dest, data in retained.writes:
            where = self.address(dest)
            if mode == 'copy' and where[0] == retained.owner and where[1] in self.fields:
                origins[1 + self.fields.index(where[1])] = self.origin(self.address(syntax.operand(data[1])), point)
        require(set(origins) == {0, 1, 2} and len(set(origins.values())) == 3, 'scalar constructor roles overlap/missing')
        self.roles = {root: token for token, root in origins.items()}
        masks = [(args, point) for symbol, args, point in retained.calls if base.mask(symbol)]
        pads = {self.address(syntax.operand(args[0])) for args, _ in masks}
        require(len(masks) == 2 and len(pads) == 1, 'scalar constructor mask/pad population')
        self.pad = pads.pop()
        require(self.pad[1] == 0 and retained.allocs.get(self.pad[0]) == 64, 'scalar constructor pad geometry')
        self.scratch = {self.pad[0]: 64, self.digest[0]: 20}
        copies = [(args, point) for symbol, args, point in retained.calls
                  if retained.names.get(symbol) == 'brynja_core::secret_memory::copy_secret_region'
                  and self.address(syntax.operand(args[0])) == self.pad]
        short = [(args, point) for args, point in copies if args[2].split()[-1] == self.key]
        require(len(copies) == 2 and len(short) == 1
                and [arg.split()[-1] for arg in short[0][0][1:]] == [self.length, self.key, self.length],
                'scalar short-key pad copy provenance/population changed')
        self.short_copy = short[0][1]
        self.checked_status, self.checked_catch = set(), set()
        self.births, self.updates, self.clears, self.successes, self.failures = set(), set(), set(), 0, 0

    def origin(self, pointer, use):
        seen = set()
        while True:
            root, offset = pointer
            require(offset == 0 and self.m.allocs.get(root) == self.width and root not in seen,
                    'scalar constructor role copy geometry/cycle')
            seen.add(root)
            copies = [(point, self.address(syntax.operand(data[1]))) for mode, point, dest, data in self.m.writes
                      if mode == 'copy' and self.address(dest) == pointer and self.m.before(point, use)
                      and data[2:] == ['i64 ' + str(self.width), 'i1 false']]
            require(len(copies) <= 1, 'scalar constructor role copy ambiguous')
            if not copies:
                return root
            use, pointer = copies[0]

    def initialize(self, state, pointer, size, public):
        root, offset = pointer
        if root not in state.initializing:
            return False
        require(public and 0 <= offset <= self.width - size, 'scalar constructor partial/nonpublic initialization')
        state.initializing[root].update(range(offset, offset + size))
        if len(state.initializing[root]) == self.width:
            state.birth((root, 0), self.width, self.roles[root])
            del state.initializing[root]
            self.births.add(self.roles[root])
        return True

    def status(self, point, line, core=False):
        """An error result from a pad/update call must not reach the handoff."""
        if point in self.checked_status:
            return
        value = re.match('(' + V + ') = (?:tail )?(?:call|invoke) ', line)
        require(value, 'scalar constructor result identity missing')
        guards = [(name, rhs, site) for name, (rhs, site) in self.m.defs.items()
                  if re.fullmatch(r'icmp (?:eq|ne) i8 ' + re.escape(value[1]) + r', -?\d+', rhs)]
        require(len(guards) == 1, 'scalar constructor result guard missing/ambiguous')
        name, rhs, site = guards[0]
        # The primitive Result<(), legacy::Error> encoding is pinned by compiler
        # population; these constants are not derived from the candidate guard.
        success = ('4' if core else '8') if self.m.compiler == '1.90.0' else '-1'
        require(rhs.endswith(', ' + success) and self.m.before(point, site), 'scalar constructor success discriminant changed')
        branch = re.fullmatch('br i1 ' + re.escape(name) + ', label %' + base.codegen.LABEL
                             + ', label %' + base.codegen.LABEL, self.m.graph[site[0]][-1])
        require(branch, 'scalar constructor status branch changed')
        failure = branch[2] if 'icmp eq ' in rhs else branch[1]
        require(not self.m.can_precede((failure, -1), self.m.cut), 'failed scalar constructor operation reaches retained owner')
        self.checked_status.add(point)
