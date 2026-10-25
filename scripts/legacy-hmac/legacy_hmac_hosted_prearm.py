"""Actual scalar/batch legacy host admission before worker-storage access.

Executes outlined validation/cancellation bodies as well as inlined versions.
Safe descriptor validity and initial resource/session layout are premises;
secret bytes are never mapped into this interpreter. Finite boundary campaigns
do not prove arbitrary loop trip counts, native protection or fatal-path erasure.
"""
import re
from functools import lru_cache
from typing import NamedTuple

import legacy_hmac_hosted_prearm_flow as flow
import legacy_hmac_hosted_prearm_cases as cases
import legacy_hmac_hosted_loans as loans

require, syntax, V = flow.require, flow.syntax, flow.V


class Evidence(NamedTuple):
    signature: str
    body: str
    target: str
    identity: str
    compiler: str
    points: frozenset
    callee_points: frozenset
    scenarios: int
    boundaries: frozenset


class Admission:
    def __init__(self, signature, body, names, callees, target, identity, compiler):
        self.body, self.names, self.callees = body, names, callees
        self.target, self.identity, self.compiler = target, identity, compiler
        self.compiled, self.batch = identity.endswith('_compiled'), identity == 'md5_compiled'
        require(identity in ('sha1', 'md5', 'sha1_compiled', 'md5_compiled'), 'pre-arm identity')
        self.args, self.params = loans.formals(signature, ('ptr', 'ptr', 'ptr', 'ptr') if self.batch else ('ptr', 'ptr', 'ptr', 'i64', 'ptr'))
        require(('dereferenceable(256)' if self.compiled else 'dereferenceable(240)') in self.args[0]
                and ('dereferenceable(320)' if self.batch else 'dereferenceable(56)') in self.args[1], 'pre-arm owner/request extent')
        self.owner = 'brynja_legacy_hmac_std::' + ('macos_resident' if target == 'aarch64-apple-darwin' else 'strict_execution')
        self.clear = ('<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear'
                      if target == 'aarch64-apple-darwin' else '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear')
        self.cancel = '<' + self.owner + '::types::Cancellation>::check'
        self.validate = self.owner + ('::md5_compiled' if self.batch else '') + '::types::validate'
        self.drop = '<' + self.owner + '::Buffers as core::ops::drop::Drop>::drop'
        self.ok = 255 if compiler == '1.99.1' else 10
        self.allocs = {'local:' + m[1]: int(m[2]) for m in re.finditer('(' + V + r') = alloca \[(\d+) x i8\]', body)}
        self.managed = {'local:' + syntax.operand(c[1][-1]) for line in body.splitlines()
                        if (c := syntax.call(line)) and c[0] == 'llvm.lifetime.start.p0'}
        self.points, self.callee_points = set(), set()
        self.boundaries = set()

    def run(self, request):
        self.request, self.events, self.memory, self.live = request, [], {}, set()
        self.cancel_reads, self.armed, self.depth = 0, False, 0
        self.uses, self.callee_uses = set(), {}
        m = self.memory
        m['self', 0, 'i128'] = request.max_bits
        m['self', 40, 'i64'] = request.max_key
        m['self', 48, 'i64'] = 123 if self.batch else request.max_chunks
        m['self', 64, 'i64'] = request.width
        m['self', 240, 'i8'] = request.backend if self.batch else 0
        m['self', 241, 'i8'] = int(request.quarantined)
        if self.batch:
            self.batch_memory(request)
            initial = dict(zip(self.params, (('self', 0), ('inputs', 0),
                           None if request.candidate is None else ('candidate', 0), ('cancel', 0))))
        else:
            for offset, kind, value in ((0, 'ptr', ('key', 0)), (8, 'i64', request.key),
                                    (16, 'ptr', ('chunks', 0)), (24, 'i64', len(request.chunks)),
                                    (32, 'ptr', ('tail', 0)), (40, 'i64', request.tail), (48, 'i8', request.bits)):
                m['request', offset, kind] = value
            for lane, length in enumerate(request.chunks):
                m['chunks', lane * 16, 'ptr'] = ('message-' + str(lane), 0)
                m['chunks', lane * 16 + 8, 'i64'] = length
            initial = dict(zip(self.params, (('self', 0), ('request', 0),
                       None if request.candidate is None else ('candidate', 0),
                       flow.values.Unknown() if request.candidate is None else request.candidate, ('cancel', 0))))
        outcome, result, points = flow.run(self.body, initial, self.read, self.write, self.call, self.stop, self.uses)
        self.points |= points
        expected = request.error()
        require(outcome == ('admitted' if expected is None else 'rejected'), 'pre-arm admission/rejection differs from request policy')
        require(self.cancel_reads == int(expected in (None, 6)), 'pre-arm cancellation ordering/population changed')
        if expected is None:
            require(self.events == [184, 128] and self.armed == self.compiled, 'pre-arm clearing/quarantine admission changed')
        else:
            require(flow.values.integer(result, 8) == expected and not self.armed
                    and self.events == ([184, 128] if expected == 9 else [184, 128, 128, 184]),
                    'pre-arm rejection changed error, retained output or quarantined session')
            if expected == 7:
                require(flow.values.integer(result, 16) >> 8 == 5, 'pre-arm eligibility rejection payload changed')

    def batch_memory(self, request):
        for lane in range(8):
            active = bool(request.mask & (1 << lane))
            self.memory['inputs', lane * 40, 'ptr'] = ('key-' + str(lane), 0) if active else None
            if active:
                for offset, kind, value in ((8, 'i64', request.keys[lane]), (16, 'ptr', ('message-' + str(lane), 0)),
                                            (24, 'i64', request.tails[lane]), (32, 'i8', request.bits[lane])):
                    self.memory['inputs', lane * 40 + offset, kind] = value
            if request.candidate is not None:
                length = request.candidate[lane]
                self.memory['candidate', lane * 16, 'ptr'] = None if length is None else ('tag-' + str(lane), 0)
                self.memory['candidate', lane * 16 + 8, 'i64'] = flow.values.Unknown() if length is None else length

    def local(self, address, kind):
        root, offset = address
        width = {'ptr': 8, 'i8': 1, 'i16': 2, 'i64': 8, 'i128': 16}[kind]
        require(root in self.allocs and 0 <= offset <= self.allocs[root] - width
                and (root not in self.managed or root in self.live), 'pre-arm local extent/lifetime changed')

    def read(self, address, kind):
        require(isinstance(address, tuple) and len(address) == 2, 'pre-arm read without pointer')
        if kind == 'atomic':
            require(address == ('cancel', 0) and self.events == [184, 128] and not self.cancel_reads,
                    'pre-arm cancellation pointer/order changed')
            self.cancel_reads += 1
            return int(self.request.cancelled)
        if address[0].startswith('local:'):
            self.local(address, kind)
        else:
            require(self.events == [184, 128], 'pre-arm metadata read before clearing/after rejection')
            require(not self.request.quarantined or address == ('self', 241), 'pre-arm quarantined request inspected')
        require((*address, kind) in self.memory, 'pre-arm read outside typed descriptors: ' + repr((address, kind)))
        return self.memory[*address, kind]

    def write(self, address, kind, value):
        if address == ('self', 241):
            require(self.compiled and kind == 'i8' and value == 1 and not self.armed
                    and self.request.error() is None and self.cancel_reads == 1, 'premature/incorrect quarantine arming')
            self.armed = True
            self.memory['self', 241, 'i8'] = 1
            return
        self.local(address, kind)
        widths = {'ptr': 8, 'i8': 1, 'i16': 2, 'i64': 8, 'i128': 16}
        # A differently typed overlapping store must invalidate the old value;
        # retaining a stale byte here could falsely preserve a guard's keep=0.
        for root, offset, dtype in list(self.memory):
            if root == address[0] and max(offset, address[1]) < min(offset + widths[dtype], address[1] + widths[kind]):
                del self.memory[root, offset, dtype]
        self.memory[*address, kind] = value

    def call(self, symbol, args, value):
        name = self.names.get(symbol, symbol)
        if symbol.startswith('llvm.lifetime.'):
            root, offset = value(args[-1])
            require(root in self.allocs and offset == 0 and (len(args) == 1 or len(args) == 2
                    and value(args[0]) == self.allocs[root]), 'pre-arm lifetime extent changed')
            if 'start' in symbol:
                require(root not in self.live, 'pre-arm repeated lifetime start')
                self.live.add(root)
            else:
                require(root in self.live, 'pre-arm lifetime ends before start')
                self.live.remove(root)
            return None
        if name == self.clear:
            require(len(args) == 1 and value(args[0]) in (('self', 128), ('self', 184)), 'pre-arm wrong clear owner')
            self.events.append(value(args[0])[1])
            return None
        if name == self.drop:
            require(len(args) == 1, 'pre-arm guard arity')
            root, offset = value(args[0])
            require(self.read((root, offset), 'ptr') == ('self', 184)
                    and self.read((root, offset + 8), 'ptr') == ('self', 128)
                    and self.read((root, offset + 16), 'i8') == 0, 'pre-arm guard owner/keep changed')
            self.events.extend((128, 184))
            return None
        if symbol == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4, 'pre-arm copy arity')
            dest, source, size, volatile = map(value, args)
            require(source == ('self', 0) and size == 64 and volatile == 0 and dest[1] == 0
                    and self.allocs.get(dest[0]) == 64, 'pre-arm copy is not original Limits')
            self.local(dest, 'i128')
            for (root, offset, kind), item in list(self.memory.items()):
                if root == 'self' and offset < 64:
                    self.memory[dest[0], offset, kind] = item
            return None
        require(name in (self.validate, self.cancel) and name in self.callees and self.depth == 0,
                'pre-arm unreviewed call: ' + name)
        signature, body = self.callees[name]
        require('alloca ' not in body, 'pre-arm outlined callee acquired unmodeled local storage')
        params = syntax.parameters(signature)
        require(len(args) == len(params), 'pre-arm outlined callee arity')
        actual = [value(arg) for arg in args]
        if name == self.cancel:
            require(actual == [('cancel', 0)], 'pre-arm outlined cancellation identity')
        elif self.batch:
            require(actual[0] == ('inputs', 0) and actual[1] == (None if self.request.candidate is None else ('candidate', 0)),
                    'pre-arm outlined batch input provenance')
        else:
            require(actual[1] == ('request', 0) and actual[2] == (None if self.request.candidate is None else ('candidate', 0))
                    and actual[4] == self.request.width, 'pre-arm outlined validation provenance')
        self.depth = 1
        outcome, result, reached = flow.run(body, dict(zip((a.split()[-1] for a in params), actual)),
                                          self.read, self.write, self.call, lambda *_: False,
                                          self.callee_uses.setdefault(name, set()))
        self.depth = 0
        self.callee_points |= {(name, *point) for point in reached}
        require(outcome == 'rejected' and isinstance(result, tuple) and len(result) == 2, 'pre-arm callee Result shape changed')
        return result

    def stop(self, point, line, argument, value):
        call = syntax.call(line)
        load = re.fullmatch(V + r' = load ptr, ptr (' + V + r'), align \d+', line)
        access = '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::as_bytes_mut'
        boundary = (load and value(load[1]) in (('self', 128), ('self', 184))) or (
            call and self.names.get(call[0]) == access)
        if boundary:
            if call:
                require(len(call[1]) == 1 and argument(call[1][0]) in (('self', 128), ('self', 184)),
                        'pre-arm selected storage changed')
            require(self.request.error() is None and self.cancel_reads == 1, 'worker storage reached before valid request/cancellation')
            self.boundaries.add(point)
            return True
        return False


def check(signature, body, names, leaf, target, identity, compiler):
    owner = 'brynja_legacy_hmac_std::' + ('macos_resident' if target == 'aarch64-apple-darwin' else 'strict_execution')
    wanted = (owner + ('::md5_compiled' if identity == 'md5_compiled' else '') + '::types::validate',
              '<' + owner + '::types::Cancellation>::check')
    callees = []
    for name in wanted:
        selected = [s for s in (*leaf[0], *leaf[1]) if leaf[2].get(s) == name]
        require(len(selected) <= 1, 'pre-arm callee ambiguous')
        if selected:
            callees.append((name, *flow.base.common.resolve(selected[0], *leaf[:2])))
    require(all(names[s] == leaf[2][s] for s in names.keys() & leaf[2].keys()), 'pre-arm conflicting symbol resolution')
    return _check(signature, body, tuple(sorted({**leaf[2], **names}.items())), tuple(callees), target, identity, compiler)


@lru_cache(maxsize=16)
def _check(signature, body, names, callees, target, identity, compiler):
    model = Admission(signature, body, dict(names), {n: (a, b) for n, a, b in callees}, target, identity, compiler)
    population = cases.batch() if identity == 'md5_compiled' else cases.scalar(identity)
    for request in population:
        model.run(request)
    return Evidence(signature, body, target, identity, compiler, frozenset(model.points),
                    frozenset(model.callee_points), len(population), frozenset(model.boundaries))
