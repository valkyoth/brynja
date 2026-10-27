"""Emitted worker checkpoint identity, ordering and fail-closed continuation."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_checkpoint_results as results
import hmac_hosted_input as input_flow

require, V, L = common.require, syntax.VALUE, common.LABEL


def population(model, target):
    owner, _ = lifecycle.profile(target)
    names = {'<' + owner + '::types::Cancellation>::check',
             owner + ('::compiled' if model.compiled else '') + '::worker::checkpoint'}
    calls = [(symbol, args, point) for symbol, args, point in model.calls if model.names.get(symbol) in names]
    require(len(calls) == (7 if model.compiled else 6), 'worker checkpoint population changed')
    return calls


class Checkpoints:
    def __init__(self, model, flow, output, target, compiler):
        self.m, self.flow, self.output = model, flow, output
        self.ok = -1 if compiler == '1.99.1' else 12
        self.target = target
        owner, _ = lifecycle.profile(target)
        self.cancel_name = '<' + owner + '::types::Cancellation>::check'
        self.check_name = owner + ('::compiled' if model.compiled else '') + '::worker::checkpoint'
        self.points, self.guards = set(), {}

    def guard(self, point):
        m, flow = self.m, self.flow
        line = m.graph[point[0]][point[1]]
        result = re.match('(' + V + r') = (?:tail )?(?:call|invoke) \{ i8, i8 \} @', line)
        require(result, 'checkpoint no longer returns the reviewed Result ABI')
        returned = flow.returned(point)
        block = returned[0]
        lines = m.graph[block]
        require(lines[-1].startswith('br i1 '), 'checkpoint normal return has no admission branch')
        condition, success, failure = flow.branch(block)
        test = re.fullmatch(r'icmp eq i8 (' + V + '), ' + str(self.ok), flow.rhs(condition))
        require(test, 'checkpoint success discriminator changed')
        flow.match(test[1], r'extractvalue \{ i8, i8 \} ' + re.escape(result[1]) + ', 0')
        require(m.before(returned, m.defs[test[1]][1])
                and m.before(m.defs[test[1]][1], m.defs[condition][1])
                and m.before(m.defs[condition][1], (block, len(lines) - 1)),
                'checkpoint guard reads before normal return')
        # No second call or unreviewed control transfer between return and guard.
        for index in range(returned[1] + 1, len(lines) - 1):
            require(re.fullmatch('(' + V + r') = (?:extractvalue \{ i8, i8 \} '
                                + re.escape(result[1]) + r', [01]|icmp eq i8 '
                                + re.escape(test[1]) + ', ' + str(self.ok) + ')', lines[index]),
                    'unreviewed instruction before checkpoint admission')
        require(success != failure, 'checkpoint success/error edges merged')
        self.points.update({point, m.defs[test[1]][1], m.defs[condition][1], (block, len(lines) - 1)})
        self.guards[point] = result[1], test[1], success, failure

    def one(self, predicate, message):
        candidates = [point for point in self.guards if predicate(point)]
        require(len(candidates) == 1, 'checkpoint boundary: ' + message)
        return candidates[0]

    def admitted(self, checkpoint, use):
        success = self.guards[checkpoint][2]
        require(self.m.before((success, -1), use), 'checkpoint success does not dominate operation')

    def check(self):
        m, f, out = self.m, self.flow, self.output
        calls = population(m, self.target)
        expected_authorities = {m.pointer(syntax.operand(args[1]), point) for symbol, args, point in m.calls
                                if m.names.get(symbol, '').startswith('<brynja_mac_hmac::execution::Hmac<')
                                and m.names[symbol].endswith('>::create')}
        for symbol, args, point in calls:
            name = m.names[symbol]
            require(len(args) == (2 if m.compiled and name == self.check_name else 1),
                    'checkpoint argument population')
            cancel = syntax.operand(args[0])
            f.field(cancel, 'ptr', 80)
            require(m.before(m.defs[cancel][1], point), 'checkpoint cancellation capture read too late')
            if len(args) == 2:
                require(expected_authorities == {m.pointer(syntax.operand(args[1]), point)}
                        and None not in expected_authorities, 'checkpoint borrows another authority')
            self.guard(point)
        # Pin each checkpoint to actual iterator/operation landmarks, never
        # guessed SSA names or only a source-level count. Loop-local placement
        # prevents hoisting a check out of repeated/empty chunk iterations.
        initial = self.one(lambda p: m.before(p, f.tail.full[2]), 'initial admission') if not m.compiled else None
        if m.compiled:
            authority = [(args, point) for symbol, args, point in m.calls
                         if m.names.get(symbol) == '<brynja_crypto_cpu::static_execution::Authority>::new']
            require(len(authority) == 1, 'checkpoint authority constructor population')
            initial = self.one(lambda p: m.before(p, authority[0][1]), 'pre-authority cancellation')
            require(m.names[next(s for s, _, p in calls if p == initial)] == self.cancel_name,
                    'initial compiled checkpoint does not check cancellation')
            self.admitted(initial, authority[0][1])
            admitted = self.one(lambda p: p != initial and m.before(p, f.tail.full[2]), 'authority admission')
            self.admitted(admitted, f.tail.full[2])
        else:
            self.admitted(initial, f.tail.full[2])
        chunk_block = m.defs[f.chunk_pointer][1][0]
        chunk = self.one(lambda p: p[0] == chunk_block, 'each selected chunk including empty chunks')
        self.admitted(chunk, (f.part_header, 0))
        part = self.one(lambda p: p[0] == f.nonempty, 'each nonempty 4096-byte part')
        self.admitted(part, f.update)
        final = self.one(lambda p: p[0] == f.finished, 'before finalization')
        self.admitted(final, out.final[1])
        self.admitted(final, out.verify[1])
        copy = self.one(lambda p: m.before(f.returned(out.final[1]), p) and m.before(p, out.copy[1]),
                        'after secret finalization and before copy')
        self.admitted(copy, out.copy[1])
        used = {initial, chunk, part, final, copy} | ({admitted} if m.compiled else set())
        post = self.one(lambda p: p not in used, 'after output/comparison')
        require(m.can_precede(f.returned(out.copy[1]), post)
                and m.can_precede(f.returned(out.verify[1]), post)
                and not m.can_precede(post, out.copy[1]) and not m.can_precede(post, out.verify[1]),
                'final checkpoint moved before output/comparison')
        self.post = post
        protected = set(self.guards) | {f.update, f.tail.full[2], f.tail.partial[2], out.copy[1],
                                       out.final[1], out.verify[1], *m.factories}
        for point, (_, _, success, failure) in self.guards.items():
            require(not any(m.can_precede((failure, -1), use) for use in protected),
                    'checkpoint failure can resume cryptographic work')
            require(not m.can_precede((failure, -1), (success, -1)), 'checkpoint failure rejoins success')
        results.check(self)
        return self


def check(model, flow, output, target, compiler='1.99.1'):
    return Checkpoints(model, flow, output, target, compiler).check()


def preflight(model, arguments, target, compiler='1.99.1'):
    # Run before iterator reconstruction: removing `?` can simplify the loop
    # topology, but must first be diagnosed as missing checkpoint admission.
    flow = input_flow.Input(model, arguments, compiler)
    checked = Checkpoints(model, flow, None, target, compiler)
    for _, _, point in population(model, target):
        checked.guard(point)
