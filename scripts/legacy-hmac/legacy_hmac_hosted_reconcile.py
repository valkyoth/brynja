"""Cross-projection host/worker bindings, not a new native/erasure guarantee.

All objects come from the same outer compiler-validation invocation. These
checks connect already validated projections; they are not serialized receipts,
external approvals or substitutes for the underlying worker/owner checks.
"""
import re

import legacy_hmac_hosted_capture as capture
import legacy_hmac_hosted_envelope as envelope
import legacy_hmac_hosted_prearm as prearm
import legacy_hmac_hosted_preentry as preentry

require, syntax, V = capture.require, capture.syntax, capture.V


def check(prefix, native, record, joined, worker, worker_signature, worker_body, worker_envelope):
    require(isinstance(prefix, prearm.Evidence), 'missing typed admission projection')
    binding = record.signature, record.body, record.target, record.identity
    require((prefix.signature, prefix.body, prefix.target, prefix.identity) == binding
            == (native.signature, native.body, native.target, native.identity)
            and prefix.compiler == joined.compiler and joined.r is record
            and native.graph == record.graph and native.names == record.names,
            'host projections describe different executor artifacts')
    require(prefix.scenarios > 0 and len(prefix.boundaries) == 1
            and prefix.boundaries <= prefix.points and joined.scenarios > 0,
            'missing/ambiguous checked admission/transaction population')
    boundary, = prefix.boundaries
    require(native.create == record.create[0] and native.job == record.job
            and native.allocs == record.allocs, 'launch/capture storage identity mismatch')
    require(record.before(boundary, native.create)
            and all(record.before(point, boundary) for point in joined.initial),
            'launch bypasses admission boundary or initial clearing')
    if record.identity.endswith('_compiled'):
        armed = [point for point, value in joined.quarantine if value == '1']
        require(len(armed) == 1 and record.before(armed[0], boundary),
                'compiled admission/transaction arming mismatch')
    require(worker_envelope.get('binding') == (worker_signature, worker_body, record.identity,
                                               tuple(sorted(record.names.items()))),
            'worker envelope belongs to another callback artifact')
    symbol, args = native.calls[native.create]
    require(symbol == 'pthread_create' and re.fullmatch(r'ptr [^@]*@' + re.escape(worker), args[2]),
            'selected worker is not the native callback')
    fields, complete, result, _ = envelope.fields(record.identity)
    require(joined.flags == (complete, complete + 1), 'worker/host completion fields disagree')
    initialized = {offset + i for offset, data in record.expected.items() for i in range(len(data))}
    widths = {'ptr': 8, 'i64': 8, 'i8': 1}
    require(result in worker_envelope['loads'] and all(
        offset in fields and set(range(offset, offset + widths[fields[offset]])) <= initialized
        for offset in worker_envelope['loads']), 'worker reads uncaptured bytes/padding')
    require(record.read((record.job, result), 8, native.create) == capture.pointer('%result')
            and record.allocs.get('%result') == 2, 'worker/host result destination mismatch')
    for offset in joined.flags:
        require(record.read((record.job, offset), 1, native.create) == (('constant', 0),),
                'worker completion flag not initially false')
    storage = borrowed_lifetimes(record, joined)
    ordinary_setup = preentry.check(joined, boundary) if not joined.compiled else 0
    return {'identity': record.identity, 'target': record.target, 'compiler': prefix.compiler,
            'admission_scenarios': prefix.scenarios, 'transaction_scenarios': joined.scenarios,
            'ordinary_setup_scenarios': ordinary_setup,
            'captured_fields_read': len(worker_envelope['loads']), 'borrowed_locals': storage}


def borrowed_lifetimes(record, joined):
    """Borrowed locals survive join and every actual host memory access.

Callback accesses are bounded separately by the worker envelope. Treating the
join as a use of every borrowed local connects its lifetime to that callback,
including generic workers that consume fewer fields than accelerated ones.
"""
    joins = [point for point, (name, _) in joined.calls.items()
             if name == 'pthread_join' or name == joined.resource + '::thread::join']
    require(len(joins) == 1, 'reconciliation join population')
    graph = record.graph
    ptrs = syntax.pointers(record.body, record.allocs)
    starts, ends = {}, {}
    uses = {root: {record.create[0], joins[0]} for root in record.borrowed}
    for block, lines in graph.items():
        for index, line in enumerate(lines):
            point = block, index
            call = syntax.call(line)
            if call and call[0].startswith('llvm.lifetime.'):
                root, offset = ptrs.get(syntax.operand(call[1][-1]), (None, None))
                if root in uses:
                    require(offset == 0 and call[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'),
                            'borrowed lifetime root changed')
                    (starts if 'start' in call[0] else ends).setdefault(root, []).append(point)
                continue
            # Capture isolation already confines these roots to typed accesses
            # and the native launch. Here bind those accesses to their lifetimes.
            if re.search(r'\b(?:load|store)\b', line):
                for token in re.findall(V, line):
                    root = ptrs.get(token, (None,))[0]
                    if root in uses:
                        uses[root].add(point)
    for root, accesses in uses.items():
        if root not in starts:
            # Without lifetime intrinsics an alloca lives for the invocation.
            # An orphan end is not such a frame-lifetime allocation.
            require(root not in ends, 'borrowed lifetime ends without start: ' + root)
            start = record.defs[root][1]
        else:
            require(len(starts[root]) == 1, 'borrowed local repeats lifetime start: ' + root)
            start = starts[root][0]
        require(all(record.before(start, use) for use in accesses), 'borrowed local used before lifetime start')
        require(all(not record.can_precede(end, use) for end in ends.get(root, []) for use in accesses),
                'borrowed local expires before join/last host access: ' + root)
    return len(uses)
