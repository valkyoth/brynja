"""Bind actual consumer admission, returned tag metadata and region transport.

The secret consumer's creation/cleanup of its region and the verification
consumer's comparison semantics are separate obligations. Here their results
must survive transport, and consumer errors/unwind cannot become success.
"""
import re

import legacy_hmac_md5_return_header as header
import legacy_hmac_md5_normalization_return as storage

r, output = header.r, header.output
require, VALUE, Bits, Pointer = r.require, r.VALUE, r.Bits, r.Pointer


def probes(fixture):
    success = r.layout.probe(fixture, 'region_success', 24, {},
                             {'%region.0': Pointer('owner'), '%region.1': Bits.token('extent')})
    error = r.layout.probe(fixture, 'region_error', 24, {}, {'%error': Bits.token('error', 8)})
    require(r.layout.read(success, 0, 1) == Bits.integer(0, 8) and
            r.layout.read(success, 8, 8) == Pointer('owner').bits() and
            r.layout.read(success, 16, 8) == Bits.token('extent') and
            r.layout.read(error, 0, 1) == Bits.integer(1, 8) and
            r.layout.read(error, 1, 1) == Bits.token('error', 8), 'consumer region ABI changed')


def excluded(graph, failed, stops):
    for label in failed:
        reachable = r.phases.handoff.reachable(graph, label)
        require(all(site[0] not in reachable for site in stops), 'consumer failure/unwind reaches successful output')


def fields(check, base, niche):
    headers = header.fields(check, base, niche)
    block = headers[0][3][0]
    found = {}
    for site, offset, size, dtype, value in output.writes(check.body):
        if not output.overlap(offset, size, 0, base):
            continue
        if site[0] != block:
            require(site[0] not in r.phases.handoff.reachable(check.graph, block),
                    'returned output overwritten after construction')
            continue  # Error payloads are not successful output objects.
        expected = {0: 'i8'} if base == 8 else {0: 'i64', 8: 'ptr', 16: 'i64', **({24: 'i64'} if base == 32 else {})}
        require(offset not in found and expected.get(offset) == dtype, 'returned tag fields missing/overlapping')
        found[offset] = (dtype, value, site)
    require(set(found) == ({0} if base == 8 else {0, 8, 16} if base == 24 else {0, 8, 16, 24}),
            'returned output field population changed')
    return found


def gate(check, operation, returned, copy_ok):
    param = r.syntax.operand(r.syntax.parameters(check.signature)[3])
    call = r.phases.one(check.body, lambda name, args:
        (r.phases.handoff.copy_region(name) and r.syntax.operand(args[0]) == param) if operation == 'authenticate'
        else r.phases.handoff.closure(name, operation), 'final output consumer')
    normal, unwind = r.n.results.continuation(check.graph, call)
    lines = check.graph[normal[0]][normal[1]:]
    stops = [field[2] for field in returned.values()]
    for site in stops:
        r.phases.dominates(check.graph, call[:2], site)
    failed = [unwind[0]] if unwind else []
    if operation == 'verify':
        result = re.match(rf'({VALUE}) = (?:tail )?(?:call|invoke) ', check.graph[call[0]][call[1]])
        require(result and returned[0][1] == result[1], 'verification result replaced before return')
    else:
        if operation == 'authenticate':
            result = re.match(rf'({VALUE}) = (?:tail )?(?:call|invoke) ', check.graph[call[0]][call[1]])
            compare = re.fullmatch(rf'({VALUE}) = icmp eq i8 {re.escape(result[1])}, {copy_ok}', lines[0]) if result else None
            require(compare and len(lines) == 2, 'public consumer success is not checked')
            tested, good = compare[1], True
        else:
            result_root, capture = (r.syntax.operand(arg) for arg in call[3][:2])
            end = r.syntax.call(lines[0])
            require(end and end[0] == 'llvm.lifetime.end.p0' and r.syntax.operand(end[1][-1]) == capture
                    and capture != result_root and check.allocs.get(capture) == 24, 'consumer capture completion changed')
            load = re.fullmatch(rf'({VALUE}) = load i8, ptr {re.escape(result_root)}, align 8(?:, !.*)?', lines[1])
            narrow = re.fullmatch(rf'({VALUE}) = trunc(?: nuw)? i8 {re.escape(load[1])} to i1', lines[2]) if load else None
            require(narrow and len(lines) >= 4, 'secret consumer result is not checked')
            pointers = r.syntax.pointers(check.body, (result_root,))
            names = {name for name, address in pointers.items() if address[0] == result_root}
            for line in lines[3:-1]:
                invocation = r.syntax.call(line)
                if invocation:
                    require(invocation[0] == 'llvm.lifetime.end.p0' and r.syntax.operand(invocation[1][-1]) == result_root,
                            'secret result admission gained an effect')
                else:
                    require(re.fullmatch(rf'{VALUE} = (?:load (?:i8|ptr|i64), ptr {VALUE}, align [18](?:, !.*)?|'
                                         rf'getelementptr inbounds(?: nuw)? i8, ptr {VALUE}, i64 \d+)', line)
                            and set(re.findall(VALUE, line)) & names, 'unbound secret result admission instruction')
            tested, good = narrow[1], False
        branch = re.fullmatch(rf'br i1 {re.escape(tested)}, label %' + r.flow.LABEL + ', label %' + r.flow.LABEL, lines[-1])
        require(branch, 'consumer admission branch detached from result')
        accepted = branch[1 if good else 2]; failed.append(branch[2 if good else 1])
        for site in stops:
            r.phases.dominates(check.graph, (accepted, -1), site)
    excluded(check.graph, failed, stops)
    return call


def region_transport(check, call, returned):
    root = r.syntax.operand(call[3][0])
    require(check.allocs.get(root) == 24, 'consumer region result storage changed')
    pointers = {name: address for name, address in r.syntax.pointers(check.body, (root,)).items() if address[0] == root}
    starts, ends, loads = [], [], {}
    for label, lines in check.graph.items():
        for index, line in enumerate(lines):
            if not set(re.findall(VALUE, line)) & pointers.keys():
                continue
            site, invocation = (label, index), r.syntax.call(line)
            if site == call[:2] or line == root + ' = alloca [24 x i8], align 8':
                continue
            gep = re.fullmatch(r.n.pads.descriptors.GEP, line)
            load = re.fullmatch(rf'({VALUE}) = load (i8|i64|ptr), ptr ({VALUE}), align [18](?:, !.*)?', line)
            if gep:
                require(pointers.get(gep[1], (None, None))[1] in (1, 8, 16), 'unbound consumer region address')
            elif load:
                offset = pointers[load[3]][1]
                require(offset not in loads and {0: 'i8', 1: 'i8', 8: 'ptr', 16: 'i64'}.get(offset) == load[2],
                        'consumer region fields overwritten or read with wrong type')
                loads[offset] = (site, load[1])
                r.phases.dominates(check.graph, call[:2], site)
            elif invocation and invocation[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
                args = invocation[1]
                require(len(args) in (1, 2) and r.syntax.operand(args[-1]) == root
                        and (len(args) == 1 or args[0] == 'i64 24'), 'consumer region lifetime extent changed')
                (starts if 'start' in invocation[0] else ends).append(site)
            else:
                require(False, 'unreviewed consumer region effect: ' + line)
    require(len(starts) == 1 and set(loads) == {0, 1, 8, 16}, 'consumer region field/lifetime population changed')
    r.phases.dominates(check.graph, starts[0], call[:2])
    for offset, (site, value) in loads.items():
        require(not any(storage.path(check.graph, starts[0], end) and storage.path(check.graph, end, site) for end in ends),
                'consumer region loaded after lifetime end')
        if offset in (8, 16):
            require(returned[offset][1] == value, 'consumer region pointer/length lost return provenance')
            r.phases.dominates(check.graph, site, returned[offset][2])


def metadata(check, returned, secret):
    length_offset = 24 if secret else 16
    dtype, length, site = returned[length_offset]
    pointers = r.syntax.pointers(check.body, (check.selection,))
    definition = check.defs.get(length)
    load = re.fullmatch(rf'{VALUE} = load i64, ptr ({VALUE}), align 8(?:, !.*)?', definition[1]) if definition else None
    require(dtype == 'i64' and load and pointers.get(load[1]) == (check.selection, 8), 'returned tag width is not selected width')
    r.phases.dominates(check.graph, definition[0], site)
    if not secret:
        expected = r.syntax.operand(r.syntax.parameters(check.signature)[3])
        require(returned[8][1] == expected, 'public tags reference a different destination')
    for backend in (0, 1):
        for mask in range(256):
            def compare(state):
                value = state.value(returned[0][1], 'i64')
                expected = sum(((mask >> lane) & 1) << (lane * 8) for lane in range(8))
                require(value == Bits.integer(expected, 64), 'returned activity metadata is not actual input activity')
            check.run_report(mask, backend, on_entry=compare)


def public_destination(check, call, returned):
    param = r.syntax.parameters(check.signature)[3]
    root = r.syntax.operand(param)
    require('noalias' in param and 'dereferenceable(128)' in param, 'public output lost exclusive fixed extent')
    allowed = {call[:2], returned[8][2]}
    for label, lines in check.graph.items():
        for index, line in enumerate(lines):
            if root in re.findall(VALUE, line):
                require((label, index) in allowed, 'public output escapes or is touched outside final copy')


def validate(fixture, llvm):
    probes(fixture)
    copy_ok = r.n.pads.probes(fixture)
    offsets = header.probes(fixture)
    definitions, aliases = r.flow.definitions_and_aliases(llvm)
    checks = []
    for operation, (base, niche) in offsets.items():
        signature, body = r.phases.rows.method(definitions, aliases, operation)[1]
        check = r.inner.Check(signature, body, llvm); check.signature = signature
        returned = fields(check, base, niche)
        call = gate(check, operation, returned, copy_ok)
        if operation != 'verify':
            metadata(check, returned, operation == 'authenticate_secret')
        if operation == 'authenticate_secret':
            region_transport(check, call, returned)
        elif operation == 'authenticate':
            public_destination(check, call, returned)
        checks.append((check, returned, call, base, niche))
    return checks
