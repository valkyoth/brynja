"""Worker access to the launch envelope and completion-write ordering.

This does not interpret the keyed computation or authenticate its result value.
It confines direct Job accesses, binds the result destination, and orders the
completion/panic writes around their actual result/catch operations.
"""
import re

import legacy_hmac_hosted_capture_model as capture
import legacy_hmac_md5_phases as phases
import legacy_hmac_md5_normalization_return as paths

flow, syntax, require, V = capture.flow, capture.syntax, capture.require, capture.V


def fields(identity):
    if identity == 'md5_compiled':
        return {0: 'ptr', 8: 'i64', 16: 'ptr', 24: 'i64', 32: 'ptr', 40: 'ptr',
                48: 'ptr', 56: 'ptr', 64: 'i64', 72: 'i64', 80: 'i8'}, 88, 32, 80
    compiled = identity == 'sha1_compiled'
    shift = 8 if compiled else 0
    result = {0: 'ptr', **({8: 'ptr'} if compiled else {})}
    result.update({offset + shift: kind for offset, kind in {
        8: 'ptr', 16: 'ptr', 24: 'i64', 32: 'ptr', 40: 'i64', 48: 'ptr', 56: 'i64', 64: 'i8',
        72: 'ptr', 80: 'ptr', 88: 'ptr', 96: 'i64', 104: 'ptr', 112: 'i64'}.items()})
    return result, 120 + shift, 0, 0


def check(arguments, body, names, identity):
    params = syntax.parameters(arguments)
    require(len(params) == 1, 'legacy worker callback arity changed')
    argument = syntax.operand(params[0])
    ptrs = syntax.pointers(body, [argument])
    graph = flow.blocks(body)
    allowed, completed, result_offset, niche = fields(identity)
    alias = {name: offset for name, (root, offset) in ptrs.items() if root == argument}
    result_roots, loads, writes, catches, returns = {}, {}, [], [], []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            site = label, index
            load = re.match('(' + V + r') = load (ptr|i8|i64), ptr (' + V + '),', line)
            if load and load[3] in alias:
                offset = alias[load[3]]
                require(allowed.get(offset) == load[2], 'worker reads wrong Job field/type')
                require(offset not in loads, 'worker reloads consumed capture')
                loads[offset] = site, load[1]
                if offset == result_offset:
                    result_roots[load[1]] = site
            call = syntax.call(line) if not re.search(r'(?:call|invoke).*?%[-\w.]+\(', line) else None
            if call and names.get(call[0]) == 'std::panicking::catch_unwind::cleanup':
                catches.append(site)
            if line.startswith('ret '):
                require(line == 'ret ptr null', 'worker returns payload instead of null')
                returns.append(site)
            mentioned = set(re.findall(V, line)) & set(alias)
            if not mentioned:
                continue
            if load:
                continue
            gep = re.fullmatch('(' + V + r') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + V + r', i64 \d+', line)
            if gep:
                require(alias.get(gep[1]) in {*allowed, completed, completed + 1}, 'worker Job alias outside fields')
                continue
            store = re.match(r'store (ptr|i8) (null|\d+), ptr (' + V + '),', line)
            if store:
                offset = alias[store[3]]
                require((offset, store[1], store[2]) in {
                    (niche, 'i8' if niche else 'ptr', '2' if niche else 'null'),
                    (completed, 'i8', '1'), (completed + 1, 'i8', '1')},
                    'worker corrupts capture or completion flag')
                writes.append((site, offset))
                continue
            nonnull = re.fullmatch('(' + V + ') = icmp ne ptr ' + re.escape(argument) + ', null', line)
            if nonnull:
                require(index + 1 < len(lines) and re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 '
                        + re.escape(nonnull[1]) + r'\)', lines[index + 1]), 'worker nonnull assumption changed')
                continue
            # These assumptions describe validity of the incoming callback
            # pointer and have no memory effects. No arbitrary call may borrow Job.
            require(re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 true\) \[ "nonnull"\(ptr '
                                 + re.escape(argument) + r'\) \]', line), 'worker Job address escapes/unmodeled use: ' + line)
    require(result_roots and len(returns) == 1, 'worker result/return population changed')
    by_offset = {offset: [site for site, at in writes if at == offset] for offset in (niche, completed, completed + 1)}
    require(len(by_offset[niche]) == len(by_offset[completed]) == 1
            and len(by_offset[completed + 1]) == len(catches) <= 1,
            'worker take/completion/panic write population changed')
    take, done = by_offset[niche][0], by_offset[completed][0]
    # Every capture is copied before Option::take clears its niche; none is
    # fetched again from the consumed launch record afterward.
    for site, _ in loads.values():
        phases.dominates(graph, site, take)
    phases.dominates(graph, take, done)
    result_ptrs = syntax.pointers(body, result_roots)
    result_aliases = {name for name, (root, _) in result_ptrs.items() if root in result_roots}
    result_stores = []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            store = re.match('store (i8|i16) (' + V + r'|-?\d+), ptr (' + V + '),', line)
            mentioned = set(re.findall(V, line)) & result_aliases
            if mentioned and not store:
                define = re.match('(' + V + ') = ', line)
                if define and define[1] in result_roots and result_roots[define[1]] == (label, index):
                    continue
                gep = re.fullmatch('(' + V + r') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + V + r', i64 \d+', line)
                if gep:
                    require(result_ptrs.get(gep[1], (None, -1))[1] in (0, 1), 'worker result alias out of bounds')
                    continue
                nonnull = re.fullmatch(V + ' = icmp (?:eq|ne) ptr (' + V + '), null', line)
                if nonnull and nonnull[1] in result_roots:
                    continue
                assumption = re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 true\) \[ "nonnull"\(ptr ('
                                          + V + r')\) \]', line)
                require(assumption and assumption[1] in result_roots, 'worker result pointer escaped/unmodeled use: ' + line)
                continue
            if not store or result_ptrs.get(store[3], (None,))[0] not in result_roots:
                require(not mentioned, 'worker result pointer stored elsewhere')
                continue
            root, offset = result_ptrs[store[3]]
            size = 1 if store[1] == 'i8' else 2
            require(0 <= offset <= 2 - size, 'worker result write outside two-byte status')
            phases.dominates(graph, result_roots[root], (label, index))
            result_stores.append(((label, index), offset))
    tags = [site for site, offset in result_stores if offset == 0]
    require(len(tags) == 1, 'worker result discriminant write missing/repeated')
    phases.dominates(graph, tags[0], done)
    for site, _ in result_stores:
        require(not paths.path(graph, done, site), 'worker result changed after completion')
    if catches:
        panicked = by_offset[completed + 1][0]
        phases.dominates(graph, catches[0], panicked)
        require(not paths.path(graph, panicked, done) and not paths.path(graph, done, panicked),
                'worker completion and caught panic overlap')
    return {'take': take, 'completed': done, 'panic': by_offset[completed + 1], 'loads': loads, 'result': tags[0]}
