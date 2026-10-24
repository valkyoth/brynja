"""SHA-1 worker retained-object consumption and MD5 selector borrow lifetime.

SHA-1's actual outlined Drop is checked for both owners and the empty case.
Update and terminal internals remain separately qualified callee contracts;
this projection does not claim erasure of compiler-created byte copies.
"""
import re

import legacy_hmac_hosted_keyed as keyed
import legacy_hmac_hosted_storage as storage
import legacy_hmac_execution_graph as cleanup

flow, syntax, require, V = keyed.flow, keyed.syntax, keyed.require, keyed.V


def drop_helper(symbol, definitions, aliases, panic):
    # Reuse the existing legacy destructor interpreter, not a modern-HMAC
    # layout or a name-only assertion. Primitive Sha1Owner::drop is its explicit
    # separately reviewed non-panicking premise.
    graph = cleanup.Graph.__new__(cleanup.Graph)
    graph.modules, graph.panic = [(definitions, aliases)], panic
    for niche in (0, 1, 2):
        state = cleanup.model.State(niche)
        outcomes = graph.walk(symbol, 0, [('state', 0)], state, None)
        require(all(status == 'ret' and child.done == (set() if niche == 2 else {0, 1})
                    for status, _, child in outcomes), 'legacy worker destructor omits owner cleanup')


def selector(model):
    """MD5 selection has no key state: only the two admitted borrows may use it."""
    roots, _, _, _, _ = storage.check(model)
    consumers = {site for _, site, _ in model.consumers}
    for label, lines in model.graph.items():
        for index, line in enumerate(lines):
            site = label, index
            if not model.can_precede(model.cut, site):
                continue
            refs = {name for name in re.findall(V, line)
                    if (p := model.pointer(name)) and p[0] in roots}
            if not refs:
                continue
            if site in model.call_map:
                symbol, _ = model.call_map[site]
                require(symbol == 'llvm.lifetime.end.p0' or site in consumers, 'legacy selector modified/escaped after admission')
            else:
                require(re.fullmatch(V + r' = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                     + V + r', i64 \d+', line), 'legacy selector read/write after admission')
    return set()


def check(model, definitions, aliases, panic):
    require(panic in ('abort', 'unwind'), 'unreviewed legacy worker panic profile')
    if model.identity == 'md5_compiled':
        return selector(model)
    roots, copies, _, _, _ = storage.check(model)
    # Constructor Result/temporary storage has no logical retained-object token.
    active_roots = {model.owner, *copies}
    terminals = {site: root for root, site, _ in model.terminals}
    moves = {site: root for root, _, site in model.terminals}
    helpers, updates, consumed, exits = set(), set(), set(), set()
    pending = [(model.cut[0], model.cut[1] + 1, model.owner, False)]
    seen = set()
    while pending:
        label, start, held, unwinding = pending.pop()
        state = label, start, held, unwinding
        if state in seen:
            continue
        seen.add(state)
        require(label in model.graph and len(seen) < 4000, 'legacy retained worker graph exceeds bound')
        lines = model.graph[label]
        for index in range(start, len(lines)):
            line, site = lines[index], (label, index)
            refs = {name: model.pointer(name) for name in re.findall(V, line)
                    if (p := model.pointer(name)) and p[0] in active_roots}
            spent_sources = {name for name in re.findall(V, line)
                             if (p := model.pointer(name)) and p[0] in model.roots - {model.owner}}
            if spent_sources:
                call = model.call_map.get(site)
                require(call and call[0] == 'llvm.lifetime.end.p0'
                        or re.fullmatch(V + r' = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                        + V + r', i64 \d+', line),
                        'legacy constructor representation used after retained admission')
            if site in model.call_map:
                symbol, args = model.call_map[site]
                name = model.names.get(symbol, symbol)
                if symbol.startswith('llvm.lifetime.'):
                    pointer = model.pointer(syntax.operand(args[-1]))
                    if pointer and pointer[0] in active_roots:
                        require(symbol == 'llvm.lifetime.start.p0' or held != pointer[0],
                                'legacy keyed lifetime ends without consumption')
                elif site in moves:
                    require(held == model.owner, 'legacy keyed move after consumption')
                    held = moves[site]
                elif site in terminals:
                    require(held == terminals[site], 'legacy finalizer lacks moved live owner')
                    require(panic == 'abort' or 'invoke ' in line, 'legacy keyed finalizer lost unwind edge')
                    held = None  # Actual consuming callee is separately qualified.
                    consumed.add(site)
                elif refs and name in ('core::ptr::drop_glue::<brynja_legacy_hmac::execution::Sha1Hmac>',
                                       'core::ptr::drop_in_place::<brynja_legacy_hmac::execution::Sha1Hmac>'):
                    require(len(args) == 1 and model.pointer(syntax.operand(args[0])) == (held, 0)
                            and held == model.owner, 'legacy keyed drop after move/cleanup or wrong owner')
                    if symbol not in helpers:
                        drop_helper(symbol, definitions, aliases, panic)
                        helpers.add(symbol)
                    held = None
                elif refs and name == keyed.PREFIX['sha1_compiled'] + '::update':
                    require(len(args) == 3 and model.pointer(syntax.operand(args[0])) == (model.owner, 0)
                            and held == model.owner and len(refs) == 1, 'legacy update borrows absent/wrong owner')
                    require(panic == 'abort' or 'invoke ' in line, 'legacy keyed update lost unwind edge')
                    updates.add(site)
                else:
                    require(not refs, 'legacy retained object passed to unknown callee')
                    if held is not None:
                        require(panic == 'abort' or 'invoke ' in line or symbol.startswith('llvm.')
                                or flow.panic_cleanup(symbol), 'ordinary potentially-unwinding call with live keyed owner')
                if flow.panic_cleanup(symbol) or name == 'core::panicking::panic_cannot_unwind':
                    require(unwinding and lines[index + 1:] == ['unreachable'], 'unreviewed fatal legacy worker exit')
                    break  # Fatal abort is outside recoverable cleanup guarantees.
            elif refs:
                require(re.fullmatch(V + r' = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                     + V + r', i64 \d+', line), 'legacy retained object read/write outside admitted operations')
            elif re.search(r'\b(?:call|invoke)\b', line):
                require(held is None, 'indirect call with live legacy keyed object')
            if re.search(r'\binvoke\b', line):
                edges = re.fullmatch('to label %' + flow.LABEL + ' unwind label %' + flow.LABEL
                                     + r'(?:,.*)?', lines[index + 1])
                require(edges, 'legacy retained invoke edges changed')
                pending.extend(((edges[1], 0, held, unwinding), (edges[2], 0, held, True)))
                break
            if line.startswith(('br ', 'switch ')):
                text = line if line.startswith('br ') else '\n'.join(lines[index:]).split(']', 1)[0]
                edges = re.findall('label %' + flow.LABEL, text)
                require(edges, 'legacy retained branch missing targets')
                pending.extend((edge, 0, held, unwinding) for edge in edges)
                break
            if line.startswith(('ret ', 'resume ')):
                require(held is None, 'legacy worker exits without keyed cleanup/consumption')
                exits.add(site)
                break
            require(line != 'unreachable', 'unreviewed unreachable legacy retained path')
        else:
            require(False, 'unterminated legacy retained worker block')
    require(helpers and updates and consumed == set(terminals) and exits, 'vacuous legacy retained cleanup projection')
    return helpers
