"""Scalar hosted worker logical-owner cleanup dispatch after admission."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_engine_update as cleanup

require, VALUE = common.require, syntax.VALUE


def check(model, identity, definitions, aliases, panic):
    require(not model.compiled and panic in ('abort', 'unwind'), 'wrong scalar worker profile')
    _, core_offset, fields = syntax.geometry(identity)
    tokens = frozenset({0, 1})
    locations = frozenset((model.owner, field, token) for token, field in enumerate(fields))
    # Copies retain provenance, not a second logical owner or a claim of erasure.
    queue = [(model.cut[0], model.cut[1] + 1, locations, frozenset(), frozenset(), False)]
    seen, updates, helpers, exits = set(), set(), set(), set()
    terminals = {point: root for root, point, _ in model.terminals}
    expected_update = ('<brynja_hash_sha2::general::hardened::HardenedSha512T>::update'
                       if identity.startswith('general') else '<brynja_mac_hmac::algorithms::Sha'
                       + identity[3:] + ' as brynja_mac_hmac::algorithms::sealed::Hash>::update')

    def address(name):
        return model.pointer(name)

    def selected(memory, pointer, delta=0):
        base = address(pointer)
        found = {token for root, offset, token in memory if base == (root, offset + delta)}
        require(len(found) == 1, 'missing/ambiguous hosted scalar owner')
        return next(iter(found))

    while queue:
        label, start, memory, done, facts, unwinding = queue.pop()
        state = label, start, memory, done, facts, unwinding
        if state in seen:
            continue
        seen.add(state)
        require(label in model.graph and len(seen) < 15000, 'scalar worker graph exceeds bound')
        lines = model.graph[label]
        for index in range(start, len(lines)):
            line, point = lines[index], (label, index)
            definition = re.match('(' + VALUE + ') =', line)
            if definition:
                facts = frozenset(item for item in facts if item[0] != definition[1])
            if point in model.call_map:
                symbol, args = model.call_map[point]
                refs = [(arg, address(syntax.operand(arg))) for arg in args if arg.startswith('ptr ')]
                owners = [(arg, addr) for arg, addr in refs if addr and any(row[0] == addr[0] for row in memory)]
                if symbol == 'llvm.memcpy.p0.p0.i64' and owners:
                    source, destination = address(syntax.operand(args[1])), address(syntax.operand(args[0]))
                    require(source == (model.owner, 0) and destination and destination[1] == 0
                            and args[2] == 'i64 ' + str(model.size) and not done,
                            'scalar worker owner copy source/extent/order')
                    require(destination[0] in {root for root, _, _ in model.terminals}, 'scalar copy escapes consumer slots')
                    require(not any(root == destination[0] for root, _, _ in memory), 'scalar consumer slot overwritten')
                    memory |= {(destination[0], offset, token) for root, offset, token in memory if root == model.owner}
                elif symbol.startswith('llvm.lifetime.'):
                    pointer = address(syntax.operand(args[-1]))
                    if pointer:
                        rows = {row for row in memory if row[0] == pointer[0]}
                        if symbol == 'llvm.lifetime.end.p0':
                            memory -= rows
                            require(all(token in done or any(row[2] == token for row in memory)
                                        for _, _, token in rows), 'scalar lifetime ends with unconsumed owner')
                        else:
                            require(not rows, 'scalar owner lifetime restarted')
                elif point in terminals:
                    root = terminals[point]
                    require({token for owner, _, token in memory if owner == root} == tokens and not done,
                            'scalar finalizer lacks both live owners')
                    done = tokens  # Separately checked consuming finalizer on both invoke edges.
                elif common.owner_drop(symbol, identity):
                    token = selected(memory, syntax.operand(args[0]), core_offset)
                    require(token not in done, 'duplicate scalar worker destruction')
                    done |= {token}
                elif owners and ('drop_glue' in symbol or 'drop_in_place' in symbol):
                    pointer = syntax.operand(args[0])
                    require({selected(memory, pointer, -field) for field in fields} == tokens and not done,
                            'scalar helper does not receive both live owners')
                    if symbol not in helpers:
                        cleanup.helper(symbol, identity, definitions, aliases)
                        helpers.add(symbol)
                    done = tokens
                elif owners and syntax.adapter_update(symbol):
                    require(model.names.get(symbol) == expected_update, 'scalar worker update algorithm changed')
                    require(selected(memory, syntax.operand(args[0])) == 0 and not done,
                            'scalar update does not borrow live inner owner')
                    require(panic == 'abort' or 'invoke ' in line, 'scalar update lost unwind cleanup edge')
                    updates.add(point)
                else:
                    require(not owners, 'scalar state passed to unreviewed callee')
                    # Before consumption, non-owner calls are LLVM intrinsics or
                    # explicit invokes (cancellation checks). Implicit unwind
                    # from an arbitrary ordinary call must not skip destruction.
                    require(panic == 'abort' or done == tokens or symbol.startswith('llvm.') or 'invoke ' in line
                            or common.panic_cleanup(symbol), 'unreviewed live-owner ordinary call')
            elif re.search(r'\b(?:call|invoke)\b', line):
                require(done == tokens, 'indirect call with live scalar owners')
            load = re.search(r'\bload [^,]+, ptr (' + VALUE + '),', line)
            if load and (pointer := address(load[1])):
                require(not any(root == pointer[0] and token in done for root, _, token in memory),
                        'scalar worker reads after owner consumption')
            if point in model.write_map:
                mode, dest, _ = model.write_map[point]
                pointer = address(dest)
                if mode != 'copy' and pointer:
                    require(not any(row[0] == pointer[0] for row in memory), 'scalar owner overwritten')
            if re.search(r'\binvoke\b', line):
                edges = re.fullmatch(r'to label %' + common.LABEL + r' unwind label %' + common.LABEL
                                     + r'(?:,.*)?', lines[index + 1])
                require(edges, 'scalar worker invoke edges changed')
                queue += [(edge, 0, memory, done, facts, unwinding or exceptional)
                          for edge, exceptional in zip(edges.groups(), (False, True))]
                break
            if line.startswith(('br ', 'switch ')):
                text = line if line.startswith('br ') else '\n'.join(lines[index:]).split(']', 1)[0]
                edges = re.findall(r'label %' + common.LABEL, text)
                require(edges, 'scalar worker branch lacks targets')
                conditional = re.fullmatch(r'br i1 (' + VALUE + '), label %' + common.LABEL
                                           + ', label %' + common.LABEL + r'(?:,.*)?', line)
                if conditional:
                    known = dict(facts).get(conditional[1])
                    queue += [(edge, 0, memory, done, facts | {(conditional[1], truth)}, unwinding)
                              for edge, truth in zip(edges, (True, False)) if known is None or known == truth]
                else:
                    queue += [(edge, 0, memory, done, facts, unwinding) for edge in edges]
                break
            if line.startswith(('ret ', 'resume ')):
                require(done == tokens, 'scalar worker exits without both cleanup/consumption dispatches')
                exits.add(label)
                break
            if line == 'unreachable':
                require(unwinding and any('panic_in_cleanup' in row or 'panic_cannot_unwind' in row for row in lines),
                        'unexpected scalar worker fatal path')
                break
        else:
            require(False, 'unterminated scalar worker block')
    require(exits and len(updates) == 1, 'vacuous scalar worker cleanup graph')
    return helpers
