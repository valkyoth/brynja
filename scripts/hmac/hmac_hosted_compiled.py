"""Static hosted retained-engine cleanup; hash internals remain callee premises."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as cleanup
import hmac_hosted_storage as storage

require, VALUE = common.require, syntax.VALUE
UNKNOWN = 'unknown'
PRESENT = frozenset({0, 1})


def helper(symbol, identity, definitions, aliases, compiler, panic):
    parameter, body = cleanup.helper(symbol, definitions, aliases)
    shape = cleanup.layout(identity, 'static')
    for route in range(16):
        metadata, expected = cleanup.initial(identity, route, True, compiler, 'static')
        outcomes = cleanup.walk(body, parameter, 0, metadata, frozenset(), definitions, aliases,
                                expected=expected, size=shape.engine, panic=panic)
        require(all(events == expected for _, events in outcomes), 'hosted compiled helper omits core/scratch cleanup')


def check(model, identity, definitions, aliases, compiler, panic, visited=None):
    helpers = set()
    storage_info = storage.check(model, identity)
    # Outlined helper bodies already explore all sixteen populations. Repeat
    # the caller walk only when it contains inlined core/scratch destruction.
    inline = any(cleanup.leaf(symbol) for symbol, _, point in model.calls
                 if model.can_precede(model.cut, point))
    for route in range(16) if inline else (0,):
        walk(model, identity, definitions, aliases, compiler, panic, route, helpers, storage_info, visited)
    return helpers


def walk(model, identity, definitions, aliases, compiler, panic, route, helpers, storage_info, visited):
    require(model.compiled and panic in ('abort', 'unwind'), 'wrong compiled worker profile')
    shape = cleanup.layout(identity, 'static')
    roots, copies, _, _, _ = storage_info
    metadata, expected = cleanup.initial(identity, route, True, compiler, 'static')
    terminals = {point: root for root, point, _ in model.terminals}
    initial = model.write_map[model.cut][2]
    tag = re.fullmatch('i8 (' + VALUE + ')', initial)
    require(tag, 'compiled admission tag transfer changed')
    queue = [(model.cut[0], model.cut[1] + 1, None, {model.owner: PRESENT},
              {tag[1]: PRESENT}, frozenset(), False)]
    seen, updates, exits = set(), set(), set()
    expected_update = ('<brynja_hash_sha2::hardened_execution::general::Sha512T>::update'
                       if identity.startswith('general') else '<brynja_mac_hmac::algorithms::Sha'
                       + identity[3:] + ' as brynja_mac_hmac::execution::backends::Backend>::update_cpu')

    def address(name):
        result = model.pointer(name)
        return result if result and result[0] in roots else None

    while queue:
        label, start, predecessor, memory, values, done, unwinding = queue.pop()
        key = label, start, predecessor, tuple(sorted(memory.items())), tuple(sorted(values.items())), done, unwinding
        if key in seen:
            continue
        seen.add(key)
        require(label in model.graph and len(seen) < 20000, 'compiled worker graph exceeds bound')
        lines = model.graph[label]

        def schedule(edge, exceptional=False):
            queue.append((edge, 0, label, memory.copy(), values.copy(), done, unwinding or exceptional))

        for index in range(start, len(lines)):
            line, point = lines[index], (label, index)
            if visited is not None:
                visited.add(point)
            definition = re.match('(' + VALUE + ') = (.*)', line)
            if definition:
                name, rhs = definition.groups()
                values.pop(name, None)  # Loop iterations do not retain stale conditions.
                load = re.match(r'load (i8|ptr), ptr (' + VALUE + '),', rhs)
                if load and (source := address(load[2])):
                    root, offset = source
                    require(root in memory, 'compiled worker read outside live storage')
                    if offset == shape.discriminator:
                        values[name] = memory[root]
                    elif offset in metadata:
                        value = cleanup.metadata(metadata, offset, load[1])
                        values[name] = value if isinstance(value, tuple) else frozenset({value})
                    else:
                        require(root == model.owner and offset == shape.engine and not done,
                                'unreviewed compiled worker owner read')
                phi = re.match(r'phi i8 (.*)', rhs)
                if phi:
                    choices = re.findall(r'\[ (' + VALUE + r'|-?\d+|undef), %' + common.LABEL + r' \]', phi[1])
                    selected = [value for value, origin in choices if origin == predecessor]
                    require(len(selected) == 1, 'compiled worker phi predecessor changed')
                    value = selected[0]
                    values[name] = (frozenset({int(value) % 256}) if re.fullmatch(r'-?\d+', value)
                                    else values.get(value, UNKNOWN))
                compare = re.fullmatch(r'icmp (eq|ne) i8 (' + VALUE + r'), (-?\d+)', rhs)
                if compare:
                    domain = values.get(compare[2], UNKNOWN)
                    if isinstance(domain, frozenset):
                        outcomes = {(value == int(compare[3]) % 256) == (compare[1] == 'eq') for value in domain}
                        if len(outcomes) == 1:
                            values[name] = outcomes.pop()
                pointer_compare = re.fullmatch(r'icmp (eq|ne) ptr (' + VALUE + r'), null', rhs)
                if pointer_compare and isinstance(values.get(pointer_compare[2]), tuple):
                    nonnull = values[pointer_compare[2]]
                    require(nonnull[0] == 'nonnull', 'unknown compiled pointer metadata')
                    values[name] = nonnull[1] == (pointer_compare[1] == 'ne')
            if point in model.call_map:
                symbol, args = model.call_map[point]
                refs = [address(syntax.operand(arg)) for arg in args if arg.startswith('ptr ')]
                if symbol == 'llvm.memcpy.p0.p0.i64' and any(refs):
                    dest, source = refs
                    require(source == (model.owner, 0) and dest and dest[1] == 0
                            and dest[0] in copies and copies[dest[0]] == point and dest[0] not in memory
                            and (memory.get(model.owner) == PRESENT and not done
                                 or memory.get(model.owner) == frozenset({2}) and done == expected
                                 and model.allocs[dest[0]] == shape.engine),
                            'compiled worker transfer source/liveness changed')
                    memory[dest[0]] = memory[model.owner]
                elif symbol.startswith('llvm.lifetime.'):
                    pointer = address(syntax.operand(args[-1]))
                    if pointer:
                        root = pointer[0]
                        if symbol == 'llvm.lifetime.end.p0':
                            memory.pop(root, None)
                            require(done == expected or PRESENT in memory.values(), 'compiled lifetime ends without engine consumption')
                        else:
                            require(root not in memory, 'compiled retained lifetime restart')
                elif point in terminals:
                    require(memory.get(terminals[point]) == PRESENT and not done,
                            'compiled finalizer lacks live retained engine')
                    done = expected  # Separately checked consuming finalizer contract.
                elif any(refs) and (kind := cleanup.leaf(symbol)):
                    require(len(args) == 1 and refs[0] and memory.get(refs[0][0]) == PRESENT,
                            'compiled leaf receives absent engine')
                    event = kind, refs[0][1]
                    require(event in expected and event not in done, 'compiled leaf cleanup missing/wrong/duplicate')
                    require(panic == 'abort' or 'invoke ' in line, 'compiled leaf lost unwind edge')
                    done |= {event}
                elif any(refs) and ('drop_glue' in symbol or 'drop_in_place' in symbol):
                    require(len(args) == 1 and refs[0] and refs[0][1] == 0
                            and memory.get(refs[0][0]) == PRESENT and not done,
                            'compiled helper receives empty/consumed/wrong engine')
                    if symbol not in helpers:
                        helper(symbol, identity, definitions, aliases, compiler, panic)
                        helpers.add(symbol)
                    done = expected
                elif any(refs) and model.names.get(symbol) == expected_update:
                    require(refs[0] == (model.owner, 0) and memory.get(model.owner) == PRESENT and not done,
                            'compiled update borrows empty/consumed/wrong engine')
                    require(panic == 'abort' or 'invoke ' in line, 'compiled update lost unwind edge')
                    updates.add(point)
                else:
                    require(not any(refs), 'compiled state passed to unreviewed callee')
                    require(panic == 'abort' or done == expected or symbol.startswith('llvm.') or 'invoke ' in line
                            or common.panic_cleanup(symbol), 'unreviewed compiled live-owner ordinary call')
            elif re.search(r'\b(?:call|invoke)\b', line):
                require(done == expected, 'indirect call with live compiled engine')
            if point in model.write_map:
                mode, dest, data = model.write_map[point]
                if mode != 'copy' and (pointer := address(dest)):
                    require(pointer == (model.owner, shape.discriminator) and data == 'i8 2'
                            and memory.get(model.owner) == PRESENT
                            and any(root != model.owner and value == PRESENT for root, value in memory.items()),
                            'compiled retained slot emptied without live transfer')
                    memory[model.owner] = frozenset({2})
            if re.search(r'\binvoke\b', line):
                edges = re.fullmatch('to label %' + common.LABEL + ' unwind label %' + common.LABEL
                                     + r'(?:,.*)?', lines[index + 1])
                require(edges, 'compiled worker invoke edges changed')
                schedule(edges[1])
                schedule(edges[2], True)
                break
            if line.startswith(('br ', 'switch ')):
                text = line if line.startswith('br ') else '\n'.join(lines[index:]).split(']', 1)[0]
                edges = re.findall('label %' + common.LABEL, text)
                require(edges, 'compiled worker branch lacks targets')
                condition = re.fullmatch('br i1 (' + VALUE + '), label %' + common.LABEL
                                         + ', label %' + common.LABEL + r'(?:,.*)?', line)
                if condition:
                    known = values.get(condition[1], UNKNOWN)
                    predicate = model.defs.get(condition[1], ('',))[0]
                    relation = re.fullmatch(r'icmp (eq|ne) i8 (' + VALUE + r'), (-?\d+)', predicate)
                    for edge, truth in zip(edges, (True, False)):
                        if known == UNKNOWN or known is truth:
                            branch_values = values.copy()
                            branch_values[condition[1]] = truth
                            if relation:
                                domain = values.get(relation[2], frozenset(range(256)))
                                if domain == UNKNOWN:
                                    domain = frozenset(range(256))
                                require(isinstance(domain, frozenset), 'invalid compiled byte domain')
                                narrowed = frozenset(value for value in domain
                                    if ((value == int(relation[3]) % 256) == (relation[1] == 'eq')) == truth)
                                if not narrowed:
                                    continue
                                branch_values[relation[2]] = narrowed
                            queue.append((edge, 0, label, memory.copy(), branch_values, done, unwinding))
                elif line.startswith('switch i8 '):
                    switch = re.match('switch i8 (' + VALUE + '), label %' + common.LABEL + r' \[', text)
                    require(switch, 'unparsed compiled byte switch')
                    cases = re.findall(r'i8 (-?\d+), label %' + common.LABEL, text)
                    domain = values.get(switch[1], frozenset(range(256)))
                    if domain == UNKNOWN:
                        domain = frozenset(range(256))
                    require(isinstance(domain, frozenset), 'invalid compiled switch domain')
                    choices = [(switch[2], domain - {int(value) % 256 for value, _ in cases})]
                    choices.extend((edge, domain & {int(value) % 256}) for value, edge in cases)
                    for edge, narrowed in choices:
                        if narrowed:
                            branch_values = {**values, switch[1]: frozenset(narrowed)}
                            queue.append((edge, 0, label, memory.copy(), branch_values, done, unwinding))
                else:
                    for edge in edges:
                        schedule(edge)
                break
            if line.startswith(('ret ', 'resume ')):
                require(done == expected, 'compiled worker exits without engine cleanup/consumption')
                exits.add(label)
                break
            if line == 'unreachable':
                require(unwinding and any('panic_in_cleanup' in row or 'panic_cannot_unwind' in row for row in lines),
                        'unexpected compiled worker fatal path')
                break
        else:
            require(False, 'unterminated compiled worker block')
    require(exits and len(updates) == 1, 'vacuous compiled worker cleanup graph')
