"""Byte-proven wrapper moves into an inlined consuming Engine; no IR rewriting.

The prefix has no throwing owner call. Only a complete, ordered Engine in a
private allocation can establish the continuation's two logical hash owners.
Other wrapper copies/scalars cannot be referenced after that handoff.
"""
import re

import hmac_constructor_state as provenance
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as cleanup
import hmac_execution_final as final

require, VALUE = common.require, syntax.VALUE


def check(body, identity, operation, definitions, aliases, compiler, panic, route, present):
    require(operation in ('secret_bits', 'verify_bits') and compiler in ('1.90.0', '1.99.1')
            and panic in ('abort', 'unwind') and route in range(16) and type(present) is bool,
            'unreviewed hosted consuming prefix')
    shape = cleanup.layout(identity, 'static')
    allocs = {name: int(size) for name, size in re.findall(
        '(' + VALUE + r') = alloca \[(\d+) x i8\],', body)}
    ptrs = syntax.pointers(body, (*allocs, '%self', '%_0', '%output.0', '%candidate.0', '%input'))
    graph = common.blocks(body)
    initial = provenance.State()
    if present:
        initial.birth(('%self', 0), shape.engine, 0)
    else:
        initial.constants['%self', shape.discriminator, 1] = shape.empty
    metadata, _ = cleanup.initial(identity, route, present, compiler, 'static')
    queue = [(next(iter(graph)), None, initial, False, frozenset())]
    visited, cuts, exits = set(), set(), 0

    def address(name):
        return ptrs.get(name, (name, 0))

    def rooted(state, name):
        return any(row[0] == address(name)[0] for row in state.memory)

    def bounded(name, size):
        root, offset = address(name)
        require(root in allocs and 0 <= offset and offset + size <= allocs[root],
                'hosted wrapper move outside private allocation')

    def number(value):
        if isinstance(value, tuple):
            token, offset, size = value
            require(token == 0 and size == 1 and offset == shape.discriminator,
                    'hosted wrapper compares non-discriminator owner bytes')
            return cleanup.metadata(metadata, offset, 'i8')
        return value

    while queue:
        label, predecessor, state, cleared, trail = queue.pop()
        require(label not in trail and label in graph and len(visited) < 10000,
                'cyclic/unknown hosted consuming prefix')
        trail |= {label}
        key = label, predecessor, state.key(), cleared
        if key in visited:
            continue
        visited.add(key)
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            definition = re.match('(' + VALUE + ') =', line)
            derived = re.match('(' + VALUE + r') = getelementptr.*?, ptr (' + VALUE + ')', line)
            load = re.match('(' + VALUE + r') = load (?:i(\d+)|ptr), ptr (' + VALUE + '),', line)
            if derived and (rooted(state, derived[2]) or address(derived[2])[0] == '%self'):
                require(derived[1] in ptrs, 'unresolved hosted wrapper owner pointer')
            if load and (rooted(state, load[3]) or address(load[3])[0] == '%self'):
                require(load[2], 'hosted wrapper owner pointer load')
                if not present:
                    require(load[2] == '8' and address(load[3]) == ('%self', shape.discriminator),
                            'empty hosted wrapper reads absent payload')
            provenance.evaluate(line, state, address, predecessor)
            compare = re.match('(' + VALUE + r') = icmp(?: samesign)? (eq|ne) i\d+ ('
                               + VALUE + r'), (-?\d+)', line)
            if compare:
                value = number(state.values.get(compare[3]))
                if value is not None:
                    state.assign(compare[1], int((value == int(compare[4])) == (compare[2] == 'eq')))
            call = syntax.call(line)
            if call:
                symbol, args = call
                require('invoke ' not in line, 'throwing call before hosted owner transfer')
                if symbol == 'llvm.memcpy.p0.p0.i64':
                    size = re.fullmatch(r'i64 (\d+)', args[2])
                    require(size, 'variable hosted wrapper copy')
                    dest, source, size = syntax.operand(args[0]), syntax.operand(args[1]), int(size[1])
                    bounded(dest, size)
                    require(present and rooted(state, source), 'hosted wrapper copy lacks live source')
                    state.transfer(address(dest), address(source), size)
                elif symbol.startswith('llvm.lifetime.'):
                    root, offset = address(syntax.operand(args[-1]))
                    require(root in allocs and offset == 0 and symbol in (
                        'llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'), 'unknown hosted wrapper lifetime')
                    require(not any(row[0] == root for row in state.memory),
                            'hosted wrapper lifetime discards/restarts owner')
                elif symbol == 'llvm.experimental.noalias.scope.decl':
                    pass
                else:
                    require(not present and operation == 'secret_bits' and syntax.auxiliary(symbol)
                            and '18clear_owned_region' in symbol and len(args) == 2
                            and syntax.operand(args[0]) == '%output.0'
                            and re.fullmatch(r'i64 (?:noundef )?%output\.1', args[1]),
                            'unreviewed hosted wrapper callee before handoff')
                    cleared = True
            elif line.startswith('store '):
                store = re.match(r'store (?:i(\d+)|ptr) (.*?), ptr (' + VALUE + '),', line)
                require(store, 'unsupported hosted wrapper store')
                size = (int(store[1]) + 7) // 8 if store[1] else 8
                value = state.value(store[2])
                require(address(store[3])[0] != '%self', 'hosted wrapper modifies its borrowed source')
                require(store[1] or not (rooted(state, store[2]) or address(store[2])[0] == '%self'),
                        'hosted wrapper pointer escape')
                if isinstance(value, tuple):
                    bounded(store[3], size)
                state.store(address(store[3]), size, value)
            elif not (derived or load):
                references = re.findall(VALUE, line)[1:] if definition else re.findall(VALUE, line)
                require(not any(rooted(state, name) or address(name)[0] == '%self' for name in references),
                        'unsupported hosted wrapper owner operation')
                require(compare or not any(isinstance(state.values.get(name), tuple) for name in references),
                        'hosted wrapper scalar owner escape')
            # The first fully initialized private Engine is the handoff. Do
            # not erase/massage the prefix or search for a favourable helper.
            roots = {row[0] for row in state.memory if row[0] != '%self'}
            complete = []
            for root in roots:
                if sum(row[2] for row in state.memory if row[0] == root) >= shape.engine:
                    require(allocs.get(root) == shape.engine and state.complete((root, 0), shape.engine) == 0,
                            'hosted wrapper Engine byte ordering/geometry changed')
                    complete.append(root)
            if complete:
                require(present and len(complete) == 1, 'ambiguous/empty hosted owner handoff')
                root = complete[0]
                excluded = tuple(sorted({row[0] for row in state.memory} - {root}))
                fragments = tuple(sorted(name for name, value in state.values.items() if isinstance(value, tuple)))
                facts = tuple(sorted((name, value) for name, value in state.values.items() if type(value) is int))
                continuation = ((label, index + 1), facts, excluded, fragments)
                final._check(body, identity, definitions, aliases, panic,
                    ((root, 0, 0), (root, shape.stride, 1)), 0, route, set(), 'static', continuation)
                cuts.add((label, index + 1, root))
                terminal = True
                break
            branch = re.fullmatch(r'br i1 (' + VALUE + '), label %' + common.LABEL
                                  + ', label %' + common.LABEL + r'(?:,.*)?', line)
            jump = re.fullmatch('br label %' + common.LABEL, line)
            if branch or jump:
                if jump:
                    child = jump[1]
                else:
                    condition = state.value(branch[1])
                    require(condition in (0, 1), 'unknown hosted wrapper admission condition')
                    child = branch[2 if condition else 3]
                queue.append((child, label, state.clone(), cleared, trail))
                terminal = True
                break
            if line.startswith('ret '):
                require(not present and not state.born and (operation == 'verify_bits' or cleared),
                        'hosted wrapper exits without handoff/secret rejection clear')
                exits += 1
                terminal = True
                break
        require(terminal, 'unterminated hosted wrapper prefix')
    require((bool(cuts) and not exits) if present else (exits and not cuts),
            'vacuous hosted wrapper handoff/rejection')
    return cuts
