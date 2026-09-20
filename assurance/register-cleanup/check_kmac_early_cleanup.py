#!/usr/bin/env python3
"""Retained pre-finish KMAC metadata cleanup; not a callee or erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_optimized_cleanup as optimized

comparison = optimized.comparison
guard = optimized.guard
require = optimized.require
SSA = optimized.SSA


def prelude(function, names, defined):
    graph, edges, events, _, origin, _, _ = optimized.inventory(function, names, defined)
    finishes = [(label, index, guard.call(line)[1])
                for label, lines in graph.items() for index, line in enumerate(lines)
                if re.match(r'call fastcc void @', line) and 'core_state' in line and '6finish' in line]
    require(len(finishes) == 1, 'unique direct finish handoff')
    finish, index, args = finishes[0]
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    parameters = comparison.arguments(header, symbol.end())
    self_arg = next((arg for arg in parameters if arg.endswith(' %self')), '')
    size = re.search(r'dereferenceable\((24|32)\)', self_arg)
    require(size is not None, 'bounded input Core descriptor')
    size = int(size[1])
    source = comparison.pointer(args[1])
    require(any(line == source + f' = alloca [{size} x i8], align 8' for line in graph['start']),
            'finish receives a distinct bounded local Core descriptor')
    copies = []
    for line in graph[finish][:index]:
        if '@llvm.memcpy.p0.p0.i64(' in line:
            name, copy_args = guard.call(line)
            require(name == 'llvm.memcpy.p0.p0.i64' and line.startswith('call void @'), 'direct descriptor copy')
            require(len(copy_args) == 4 and comparison.pointer(copy_args[0]) == source
                    and comparison.pointer(copy_args[1]) == '%self'
                    and copy_args[2:] == [f'i64 {size}', 'i1 false'],
                    'complete original Core descriptor passed to finish')
            copies.append(line)
        else:
            require(re.fullmatch(r'call void @llvm.lifetime.start.p0\((?:i64 (?:24|32), )?ptr nonnull '
                                 + SSA + r'\)', line), 'only lifetime markers before descriptor handoff')
    require(len(copies) == 1, 'exactly one complete descriptor handoff')
    require(not events.get(finish), 'handoff precedes metadata cleanup/comparison')
    return graph, edges, events, origin, finish


def inspect(function, names, defined, state_callees):
    graph, edges, events, origin, finish = prelude(function, names, defined)
    todo, visited, exits, calls, state_calls = [('start', 0, False, ())], set(), set(), set(), set()
    while todo:
        label, progress, attempted, ancestors = todo.pop()
        require(label not in ancestors, 'acyclic pre-finish path, not vacuous looping')
        state = label, progress, attempted
        if state in visited:
            continue
        visited.add(state)
        if label == finish:
            require(progress == 0 and not attempted, 'finish receives ownership before metadata cleanup')
            exits.add('handoff')
            continue
        lines = graph[label]
        transitions = None
        selected = {index: (role, args, invoked) for index, role, args, invoked in events.get(label, [])}
        for index, line in enumerate(lines):
            if index in selected:
                role, args, invoked = selected[index]
                require(role in ('CLEAR', 'GLUE') and progress < 3, 'only pending early metadata cleanup')
                require(len(args) == (2 if role == 'CLEAR' else 1), 'complete early cleanup ABI')
                base, offset = origin(comparison.pointer(args[0]))
                # Both normal and exceptional cleanup load the original guard
                # field from Core, in their own block, before using it.
                require(base + ' = load ptr, ptr %self, align 8' in lines[:index],
                        'cleanup uses original Core metadata field, loaded before the request')
                if role == 'CLEAR':
                    require(len(args) == 2 and (offset, args[1]) ==
                            ((64, 'i64 noundef 1'), (0, 'i64 noundef 64'), (65, 'i64 noundef 1'))[progress],
                            'early rejection clears the exact ordered original metadata regions')
                    completed = progress + 1
                else:
                    require(len(args) == 1 and offset == 0 and progress == 0 and not attempted,
                            'early unwind invokes the original complete metadata guard once')
                    completed = 3
                calls.add((label, index))
                attempted = True
                if invoked:
                    require(index == len(lines) - 2 and len(edges[label][0]) == 2, 'terminal cleanup invoke')
                    normal, unwind = edges[label][0]
                    transitions = [(normal, completed, True), (unwind, progress, True)]
                else:
                    progress = completed
                continue
            if re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                name, args = guard.call(line)
                if name in state_callees:
                    require(line.startswith('invoke void @') and len(args) == 1 and not attempted,
                            'bound state destructor before metadata cleanup')
                    pointer = comparison.pointer(args[0])
                    if 'HardenedFips202Owner' in name:
                        load = next((re.fullmatch(re.escape(pointer) + r' = load ptr, ptr (' + SSA + r'), align 8', prior)
                                     for prior in lines[:index] if prior.startswith(pointer + ' = ')), None)
                        require(load is not None and origin(load[1]) == ('%self', 8), 'original borrowed state pointer')
                    else:
                        require(origin(pointer) == ('%self', 8), 'original accelerated state descriptor')
                    state_calls.add((label, index))
                elif name == 'llvm.experimental.noalias.scope.decl':
                    require(re.fullmatch(r'tail call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', line),
                            'metadata-only noalias declaration')
                elif '16panic_in_cleanup' in name:
                    require(re.fullmatch(r'tail call void @[^ (]*16panic_in_cleanup[^ (]*\(\) #\d+', line)
                            and edges[label][1] == 'unreachable', 'identified double-panic abort only')
                else:
                    raise ValueError('unreviewed pre-finish callee: ' + name)
                continue
            # No stores, memory intrinsics, indirect calls or payload operations
            # are allowed in this small descriptor/control-flow slice.
            require(re.match(r'(?:(?:' + SSA + r' = )?(?:alloca|load|getelementptr|icmp|select|zext|trunc|phi|insertvalue|landingpad)\b'
                             r'|(?:br|ret|resume|unreachable|cleanup|filter|to label)\b)', line),
                    'reviewed read-only pre-finish descriptor/control instruction: ' + line)
        targets, terminal = edges[label]
        if terminal == 'return':
            require(progress == 3, 'early normal return follows complete metadata clearing requests')
            exits.add('return')
        elif terminal == 'resume':
            require(attempted, 'early resumed unwind has attempted metadata cleanup')
            exits.add('resume')
        elif terminal == 'unreachable':
            require(attempted and any('16panic_in_cleanup' in line for line in lines),
                    'only identified cleanup double-panic abort excluded')
        next_states = transitions if transitions is not None else [(target, progress, attempted) for target in targets]
        todo.extend((target, count, tried, ancestors + (label,)) for target, count, tried in next_states)
    require(exits == {'handoff', 'return', 'resume'} and len(calls) == 4 and len(state_calls) == 1,
            'complete reachable early rejection, cleanup, unwind and ownership handoff')
    return len({label for label, _, _ in visited}), len(calls)


def state_symbols(text):
    functions = comparison.definitions(text)
    def wipe(name):
        return 'HardenedFips202Owner' in name and '4wipe' in name
    def drop(name, owner):
        return all(token in name for token in ('hardened', 'accelerated', 'in_place', 'xof', 'core', owner, '4drop'))
    selected = {name for name in functions if wipe(name) or drop(name, 'Borrowed')}
    # LLVM merges equal monomorphizations. Accept only an exact void(ptr)
    # alias to an already selected definition, never an unbound declaration.
    symbol = r'("[^"\n]+"|[^\s,]+)'
    for alias, target in re.findall(r'^@' + symbol + r' = unnamed_addr alias void \(ptr\), ptr @' + symbol + r'$', text, re.M):
        if wipe(alias) or drop(alias, 'Borrowed'):
            require(alias not in functions and alias not in selected and target in functions
                    and (wipe(alias) and wipe(target) or drop(alias, 'Borrowed') and drop(target, 'Scope')),
                    'unique state wipe alias bound to an existing definition')
            selected.add(alias)
    require(selected, 'bound state destruction definitions')
    return selected


def cases(record):
    for row, names, defined, verifiers in optimized.cases(record):
        paths = [record.parent / name for name in row['artifacts']
                 if Path(name).name.startswith('brynja_hash_sha3-') and name.endswith('.ll')]
        require(len(paths) == 1, 'unique validated SHA-3 LLVM artifact')
        state_callees = state_symbols(paths[0].read_text())
        yield row, names, defined, state_callees, verifiers


def main(record):
    before = comparison.capture.sources()
    builds = functions = blocks = calls = 0
    for _, names, defined, state_callees, verifiers in cases(record):
        for function in verifiers:
            count, requests = inspect(function, names, defined, state_callees)
            functions += 1
            blocks += count
            calls += requests
        builds += 1
    require((builds, functions, blocks, calls) == (8, 24, 216, 96)
            and before == comparison.capture.sources(), 'complete unchanged early-cleanup matrix')
    print(f'Early KMAC cleanup: {functions} verifiers, {blocks} blocks, {calls} cleanup sites across {builds} builds PASS')
    print('Normal early returns follow complete metadata clearing requests; resumed unwinds retain an attempted cleanup')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not state/finish-callee contents, successful unwinding cleanup, implicit unwinds, machine spills or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
