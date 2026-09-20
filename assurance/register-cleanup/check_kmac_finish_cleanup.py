#!/usr/bin/env python3
"""Retained KMAC finish error/unwind metadata paths, not whole-call erasure."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_early_cleanup as early

comparison = early.comparison
guard = early.guard
require = early.require
SSA = early.SSA


def graph_info(function):
    graph = guard.metadata.model.blocks(function)
    edges = {label: guard.successors(lines) for label, lines in graph.items()}
    definitions = {}
    for label, lines in graph.items():
        require(all(target in graph for target in edges[label][0]), 'existing finish successor')
        for index, line in enumerate(lines):
            match = re.match('(' + SSA + r') = (.+)', line)
            if match:
                require(match[1] not in definitions, 'unique finish SSA')
                definitions[match[1]] = label, index, match[2]
        if lines[-1].startswith('to label '):
            kinds = []
            for target in edges[label][0]:
                non_phi = [line for line in graph[target] if not re.match(SSA + r' = phi ', line)]
                kinds.append(bool(non_phi and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', non_phi[0])))
            require(kinds == [False, True], 'normal/unwind edges enter the correct block kinds')

    def origin(value):
        seen, offset = set(), 0
        while value in definitions:
            require(value not in seen, 'acyclic finish pointer provenance')
            seen.add(value)
            match = re.fullmatch(r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (-?\d+)', definitions[value][2])
            if match is None:
                break
            value, offset = match[1], offset + int(match[2])
        return value, offset
    return graph, edges, origin


def follow(function, names, state_callees, core, starts):
    graph, edges, origin = graph_info(function)
    all_blocks, calls, states = set(), set(), set()
    for start in starts:
        todo, visited, exits = [(start, 0, False, ())], set(), set()
        while todo:
            label, progress, attempted, ancestors = todo.pop()
            require(label not in ancestors, 'acyclic selected cleanup path')
            state = label, progress, attempted
            if state in visited:
                continue
            visited.add(state)
            all_blocks.add(label)
            transitions = None
            lines = graph[label]
            for index, line in enumerate(lines):
                if not re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                    # Stores on these paths only write the error descriptor.
                    store = re.fullmatch(r'store (?:i8 (?:' + SSA + r'|\d+)|ptr null), ptr (' + SSA + r'), align 8', line)
                    if line.startswith('store '):
                        require(store is not None and origin(store[1]) in (('%_0', 0), ('%_0', 8)),
                                'only bounded error-result stores in selected cleanup slice')
                    else:
                        require(re.match(r'(?:(?:' + SSA + r' = )?(?:getelementptr|load|icmp|phi|ptrtoint|trunc|landingpad)\b'
                                         r'|(?:br|ret|resume|unreachable|cleanup|filter|to label)\b)', line),
                                'reviewed descriptor/control instruction in cleanup slice: ' + line)
                    continue
                name, args = guard.call(line)
                role = next((role for role in ('CLEAR', 'GLUE', 'CORE') if names.get(role) == name), None)
                if role is not None:
                    require(progress < 3 and len(args) == (2 if role == 'CLEAR' else 1), 'pending complete cleanup ABI')
                    symbol = re.search(comparison.SYMBOL, line)
                    prefix = line[:symbol.start()]
                    expected = SSA + r' = (?:tail call|call|invoke) noundef i8 ' if role == 'CLEAR' else r'invoke fastcc void '
                    require(re.fullmatch(expected, prefix), 'bound cleanup call ABI')
                    base, offset = origin(comparison.pointer(args[0]))
                    if role == 'CORE':
                        require((base, offset) == (core, 0) and progress == 0 and not attempted,
                                'whole original Core cleanup before any partial metadata cleanup')
                        completed = 3
                    else:
                        require(base + f' = load ptr, ptr {core}, align 8' in lines[:index],
                                'original Core metadata loaded before cleanup')
                        if role == 'CLEAR':
                            require((offset, args[1]) == ((64, 'i64 noundef 1'), (0, 'i64 noundef 64'), (65, 'i64 noundef 1'))[progress],
                                    'complete ordered original metadata regions')
                            completed = progress + 1
                        else:
                            require(offset == progress == 0 and not attempted, 'original guard invoked once')
                            completed = 3
                    calls.add((label, index))
                    attempted = True
                    if 'invoke ' in prefix:
                        require(index == len(lines) - 2, 'terminal metadata cleanup invoke')
                        normal, unwind = edges[label][0]
                        transitions = [(normal, completed, True), (unwind, progress, True)]
                    else:
                        progress = completed
                elif name in state_callees:
                    require(line.startswith('invoke void @') and len(args) == 1 and not attempted,
                            'bound state cleanup before metadata cleanup')
                    pointer = comparison.pointer(args[0])
                    if 'HardenedFips202Owner' in name:
                        match = next((re.fullmatch(re.escape(pointer) + r' = load ptr, ptr (' + SSA + r'), align 8', prior)
                                      for prior in lines[:index] if prior.startswith(pointer + ' = ')), None)
                        require(match is not None and origin(match[1]) == (core, 8), 'original portable state field')
                    else:
                        require(origin(pointer) == (core, 8), 'original accelerated state field')
                    states.add((label, index))
                elif name in (names.get('FRAMING'), names.get('PACKER')):
                    require(line.startswith('invoke fastcc void @') and len(args) == 1
                            and comparison.pointer(args[0]) == '%storage.i', 'separate framing destructor')
                elif name == 'llvm.experimental.noalias.scope.decl':
                    require(re.fullmatch(r'(?:tail )?call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', line), 'noalias metadata only')
                else:
                    require(re.fullmatch(r'(?:tail )?call void @[^ (]*16panic_in_cleanup[^ (]*\(\) #\d+', line)
                            and edges[label][1] == 'unreachable', 'only identified cleanup double-panic abort excluded: ' + line)
            targets, terminal = edges[label]
            if terminal == 'return':
                require(progress == 3, 'finish error return requires complete metadata clearing requests')
                exits.add('return')
            elif terminal == 'resume':
                require(attempted, 'finish resumed unwind requires metadata cleanup attempt')
                exits.add('resume')
            elif terminal == 'unreachable':
                require(any('16panic_in_cleanup' in line for line in lines), 'only identified double-panic abort excluded')
            next_states = transitions if transitions is not None else [(target, progress, attempted) for target in targets]
            todo.extend((target, count, tried, ancestors + (label,)) for target, count, tried in next_states)
        direct_abort = any(re.fullmatch(r'(?:tail )?call void @[^ (]*16panic_in_cleanup[^ (]*\(\) #\d+', line)
                           for line in graph[start]) and edges[start][1] == 'unreachable'
        require(exits or direct_abort, 'each non-abort cleanup start reaches a return or resumed unwind')
    return len(all_blocks), len(calls), len(states)


def errors(function):
    graph, edges, origin = graph_info(function)
    size = re.search(r'dereferenceable\((24|32)\) %_0', function.splitlines()[0])
    require(size is not None, 'bounded finish result descriptor')
    starts = []
    for label, lines in graph.items():
        for line in lines:
            match = re.fullmatch(r'store (i8 2|ptr null), ptr (' + SSA + r'), align 8', line)
            if match and ((size[1] == '24' and match[1] == 'i8 2' and origin(match[2]) == ('%_0', 8)) or
                          (size[1] == '32' and match[1] == 'ptr null' and origin(match[2]) == ('%_0', 0))):
                starts.append(label)
    require(len(starts) == len(set(starts)) == 3, 'three explicit error-result paths')
    unwinds = [edges[label][0][1] for label, lines in graph.items() if lines[-1].startswith('to label ')]
    pending, reachable = ['start'], set()
    while pending:
        label = pending.pop()
        if label in reachable:
            continue
        reachable.add(label)
        pending.extend(edges[label][0])
    require(set(starts + unwinds) <= reachable, 'selected errors and unwind roots reachable from finish entry')
    return starts, unwinds


def inspect(function, core_function, names, state_callees):
    require(core_function.splitlines()[0].startswith('define internal fastcc void @' + names['CORE'] + '(')
            and guard.metadata.model.parameters(core_function) == ['%_1'], 'actual matching Core destructor definition/ABI')
    glue_counts = follow(core_function, names, state_callees, '%_1', ['start'])
    require(glue_counts == (6, 4, 1), 'complete Core destructor metadata/unwind inventory')
    starts, unwinds = errors(function)
    counts = follow(function, names, state_callees, '%self', starts + unwinds)
    require(counts[1:] == (5, 1), 'complete finish metadata and state cleanup inventory')
    return counts[0], len(unwinds), glue_counts[0]


def cases(record):
    for row, names, defined, state_callees, verifiers in early.cases(record):
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_mac_kmac-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated KMAC artifact')
        definitions = comparison.definitions(paths[0].read_text())
        selected = set()
        for verifier in verifiers:
            graph = guard.metadata.model.blocks(verifier)
            finish_names = [guard.call(line)[0] for lines in graph.values() for line in lines
                            if line.startswith('call fastcc void @') and 'core_state' in line and '6finish' in line]
            require(len(finish_names) == 1 and finish_names[0] in definitions, 'actual verifier finish callee')
            selected.add(finish_names[0])
        require(len(selected) == len(verifiers), 'all distinct instantiated finish callees')
        for name in sorted(selected):
            function = definitions[name]
            callees = {guard.call(line)[0] for lines in guard.metadata.model.blocks(function).values() for line in lines
                       if line.startswith('invoke fastcc void @')}
            bound = dict(names)
            for role, tokens in (('CORE', ('core_state', 'Core')), ('FRAMING', ('packer', 'Framing'))):
                matches = [callee for callee in callees if all(token in callee for token in tokens)]
                require(len(matches) == 1 and matches[0] in definitions, 'bound ' + role + ' definition')
                bound[role] = matches[0]
            packers = [callee for callee in callees if 'packer' in callee and 'SecretPacker' in callee]
            require(len(packers) <= 1 and all(callee in definitions for callee in packers), 'bound optional packer destructor')
            if packers:
                bound['PACKER'] = packers[0]
            yield row, function, definitions[bound['CORE']], bound, state_callees


def main(record):
    before = comparison.capture.sources()
    functions = blocks = unwinds = glue_blocks = 0
    for _, function, core_function, names, state_callees in cases(record):
        count, exceptional, glue = inspect(function, core_function, names, state_callees)
        functions += 1
        blocks += count
        unwinds += exceptional
        glue_blocks += glue
    require((functions, blocks, unwinds, glue_blocks) == (24, 480, 576, 144)
            and before == comparison.capture.sources(), 'complete unchanged finish matrix')
    print(f'KMAC finish cleanup: {functions} finish/Core pairs, 72 error roots, {unwinds} invoke unwind roots, {blocks} finish cleanup blocks and {glue_blocks} Core blocks PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Scoped error-result and explicit unwind paths only; not success transfer, error classification, state/framing callee internals, implicit unwinds, termination, spills or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
