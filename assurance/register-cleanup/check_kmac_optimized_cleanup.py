#!/usr/bin/env python3
"""Retained optimized verifier cleanup requests, not whole-call erasure proof."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_kmac_guard_paths as guard

comparison = guard.comparison
require = guard.require
SSA = guard.SSA


def inventory(function, names, defined):
    graph = guard.metadata.model.blocks(function)
    edges, definitions, events = {}, {}, {}
    comparisons, finishes = [], []
    for label, lines in graph.items():
        edges[label] = guard.successors(lines)
        require(all(target in graph for target in edges[label][0]), 'existing optimized successor')
        for index, line in enumerate(lines):
            assignment = re.match('(' + SSA + r') = (.+)', line)
            if assignment:
                require(assignment[1] not in definitions, 'unique optimized SSA definition')
                definitions[assignment[1]] = label, index, assignment[2]
            if not re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                continue
            name, args = guard.call(line)
            role = next((role for role in ('CLEAR', 'GLUE', 'ACCUMULATE', 'PREDICATE') if names[role] == name), None)
            if role is not None:
                symbol = re.search(comparison.SYMBOL, line)
                prefix = line[:symbol.start()]
                expected = {
                    'CLEAR': SSA + r' = (?:tail call|invoke) noundef i8 ',
                    'GLUE': r'(?:invoke|call) fastcc void ',
                    'ACCUMULATE': r'invoke void ',
                    'PREDICATE': SSA + r' = invoke noundef i8 ',
                }[role]
                require(re.fullmatch(expected, prefix), 'reviewed cleanup/comparison call ABI')
                complete = prefix + '@' + name + '(' + ', '.join(args) + ')'
                require(re.fullmatch(re.escape(complete) + r'(?: #\d+)?', line), 'single complete selected call')
                events.setdefault(label, []).append((index, role, args, 'invoke ' in line))
                if role in ('ACCUMULATE', 'PREDICATE'):
                    require(name in defined and 'invoke ' in line, 'bound comparison with explicit successors')
                    comparisons.append((label, role, args))
            if 'core_state' in name and '6finish' in name:
                require(name in defined, 'bound finish definition')
                finishes.append((label, index, args))
    require(Counter(role for _, role, _ in comparisons) == {'ACCUMULATE': 2, 'PREDICATE': 1},
            'complete optimized comparison inventory')
    require(len(finishes) == 1, 'unique finish-result producer')
    def landingpad(label):
        non_phi = [line for line in graph[label] if not re.match(SSA + r' = phi ', line)]
        return bool(non_phi and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', non_phi[0]))
    for label, lines in graph.items():
        if lines[-1].startswith('to label '):
            normal, unwind = edges[label][0]
            require(not landingpad(normal) and landingpad(unwind),
                    'invoke normal and exception edges enter the correct block kinds')

    def origin(value):
        seen, offset = set(), 0
        while value in definitions:
            require(value not in seen, 'acyclic constant-offset provenance')
            seen.add(value)
            gep = re.fullmatch(r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (-?\d+)', definitions[value][2])
            if gep is None:
                break
            value, offset = gep[1], offset + int(gep[2])
        return value, offset

    predicate = next(args for _, role, args in comparisons if role == 'PREDICATE')
    require(len(predicate) == 1, 'borrowed comparison difference ABI')
    owner, offset = origin(comparison.pointer(predicate[0]))
    require(offset == 65 and owner in definitions, 'verdict uses the metadata difference byte')
    start, load_index, load = definitions[owner]
    pointer_load = re.fullmatch(r'load ptr, ptr (' + SSA + r'), align 8', load)
    require(pointer_load is not None, 'metadata pointer loaded from finish-result descriptor')
    slot, slot_offset = origin(pointer_load[1])
    allocation = re.fullmatch(r'alloca \[(24|32) x i8\], align 8', definitions.get(slot, ('', 0, ''))[2])
    require(allocation is not None and (int(allocation[1]), slot_offset) in ((24, 16), (32, 24)),
            'reviewed metadata field in bounded finish-result descriptor')
    finish_label, _, finish_args = finishes[0]
    require(comparison.pointer(finish_args[0]) == slot, 'finish writes the extracted result slot')
    require(not any(index < load_index for index, _, _, _ in events.get(start, [])),
            'metadata extraction precedes selected events in its block')
    require(finish_label != start, 'distinct finish and successful extraction blocks')
    # Structural dominance only; the contents produced by finish are a separate
    # callee-provenance obligation, not assumed proven by this descriptor check.
    pending, visited = ['start'], set()
    while pending:
        label = pending.pop()
        if label in visited or label == finish_label:
            continue
        visited.add(label)
        require(label != start, 'finish dominates metadata extraction')
        pending.extend(edges[label][0])
    pending, visited = ['start'], set()
    while pending:
        label = pending.pop()
        if label in visited or label == start:
            continue
        visited.add(label)
        require(label not in {item[0] for item in comparisons}, 'extraction dominates comparisons')
        pending.extend(edges[label][0])
    return graph, edges, events, comparisons, origin, owner, start


def inspect(function, names, defined):
    graph, edges, events, comparisons, origin, owner, initial = inventory(function, names, defined)
    starts = [initial] + [target for label, _, _ in comparisons for target in edges[label][0]]
    initialized, all_blocks, checked_calls = set(), set(), set()
    for start_index, start in enumerate(starts):
        # progress counts normal completions of the ordered clearing requests;
        # attempted is kept separately because an invoked clearer may unwind.
        todo, visited, exits = [(start, 0, False)], set(), set()
        while todo:
            label, progress, attempted = todo.pop()
            state = label, progress, attempted
            if state in visited:
                continue
            visited.add(state)
            all_blocks.add(label)
            transitions = None
            for index, role, args, invoked in events.get(label, []):
                if role in ('ACCUMULATE', 'PREDICATE'):
                    require(progress == 0 and not attempted, 'no comparison after cleanup starts')
                    continue
                require(progress < 3, 'no repeated metadata cleanup after completion')
                if role == 'CLEAR':
                    require(len(args) == 2, 'clearing pointer/width ABI')
                    base, offset = origin(comparison.pointer(args[0]))
                    width = re.fullmatch(r'i64 noundef (\d+)', args[1])
                    require(width is not None and base == owner and (offset, int(width[1])) == ((64, 1), (0, 64), (65, 1))[progress],
                            'ordered complete regions of the original metadata pointer')
                    completed = progress + 1
                else:
                    require(role == 'GLUE' and len(args) == 1 and progress == 0 and not attempted,
                            'whole guard cleanup starts once')
                    require(origin(comparison.pointer(args[0])) == (owner, 0), 'glue receives original promoted metadata pointer')
                    completed = 3
                checked_calls.add((label, index))
                attempted = True
                if invoked:
                    require(index == len(graph[label]) - 2 and len(edges[label][0]) == 2,
                            'cleanup invoke has explicit terminal edges')
                    normal, unwind = edges[label][0]
                    transitions = [(normal, completed, True), (unwind, progress, True)]
                else:
                    progress = completed
            targets, terminal = edges[label]
            if terminal == 'return':
                require(progress == 3, 'normal verification return needs complete metadata cleanup')
                exits.add(terminal)
            elif terminal == 'resume':
                require(attempted, 'resumed unwind must have attempted metadata cleanup')
                exits.add(terminal)
            elif terminal == 'unreachable':
                require(any(re.fullmatch(r'(?:tail )?call void @[^ (]*16panic_in_cleanup[^ (]*\(\) #\d+', line)
                            for line in graph[label]), 'only identified double-panic abort is excluded')
            todo.extend(transitions if transitions is not None else [(target, progress, attempted) for target in targets])
        require(exits, 'each selected start has a reachable return or resume')
        if start_index == 0:
            initialized = {label for label, _, _ in visited}
    require({label for label, _, _ in comparisons} <= initialized, 'comparison sites reachable from extracted metadata')
    require({label for label, _ in checked_calls} <= initialized, 'cleanup sites reachable from extracted metadata')
    require(len(checked_calls) in (7, 11), 'reviewed inlined/glue cleanup inventory')
    return len(all_blocks), len(checked_calls)


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        functions, names = guard.metadata.select(kmac, core)
        definitions = comparison.definitions(kmac)
        names['GLUE'], functions['GLUE'] = guard.metadata.one(definitions,
            lambda name: 'core_state' in name and 'Guard' in name and ('drop_in_place' in name or 'drop_glue' in name), 'guard glue')
        core_definitions = comparison.definitions(core)
        for role, token in (('ACCUMULATE', '33accumulate_secret_byte_difference'), ('PREDICATE', '25secret_difference_is_zero')):
            names[role], _ = guard.metadata.one(core_definitions, lambda name: token in name, 'bound ' + role)
        yield row, names, set(definitions) | set(core_definitions), comparison.verifiers(kmac, row['mode'] == 'accelerated')


def main(record):
    before = comparison.capture.sources()
    builds = functions = blocks = calls = 0
    for _, names, defined, verifiers in cases(record):
        for function in verifiers:
            count, requests = inspect(function, names, defined)
            blocks += count
            calls += requests
            functions += 1
        builds += 1
    require((builds, functions, blocks, calls) == (8, 24, 1386, 216)
            and before == comparison.capture.sources(), 'complete unchanged optimized matrix')
    print(f'Optimized KMAC cleanup: {functions} verifiers, {blocks} reachable blocks, {calls} cleanup sites and 72 comparison sites across {builds} builds PASS')
    print('Normal returns follow complete metadata clearing requests; resumed unwinds retain an attempted cleanup')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not successful unwinding cleanup, finish-callee contents, comparison-byte provenance, implicit unwinds, termination, machine spills or native-platform qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
