#!/usr/bin/env python3
"""Retained KMAC guard glue and debug cleanup CFG, not whole-verifier proof."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_kmac_metadata_assembly as assembly
import check_kmac_metadata_clear as metadata

comparison = metadata.comparison
require = metadata.require
SSA = r'%[-.$\w]+'
LABEL = metadata.model.shared.LABEL


class GlueModel(metadata.MetadataModel):
    def __init__(self, functions, names, base):
        super().__init__(functions, names, base)
        self.assumptions = 0

    def run(self, name, args, depth=0):
        if name == 'llvm.assume':
            require(args == [1], 'valid nonnull cleanup input assumption')
            self.assumptions += 1
            return None
        return super().run(name, args, depth)


def glue(functions, names, body, compiler, profile, arm):
    metadata.inspect(functions, names, compiler, profile)
    function = functions['GLUE']
    expected_parameter = '%_1' if profile == 'debug' else '%_1.0.val'
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and symbol[1] == names['GLUE']
            and header.startswith('define ' + ('void ' if profile == 'debug' else 'internal fastcc void ')),
            'exact glue definition identity/ABI')
    require(metadata.model.parameters(function) == [expected_parameter], 'correct glue descriptor versus promoted-pointer input')
    selected = {}
    for role in ('WIPE', 'DROP', 'GUARD', 'GLUE'):
        graph = metadata.model.blocks(functions[role])
        require(set(graph) == {'start'}, 'linear cleanup glue closure')
        selected[names[role]] = (metadata.model.parameters(functions[role]),
                               {'start': [line.replace('tail call ', 'call ', 1) for line in graph['start']]})
    if profile == 'release':
        require(selected[names['GLUE']][1]['start'][:2] == [
            '%0 = icmp ne ptr %_1.0.val, null', 'call void @llvm.assume(i1 %0)'],
            'explicit promoted-pointer nonnull assumption')
    for base in (0, 17):
        machine = GlueModel(selected, names, base)
        machine.allocate('metadata', base + 66 + 9, payload=True)
        owner = metadata.model.Pointer('metadata', base)
        guard = machine.allocate('guard', 8)
        machine.store(guard, 8, owner)
        require(machine.run(names['GLUE'], [guard if profile == 'debug' else owner]) is None, 'void glue return')
        require(machine.calls == [(64, 1), (0, 64), (65, 1)], 'glue requests original complete metadata regions')
        require(machine.load(guard, 8) == owner and machine.assumptions == int(profile == 'release'),
                'preserved guard and reviewed assumption count')
    names_asm = {role: name.strip('"') for role, name in names.items()}
    contract = assembly.reviewed.contracts(arm, profile, compiler)['DROP' if profile == 'debug' else 'WIPE']
    if profile == 'debug':
        contract = [line.replace('WIPE', 'GUARD') for line in contract]
    lines = assembly.normalized(body, names_asm['GLUE'], names_asm)
    require(lines == contract, 'exact glue normal-return assembly forwarding')
    return sum(not line.endswith(':') for line in lines)


def call(line):
    symbol = re.search(comparison.SYMBOL, line)
    require(symbol is not None, 'direct named verification call')
    return symbol[1], comparison.arguments(line, symbol.end())


def successors(lines):
    """Read explicit LLVM successors; no branch feasibility assumptions."""
    joined = '\n'.join(lines)
    terminators = re.findall(r'(?m)^(?:' + SSA + r' = )?(?:invoke|br|switch|ret|resume|unreachable)\b', joined)
    require(len(terminators) == 1, 'single explicit block terminator')
    last = lines[-1]
    if last.startswith(('ret ', 'resume ')):
        return (), 'return' if last.startswith('ret ') else 'resume'
    if last == 'unreachable':
        return (), 'unreachable'
    if last.startswith('to label '):
        require(len(lines) >= 2 and re.match(r'(?:' + SSA + r' = )?invoke ', lines[-2]), 'terminal invoke edges')
        return metadata.model.shared.edges(last), None
    unconditional = re.fullmatch(r'br label %(' + LABEL + ')', last)
    if unconditional:
        return (unconditional[1],), None
    conditional = re.fullmatch(r'br i1 (?:' + SSA + r'|true|false), label %(' + LABEL + r'), label %(' + LABEL + ')', last)
    if conditional:
        return conditional.groups(), None
    switches = [i for i, line in enumerate(lines) if line.startswith('switch ')]
    require(len(switches) == 1 and last == ']', 'known explicit CFG terminator')
    index = switches[0]
    head = re.fullmatch(r'switch i\d+ ' + SSA + r', label %(' + LABEL + r') \[', lines[index])
    require(head is not None, 'bounded switch header')
    targets = [head[1]]
    for line in lines[index + 1:-1]:
        case = re.fullmatch(r'i\d+ -?\d+, label %(' + LABEL + ')', line)
        require(case is not None, 'explicit switch case')
        targets.append(case[1])
    return tuple(targets), None


def debug_paths(function, glue_name, defined_callees):
    graph = metadata.model.blocks(function)
    require(graph.get('start', []).count('%cleanup = alloca [8 x i8], align 8') == 1,
            'unique local cleanup guard descriptor')
    initializers, drops, operations, edges = [], {}, [], {}
    for label, lines in graph.items():
        edges[label] = successors(lines)
        for target in edges[label][0]:
            require(target in graph, 'existing CFG successor')
        for index, line in enumerate(lines):
            if re.fullmatch(r'store ptr ' + SSA + r', ptr %cleanup, align 8', line):
                initializers.append(label)
            if not re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
                continue
            name, args = call(line)
            if name == glue_name:
                require(re.fullmatch(r'invoke void @' + re.escape(name) + r'\(ptr align 8 %cleanup\)(?: #\d+)?', line),
                        'guard invocation uses the initialized descriptor')
                require(label not in drops, 'one guard invocation per block')
                drops[label] = index
            kind = next((token for token in ('33accumulate_secret_byte_difference', '25secret_difference_is_zero',
                                             '12final_secret', '6secret') if token in name), None)
            if kind:
                require(name in defined_callees, 'selected operation has a bound retained definition')
                require('invoke ' in line and index == len(lines) - 2, 'operation has explicit normal/unwind edges')
                operations.append((label, kind))
    require(len(initializers) == 1 and len(drops) == 3, 'one initialized guard and three actual cleanup sites')
    require(Counter(kind for _, kind in operations) == {
        '33accumulate_secret_byte_difference': 2, '25secret_difference_is_zero': 1,
        '12final_secret': 1, '6secret': 1}, 'five verification-operation sites')
    # Conservatively require initialization to dominate all selected operations
    # and guard invocations. Do not use assumed branch feasibility to prove it.
    pending, before_initialization = ['start'], set()
    guarded = {label for label, _ in operations} | set(drops)
    while pending:
        label = pending.pop()
        if label in before_initialization or label == initializers[0]:
            continue
        before_initialization.add(label)
        require(label not in guarded, 'guard initialization dominates selected operations and cleanup')
        pending.extend(edges[label][0])
    starts = [initializers[0]] + [target for label, _ in operations for target in edges[label][0]]
    all_visited = set()
    initialized_visited = set()
    for index, start in enumerate(starts):
        todo, visited, exits = [(start, False)], set(), set()
        while todo:
            label, invoked = todo.pop()
            if (label, invoked) in visited:
                continue
            visited.add((label, invoked))
            all_visited.add(label)
            invoked = invoked or label in drops
            targets, terminal = edges[label]
            if terminal in ('return', 'resume'):
                require(invoked, 'verification exit bypasses cleanup invocation: ' + label)
                exits.add(terminal)
            if terminal == 'unreachable':
                require(any(re.fullmatch(r'call void @[^ (]*16panic_in_cleanup[^ (]*\(\) #\d+', line)
                            for line in graph[label]), 'no unexplained unreachable after guard initialization')
            todo.extend((target, invoked) for target in targets)
        require(exits, 'nonvacuous reachable return/resume from each selected edge')
        if index == 0:
            initialized_visited = {label for label, _ in visited}
    require(guarded <= initialized_visited,
            'operations and cleanup reachable in modeled initialized CFG')
    return len(all_visited)


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        functions, names = metadata.select(kmac, core)
        names['GLUE'], functions['GLUE'] = metadata.one(comparison.definitions(kmac),
            lambda name: 'core_state' in name and 'Guard' in name and ('drop_in_place' in name or 'drop_glue' in name),
            'instantiated guard drop glue')
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_mac_kmac-') and path.endswith('.s')]
        require(len(paths) == 1, 'unique validated KMAC assembly')
        body = assembly.assembly.select(paths[0].read_text(), names['GLUE'].strip('"'))
        verifiers = comparison.verifiers(kmac, row['mode'] == 'accelerated') if row['profile'] == 'debug' else []
        yield row, functions, names, body, verifiers, set(comparison.definitions(kmac)) | set(comparison.definitions(core))


def main(record):
    before = comparison.capture.sources()
    builds = instructions = verifiers_checked = blocks = 0
    for row, functions, names, body, verifiers, defined_callees in cases(record):
        instructions += glue(functions, names, body, row['compiler'].splitlines()[0].split()[1],
                             row['profile'], row['target'].startswith('aarch64-'))
        for verifier in verifiers:
            blocks += debug_paths(verifier, names['GLUE'], defined_callees)
            verifiers_checked += 1
        builds += 1
    require((builds, verifiers_checked) == (16, 24) and before == comparison.capture.sources(), 'complete unchanged guard matrix')
    print(f'KMAC guard glue: {builds} LLVM/assembly definitions; {instructions} machine instructions; 32 modeled calls PASS')
    print(f'Debug verifier CFG: {verifiers_checked} bodies, {blocks} reachable blocks, 120 operation sites retain cleanup invocation on explicit return/resume paths PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Invocation is not successful cleanup; termination, descriptor provenance, implicit unwinds, abort, optimized caller CFG and whole-call residue remain outside scope')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
