#!/usr/bin/env python3
"""Inspect retained verification comparison ABIs; no release or whole-call proof."""
import argparse
import itertools
import json
from pathlib import Path
import re

import check_kmac_verify_callers as capture
import check_recorded_boundaries as recorded
import check_secret_difference as difference
import check_secret_predicate as predicate

require = recorded.handoffs.require
SYMBOL = r'@("[^"\n]+"|[^\s(]+)\('
ACCUMULATE = 'brynja_core13secret_memory33accumulate_secret_byte_difference'
PREDICATE = 'brynja_core13secret_memory25secret_difference_is_zero'
PRIVATE = 'brynja_core24secret_memory_difference'


def arguments(text, start):
    """Split LLVM call/header arguments without splitting attribute parentheses."""
    depth, begin, result = 0, start, []
    for index in range(start, len(text)):
        value = text[index]
        if value == '(':
            depth += 1
        elif value == ')':
            if depth == 0:
                result.append(text[begin:index].strip())
                return result
            depth -= 1
        elif value == ',' and depth == 0:
            result.append(text[begin:index].strip())
            begin = index + 1
    raise ValueError('unterminated LLVM argument list')


def pointer(value):
    require(value.startswith('ptr ') and not re.search(r'\b(?:byval|sret|inalloca)\b', value),
            'comparison argument must remain a borrowed pointer')
    match = re.search(r' (%[-.$\w]+)$', value)
    require(match is not None, 'comparison argument must be an SSA reference')
    return match[1]


def definitions(text):
    result = {}
    for function in re.findall(r'^define [^\n]*\{.*?^}', text, re.M | re.S):
        match = re.search(SYMBOL, function.splitlines()[0])
        require(match is not None and match[1] not in result, 'unique LLVM function identity')
        result[match[1]] = function
    return result


def verifiers(text, accelerated):
    found = [function for name, function in definitions(text).items()
             if all(token in name for token in ('hardened_in_place', 'core_state', '6verify'))
             and all(re.search('%' + arg + r'[,)]', function.splitlines()[0])
                     for arg in ('self', 'input', 'candidate'))]
    require(len(found) == (4 if accelerated else 2), 'complete instantiated verifier inventory')
    return found


def comparison_calls(function):
    found = {ACCUMULATE: [], PREDICATE: []}
    for line in function.splitlines()[1:]:
        if line.lstrip().startswith(';'):
            continue
        for kind in found:
            if kind not in line:
                continue
            match = re.search(SYMBOL, line)
            require(match is not None and kind in match[1], 'direct comparison callee')
            require(re.search(r'\b(?:call|invoke)\b', line[:match.start()]), 'comparison must be called')
            params = arguments(line, match.end())
            require(len(params) == (3 if kind == ACCUMULATE else 1), 'comparison argument count')
            for parameter in params:
                pointer(parameter)
            if kind == ACCUMULATE:
                require(re.search(r'\bvoid\s*$', line[:match.start()]), 'difference must not return secret data')
            else:
                require(re.search(r'\bi8\s*$', line[:match.start()]), 'expected byte-sized Choice verdict ABI')
            found[kind].append(line)
    require([len(found[key]) for key in (ACCUMULATE, PREDICATE)] == [2, 1],
            'two accumulation calls and one verdict call required')
    return [line for values in found.values() for line in values]


def forwarder(function):
    """Closed grammar: pointer spills for debug info, one exact forwarding call."""
    header = function.splitlines()[0]
    match = re.search(SYMBOL, header)
    require(match is not None and re.search(r'\bvoid\s*$', header[:match.start()]), 'void forwarding ABI')
    params = [pointer(value) for value in arguments(header, match.end())]
    require(params == ['%difference', '%left', '%right'], 'exact forwarding parameter order')
    slots, calls, returns, callee = set(), 0, 0, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith((';', '#dbg_')) or line == 'start:':
            continue
        require(returns == 0, 'instructions after forwarding return')
        slot = re.fullmatch(r'(%[-.$\w]+) = alloca \[8 x i8\], align 8', line)
        if slot:
            require(slot[1] not in slots and slot[1] not in params, 'unique pointer spill slot')
            slots.add(slot[1])
            continue
        store = re.fullmatch(r'store ptr (%[-.$\w]+), ptr (%[-.$\w]+), align 8', line)
        if store:
            require(store[1] in params and store[2] in slots, 'only input pointers may enter local debug slots')
            continue
        match = re.search(SYMBOL, line)
        if match:
            require(re.fullmatch(r'(?:tail )?call (?:fastcc )?void\s*', line[:match.start()]), 'void direct forwarding call')
            require(PRIVATE + '10accumulate' in match[1] or PRIVATE + '15accumulate_byte' in match[1], 'expected private boundary')
            require([pointer(value) for value in arguments(line, match.end())] == params, 'forward exact pointers in order')
            calls += 1
            callee = match[1]
            continue
        if re.fullmatch(r'ret void(?:, !dbg !\d+)?', line):
            require(calls == 1, 'exactly one boundary call before return')
            returns += 1
            continue
        raise ValueError('unreviewed forwarding instruction: ' + line)
    require(calls == returns == 1, 'complete straight-line forwarding')
    return callee


def forwarding_chain(text):
    functions = definitions(text)
    roots = [name for name in functions if ACCUMULATE in name]
    require(len(roots) == 1, 'unique public comparison wrapper')
    chain, name = [], roots[0]
    while PRIVATE + '15accumulate_byte' not in name:
        require(name in functions and name not in {entry[0] for entry in chain}, 'complete acyclic comparison forwarding')
        chain.append((name, functions[name]))
        name = forwarder(functions[name])
    require(name in functions, 'private comparison implementation absent')
    return chain


def validate_record(document, directory):
    require(document.get('schema') == 1 and document.get('qualifies_register_cleanup') is False,
            'expected unqualified verification record')
    require(document['sources'] == capture.sources(), 'verification source closure is stale')
    expected = set(itertools.product(('1.90.0', '1.98.1'),
                   ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'),
                   ('debug', 'release'), ('portable', 'accelerated')))
    seen = set()
    for row in document['records']:
        compiler = row['compiler'].splitlines()[0].split()[1]
        identity = compiler, row['target'], row['profile'], row['mode']
        require(identity in expected and identity not in seen, 'duplicate or unknown verification configuration')
        seen.add(identity)
        require(row['execution'] == ('QEMU, not native' if row['target'].startswith('aarch64') else 'native'), 'execution classification')
        build = directory / '-'.join(identity)
        log = build / 'observations.log'
        require(capture.audit.digest(log) == row['log_sha256'], 'verification log changed')
        require(row['observations'] == capture.observations(log.read_text(), row['mode'] == 'accelerated', row['target']), 'observations differ from actual log')
        require(len(row['artifacts']) == 15, 'complete emitted artifact inventory')
        inventory = set()
        for relative, digest in row['artifacts'].items():
            path = (directory / relative).resolve()
            require(path.is_relative_to(directory.resolve()), 'artifact outside record directory')
            require(path.parent == build / row['target'] / row['profile'] / 'deps', 'artifact belongs to wrong configuration')
            require(capture.audit.digest(path) == digest, 'verification artifact changed')
            packages = [p for p in capture.PACKAGES if path.name.startswith(p + '-')]
            require(len(packages) == 1 and (packages[0], path.suffix) not in inventory, 'unique known artifact identity')
            inventory.add((packages[0], path.suffix))
        require(inventory == set(itertools.product(capture.PACKAGES, ('.mir', '.ll', '.s'))), 'missing emitted artifact kind')
    require(seen == expected, 'incomplete verification matrix')


def cases(record):
    record = record.resolve()
    document = json.loads(record.read_text())
    validate_record(document, record.parent)
    for row in document['records']:
        def artifact(package, extension):
            return next((record.parent / key).read_text() for key in row['artifacts']
                        if Path(key).name.startswith(package + '-') and key.endswith(extension))
        yield row, artifact('brynja_mac_kmac', '.ll'), artifact('brynja_core', '.ll'), artifact('brynja_core', '.s')


def main(record):
    before = capture.sources()
    counts = [0, 0, 0]
    for row, kmac, core, assembly in cases(record):
        for function in verifiers(kmac, row['mode'] == 'accelerated'):
            comparison_calls(function)
            counts[0] += 1
        counts[1] += len(forwarding_chain(core))
        for checker in (difference, predicate):
            checker.inspect(assembly, row['target'].startswith('aarch64'))
            counts[2] += 1
    require(counts == [48, 24, 32] and before == capture.sources(), 'incomplete or changing comparison inputs')
    print('KMAC verification: 48 instantiated comparison ABIs, 24 pointer-only forwarders, 32 private assembly boundaries PASS')
    print('Record SHA-256: ' + capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(recorded.inspector_sources(), sort_keys=True))
    print('Not full verifier provenance/data-flow, callee-tree, spill, platform or erasure qualification; no build/runtime rerun')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
