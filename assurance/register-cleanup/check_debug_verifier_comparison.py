#!/usr/bin/env python3
"""Retained debug verifier bulk loop with explicit reader/iterator contracts."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_verifier_comparison import ComparisonModel, extract, model, comparison, require


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        paths = [record.parent / key for key in row['artifacts']
                 if Path(key).name.startswith('brynja_hash_sha3-') and key.endswith('.ll')]
        require(len(paths) == 1, 'same-row output-helper artifact')
        definitions = {**comparison.definitions(core), **comparison.definitions(paths[0].read_text()),
                       **comparison.definitions(kmac)}
        for function in comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            yield function, definitions, 20 if row['mode'] == 'accelerated' else 7


def inspect(function, definitions, errors):
    allocations, result, roles, functions, _ = extract(function, definitions)
    count = pairs = 0
    probes = [(length, candidate, None) for length in (0, 1, 2, 31, 63, 64)
              for candidate in (0, 1, 2, 31, 63, 64)] + [(64, 64, error) for error in range(errors)]
    for base in (0, 32):
        for length, candidate_length, error in probes:
            machine = ComparisonModel(functions, roles, base, length, candidate_length)
            slots = {name: machine.allocate('slot:' + name, size) for name, size in allocations.items()}
            machine.allocate('metadata', base + 66, payload=True)
            machine.allocate('candidate', base + 64, payload=True)
            machine.allocate('empty', 0, payload=True)
            p = model.Pointer
            machine.store(slots['%cleanup'], 8, p('metadata', base))
            fields = ([(0, 8, 2), (8, 1, error)] if error is not None else
                      [(0, 8, 1), (8, 8, p('metadata', base)), (16, 8, length)] if length else [(0, 8, 0)])
            for offset, size, value in fields:
                machine.store(p(slots[result].region, offset), size, value)
            returned = machine.run('fragment', list(slots.values()) + [p('candidate', base), candidate_length])
            expected = 0 if error is not None else min(length, candidate_length)
            require(len(machine.pairs) == expected and returned == int(error is not None), 'all and only paired bytes compared')
            if error is not None:
                require(machine.boundaries == [('boundary_error', error)] and not machine.exposures,
                        'exact reader error without exposing or comparing output')
            else:
                require(len(machine.exposures) == 1 and machine.boundaries == [('boundary_drop', machine.exposures[0])],
                        'normal completion reaches original output Drop boundary')
            count += 1
            pairs += expected
    return count, pairs


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in cases(record)]
    require(len(results) == 24 and before == comparison.capture.sources(), 'complete unchanged debug comparison matrix')
    print(f'Debug verifier bulk comparison: {len(results)} fragments; {sum(n for n, _ in results)} cases; '
          f'{sum(n for _, n in results)} ordered byte-pair handoffs PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Reader result, expose/iterator and comparison primitives are contracts; no full verifier, unwind or F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
