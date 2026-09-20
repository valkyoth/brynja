#!/usr/bin/env python3
"""Mutate real retained worker MIR; never run production code or rebuild it."""
import argparse
import copy
from pathlib import Path
import re
from unittest.mock import patch

import check_worker_handoffs as check


def rejects(function, strength, label):
    try:
        check.check_function(function, strength)
    except (ValueError, check.mir.MirCleanupFlowError):
        return
    raise AssertionError('worker MIR mutant accepted: ' + label)


def main(record):
    functions = check.checked_functions(record)
    rejected = 0
    for strength, function in functions:
        owner = check.check_function(function, strength)
        name = f'ParallelHash{strength}LeafWorkspace'
        # Every individual success/error/unwind Drop site must matter.
        drops = list(re.finditer(rf'drop\({owner}\) ->', function))
        assert len(drops) == 3
        for drop in drops:
            mutant = function[:drop.start()] + '_999 = lost_drop() ->' + function[drop.end():]
            rejects(mutant, strength, 'individual Drop bypass')
            rejected += 1
        call = re.search(rf'(?m)^\s*(_\d+) = {name}::.*?execute\((?:move|copy) (_\d+),.*?-> \[return: (bb\d+), unwind: (bb\d+)\];', function)
        assert call
        alias, returned = call[2], call[3]
        start = re.search(rf'(?m)^\s*{returned}: \{{', function)
        assert start
        for payload in (f'_999 = copy {owner};', f'_999 = move {owner};',
                        f'_999 = &mut {owner};', f'_999 = copy {alias};',
                        f'StorageDead({owner});', 'return;', 'resume;',
                        f'goto -> {returned};'):
            mutant = function[:start.end()] + '\n        ' + payload + function[start.end():]
            rejects(mutant, strength, payload)
            rejected += 1
        for before, after in (
            (f'{alias} = &mut {owner};', f'{alias} = &mut _999;'),
            (f'unwind: {call[4]}', 'unwind continue'),
            (f'fn leaf{strength}(', 'fn wrong_worker('),
            (f'Result<(ParallelHash{strength}LeafResult<\'_, \'_>, bool), execution::Error>',
             'Result<([u8; 64], bool), execution::Error>'),
            ('debug workspace =>', 'debug unbound_workspace =>'),
        ):
            assert before in function
            rejects(function.replace(before, after), strength, before)
            rejected += 1
    original = check.json.loads(record.read_text())
    variants = []
    for key, value in (('sources', {}), ('api_profile', 'accelerated'),
                       ('qualifies_register_cleanup', True), ('records', [])):
        changed = copy.deepcopy(original)
        changed[key] = value
        variants.append(changed)
    changed = copy.deepcopy(original)
    changed['records'].append(changed['records'][0])
    variants.append(changed)
    changed = copy.deepcopy(original)
    key = next(iter(changed['records'][0]['artifacts']))
    changed['records'][0]['artifacts'][key] = '0' * 64
    variants.append(changed)
    for changed in variants:
        with patch.object(check.json, 'loads', return_value=changed):
            try:
                check.checked_functions(record)
            except ValueError:
                continue
        raise AssertionError('invalid development record accepted')
    print(f'Worker handoff diagnostic rejects {rejected} real-MIR mutations and {len(variants)} record regressions')
    print('MIR mutations only; not compiled fault injection or full-erasure proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
