#!/usr/bin/env python3
"""Mutate real retained worker MIR; never run production code or rebuild it."""
import argparse
import copy
from pathlib import Path
import re
from unittest.mock import patch

import check_worker_handoffs as check


def rejects(function, strength, label, *, batch=False):
    try:
        (check.check_batch_function if batch else check.check_function)(function, strength)
    except (ValueError, check.mir.MirCleanupFlowError):
        return
    raise AssertionError('worker MIR mutant accepted: ' + label)


def main(record, *, batch=False):
    functions = check.checked_functions(record, batch=batch)
    rejected = 0
    for strength, function in functions:
        validate = check.check_batch_function if batch else check.check_function
        owner = validate(function, strength)
        name = f'ParallelHash{strength}LeafWorkspace'
        # Every individual success/error/unwind Drop site must matter.
        drops = list(re.finditer(rf'drop\({owner}\) ->', function))
        assert len(drops) == 3
        for drop in drops:
            mutant = function[:drop.start()] + '_999 = lost_drop() ->' + function[drop.end():]
            rejects(mutant, strength, 'individual Drop bypass', batch=batch)
            rejected += 1
        target = (rf"Batch{strength}::<'_, '_>::execute_into\((?:move|copy) _\d+, (?:move|copy) _\d+, "
                  if batch else rf'{name}::.*?execute\(')
        call = re.search(rf'(?m)^\s*(_\d+) = {target}(?:move|copy) (_\d+),.*?-> \[return: (bb\d+), unwind: (bb\d+)\];', function)
        assert call
        alias, returned = call[2], call[3]
        start = re.search(rf'(?m)^\s*{returned}: \{{', function)
        assert start
        for payload in (f'_999 = copy {owner};', f'_999 = move {owner};',
                        f'_999 = &mut {owner};', f'_999 = copy {alias};',
                        f'StorageDead({owner});', 'return;', 'resume;',
                        f'goto -> {returned};'):
            mutant = function[:start.end()] + '\n        ' + payload + function[start.end():]
            rejects(mutant, strength, payload, batch=batch)
            rejected += 1
        worker = f'wave{strength}::{{closure#0}}::{{closure#2}}' if batch else f'leaf{strength}'
        signature = (f"Result<Leaves{strength}<'_, '_, '_>, execution::batch::Error>" if batch
                     else f"Result<(ParallelHash{strength}LeafResult<'_, '_>, bool), execution::Error>")
        for before, after in (
            (f'{alias} = &mut {owner};', f'{alias} = &mut _999;'),
            (f'unwind: {call[4]}', 'unwind continue'),
            (f'fn {worker}(', 'fn wrong_worker('),
            (signature, 'Result<([u8; 64], bool), execution::Error>'),
            ('debug workspace =>', 'debug unbound_workspace =>'),
        ):
            assert before in function
            rejects(function.replace(before, after), strength, before, batch=batch)
            rejected += 1
        if batch:
            # Control::new is out-of-line in debug but inlined in release;
            # neither setup shape may copy, replace or leak the owner borrow.
            borrow = f'{alias} = &mut {owner};'
            for payload in (f'_999 = copy {alias};', f'{alias} = &mut _999;',
                            f'_999 = copy {owner};', f'escape({alias});'):
                rejects(function.replace(borrow, borrow + '\n        ' + payload),
                        strength, 'pre-execution ' + payload, batch=True)
                rejected += 1
            result = re.findall(r'debug result => (_\d+);', function)[0]
            for before, after in ((f'drop({result})', 'drop(_999)'),
                                  ('debug result =>', 'debug unbound_result =>')):
                rejects(function.replace(before, after), strength, before, batch=True)
                rejected += 1
            cleanup = re.search(rf'drop\({result}\) -> \[return: bb\d+, unwind terminate\(cleanup\)\];', function)
            assert cleanup
            # Only abort is excluded: a recoverable unwind from result Drop
            # cannot bypass the workspace destructor.
            rejects(function.replace(cleanup[0], cleanup[0].replace(
                'unwind terminate(cleanup)', 'unwind continue')), strength,
                'recoverable unwind mislabeled as abort', batch=True)
            rejected += 1
    original = check.json.loads(record.read_text())
    parent_rejected = 0
    if batch:
        for row in original['records']:
            relative = next(key for key in row['artifacts']
                            if 'brynja_hash_parallel_std-' in key and key.endswith('.mir'))
            function = check.check_parent_slots((record.parent / relative).read_text())
            for mutant in (
                function.replace('GroupSlots::clear(', 'GroupSlots::wrong_clear('),
                re.sub(r'((?:copy|move) )_1\)', r'\g<1>_99)', function),
                function.replace('bb0: {', 'bb0: {\n        switchInt(const false) -> [0: bb2, otherwise: bb3];\n    }\n    bb2: {\n        return;\n    }\n    bb3: {'),
            ):
                assert mutant != function
                try:
                    check.check_parent_slots(mutant)
                except (ValueError, check.mir.MirCleanupFlowError):
                    parent_rejected += 1
                    continue
                raise AssertionError('parent slot cleanup mutant accepted')
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
                check.checked_functions(record, batch=batch)
            except ValueError:
                continue
        raise AssertionError('invalid development record accepted')
    mode = 'Multibuffer' if batch else 'Single-leaf'
    print(f'{mode} worker handoff diagnostic rejects {rejected} real-MIR mutations and {len(variants)} record regressions')
    if batch:
        print(f'Parent slot forwarding rejects {parent_rejected} MIR cleanup/receiver/bypass mutations')
    print('MIR mutations only; not compiled fault injection or full-erasure proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--batch', action='store_true')
    args = parser.parse_args()
    main(args.record, batch=args.batch)
