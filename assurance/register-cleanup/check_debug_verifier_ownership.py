#!/usr/bin/env python3
"""Retained verifier post-finish result/reader/guard ownership handoff."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_verifier_ownership import OwnershipModel, extract, guard, comparison, model, require


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        definitions = {**comparison.definitions(core), **comparison.definitions(kmac)}
        _, names = guard.metadata.select(kmac, core)
        names['GLUE'], _ = guard.metadata.one(definitions,
            lambda name: 'core_state' in name and 'Guard' in name and ('drop_in_place' in name or 'drop_glue' in name),
            'original verifier guard glue')
        for function in comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            yield function, definitions, names, 20 if row['mode'] == 'accelerated' else 7


def inspect(function, definitions, names, errors):
    width, result, output, allocations, functions, labels, live = extract(function, definitions, names)
    count = 0
    for base in (0, 32):
        for error, value in [(None, n) for n in ((0, 1) if width == 24 else (0, 1, 168))] + [(n, None) for n in range(errors)]:
            machine = OwnershipModel(functions, names, base)
            slots = {name: machine.allocate('slot:' + name, size) for name, size in allocations.items()}
            machine.allocate('metadata', base + 66, payload=True)
            machine.allocate('engine', base + 1088, payload=True)
            scratch = machine.allocate('scratch', 168, payload=True)
            owner, engine = model.Pointer('metadata', base), model.Pointer('engine', base)
            if error is None:
                reader = [(0, 8, engine), (8, 1, value)] if width == 24 else [(0, 8, engine), (8, 8, scratch), (16, 8, value)]
                fields = reader + [(width - 8, 8, owner)]
            else:
                fields = [(0, 1, error), (8, 1, 2)] if width == 24 else [(0, 8, 0), (8, 1, error)]
            for offset, size, item in fields:
                machine.store(model.Pointer(slots[result].region, offset), size, item)
            returned = machine.run('fragment', list(slots.values()))
            require(returned == int(error is not None), 'actual helper/caller discriminator selects exact success or error boundary')
            require(machine.observed_error == error, 'actual caller residual argument preserves the exact error byte')
            if error is None:
                require(machine.load(slots['%cleanup'], 8) == owner and machine.load(slots[live], 1) == 1,
                        'cleanup receives original returned metadata owner and live-reader flag is armed')
                for offset, size, item in reader:
                    require(machine.load(model.Pointer(slots['%reader'].region, offset), size) == item,
                            'all borrowed reader fields survive exact handoff')
                require(len(machine.moves) == (3 if width == 24 else 4), 'complete helper/caller descriptor transfers')
                require(machine.run(names['GLUE'], [slots['%cleanup']]) is None
                        and machine.requests == [(64, 1), (0, 64), (65, 1)], 'actual guard clears original metadata regions in order')
            else:
                require(machine.load(slots['%cleanup'], 8) is model.UNKNOWN
                        and machine.load(slots['%reader'], 8) is model.UNKNOWN
                        and machine.load(slots[live], 1) is model.UNKNOWN
                        and not machine.moves and not machine.requests, 'failed finish cannot construct a reader/guard')
                offset = 0 if width == 24 else 8
                require(machine.load(model.Pointer(slots[output].region, offset), 1) == error, 'error byte preserved at residual boundary')
            count += 1
    return count


def main(record):
    before = comparison.capture.sources()
    selected = list(cases(record))
    count = sum(inspect(*case) for case in selected)
    require(len(selected) == 24 and before == comparison.capture.sources(), 'complete unchanged debug verifier matrix')
    print(f'Debug verifier ownership: 24 actual post-finish fragments; {count} descriptor cases PASS')
    print('Original reader fields and metadata guard retained; error cannot initialize either owner')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Finish result is an input contract; fragment boundaries are not verifier exits; no whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
