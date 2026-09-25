#!/usr/bin/env python3
"""Finish admission/result forwarding composed with actual verifier ownership."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_verifier_finish import FinishModel, closure, ownership, model, comparison, require


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        definitions = {**comparison.definitions(core), **comparison.definitions(kmac)}
        _, names = ownership.guard.metadata.select(kmac, core)
        names['GLUE'], _ = ownership.guard.metadata.one(definitions,
            lambda name: 'core_state' in name and 'Guard' in name and ('drop_in_place' in name or 'drop_glue' in name),
            'actual verifier guard glue')
        for function in comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            yield function, definitions, names, kmac, 20 if row['mode'] == 'accelerated' else 7


def scenarios(errors, width, fast):
    maximum = (1 << 128) - 1
    for present in (False, True):
        for strong in (False, True):
            for production in (False, True):
                for bits, strength in ((127, 128), (128, 128)) if fast else (
                    (0, 0), (0, 128), (127, 128), (128, 128), (129, 128), (255, 256),
                    (256, 256), (maximum - 1, maximum), (maximum, maximum)):
                    yield present, strong, bits, strength, production, None, 1
    for outcome in (*range(errors), 'unwind'):
        yield True, True, 256, 256, True, outcome, 1
    for variant in ((0, 1) if width == 24 else (0, 1, 168)):
        yield True, True, 0, 128, False, None, variant


def inspect(function, definitions, names, text, errors, fast=False):
    root, roles, constants, functions, transfer = closure(function, definitions, names, text)
    width, result, _, allocations, _, _, live = transfer
    count = success = unwind_count = 0
    for base in (0, 32):
        for scenario in scenarios(errors, width, fast):
            present, strong, bits, strength, production, outcome, variant = scenario
            m = FinishModel(functions, names, roles, constants, base, width, scenario)
            slots = {name: m.allocate('slot:' + name, size) for name, size in allocations.items()}
            p = model.Pointer
            core, input_slot = m.allocate('core', width), m.allocate('input', 32)
            for region, size in (('metadata', base + 66), ('engine', base + 1088), ('scratch', 168), ('message', base + 1)):
                m.allocate(region, size, payload=True)
            m.allocate('exception', 0)
            m.store(core, 8, p('metadata', base))
            # Valid descriptor shape, with contents/canonicality a producer
            # precondition. No payload bytes are installed in this model.
            m.input_fields = ([(0, 8, p('message', base)), (8, 8, 1), (16, 8, 7), (24, 1, 7)]
                              if base else [(0, 8, 0)])
            for offset, size, value in m.input_fields:
                m.store(p('input', offset), size, value)
            prefix = ['none'] + (['key', 'ne'] if present and production else [])
            error_base = 0 if errors == 7 else 12
            error = (error_base if not present else error_base + 1 if production and not strong else
                     error_base + 2 if production and bits < strength else outcome)
            admitted = present and (not production or (strong and bits >= strength))
            expected_events = prefix + (['suffix'] if admitted else []) + ['state_drop' if error is None else 'core_drop']
            try:
                returned = m.run(root, [slots[result], core, input_slot, bits, strength, int(production)])
            except model.Unwind as exception:
                require(error == 'unwind' and exception.value == (p('exception'), 37), 'original modeled exception preserved')
                require(m.load(slots[result], 8) is model.UNKNOWN, 'unwind cannot publish a finish result')
                unwind_count += 1
            else:
                require(error != 'unwind' and returned is None, 'original finish return')
                selected = m.run('fragment', list(slots.values()))
                require(selected == int(error is not None) and m.observed_error == error, 'composed actual finish/transfer outcome')
                if error is None:
                    require(m.load(slots['%cleanup'], 8) == p('metadata', base) and m.load(slots[live], 1) == 1,
                            'original cleanup owner and live-reader transfer')
                    for offset, size, value in m.reader_fields:
                        require(m.load(p(slots['%reader'].region, offset), size) == value, 'all produced reader fields preserved')
                    m.run(names['GLUE'], [slots['%cleanup']])
                    require(m.requests == [(64, 1), (0, 64), (65, 1)], 'transferred guard requests original metadata clearing')
                    success += 1
                else:
                    require(m.load(slots['%cleanup'], 8) is model.UNKNOWN and m.load(slots['%reader'], 8) is model.UNKNOWN
                            and not m.requests, 'rejected finish cannot initialize caller owners')
            require(m.boundary_events == expected_events, 'exact ordered admission/producer/destructor requests')
            count += 1
    return count, success, unwind_count


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in cases(record)]
    require(len(results) == 24 and before == comparison.capture.sources(), 'complete unchanged finish/transfer matrix')
    totals = tuple(sum(values[i] for values in results) for i in range(3))
    require(totals == (4368, 1216, 48), 'complete admission, ownership and suffix-unwind scenario coverage')
    print(f'Debug verifier finish: 24 composed paths; cases={totals[0]}; successful transfers={totals[1]}; modeled unwinds={totals[2]} PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('State/key classification, suffix producer and state/Core destructors remain contracts; no whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
