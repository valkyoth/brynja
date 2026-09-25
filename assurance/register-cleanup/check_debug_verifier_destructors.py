#!/usr/bin/env python3
"""Replay retained verifier Core/Borrowed Drop through owned-clear requests."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_verifier_destructors import (DestructorModel, closure, finish, model, comparison,
                                       require, PORTABLE, ACCELERATED, METADATA)


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        paths = [key for key in row['artifacts'] if Path(key).name.startswith('brynja_hash_sha3-') and key.endswith('.ll')]
        require(len(paths) == 1, 'unique bound same-row SHA-3 artifact')
        definitions = comparison.definitions((record.parent / paths[0]).read_text())
        for text in (core, kmac):
            for name, body in comparison.definitions(text).items():
                if name in definitions:
                    require(model.parameters(body) == model.parameters(definitions[name]) and
                            model.blocks(body) == model.blocks(definitions[name]), 'identical duplicate helper')
                definitions[name] = body
        _, names = finish.guard.metadata.select(kmac, core)
        names['GLUE'], _ = finish.guard.metadata.one(definitions,
            lambda n: 'core_state' in n and 'Guard' in n and ('drop_in_place' in n or 'drop_glue' in n),
            'actual guard glue')
        for function in comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            yield function, definitions, names, kmac


def inspect(function, definitions, names, text):
    roots, helpers, accelerated = closure(function, definitions, names, text)
    count = unwinds = clears = 0
    p = model.Pointer
    for base in (0, 32):
        for state in ((None, 1) if accelerated else (None, 0, 1)):
            for root in roots:
                for unwind in (False, True):
                    m = DestructorModel(helpers, names, roots, base, accelerated, unwind)
                    m.allocate('core', base + (32 if accelerated else 24))
                    m.allocate('metadata', base + 66, payload=True)
                    m.allocate('engine', base + 1088, payload=True)
                    m.allocate('exception', 0)
                    m.store(p('core', base), 8, p('metadata', base))
                    if accelerated or state is not None:
                        m.store(p('core', base + 8), 8, p('engine', base) if state is not None else 0)
                    if not accelerated:
                        m.store(p('core', base + 16), 1, 2 if state is None else state)
                    try:
                        result = m.run(roots[root], [p('core', base + (8 if root == 'state_drop' else 0))])
                    except model.Unwind as error:
                        require(unwind and error.value == (p('exception'), 37), 'original destructor exception identity')
                        unwinds += 1
                    else:
                        require(not unwind and result is None, 'normal destructor return')
                    expected = []
                    flags = [(859, 1, 1), (616, 8, 0)] if accelerated and state is not None and not unwind else []
                    expected += [('flag', *event) for event in flags]
                    if state is not None and not unwind:
                        expected += [('engine', offset, width) for offset, width in (ACCELERATED if accelerated else PORTABLE)]
                    if root == 'core_drop':
                        expected += [('metadata', offset, width) for offset, width in METADATA]
                    require(m.state_calls == 1 and m.trace == expected, 'exact state-first, metadata-last cleanup requests')
                    require(m.flags == flags, 'exact accelerated cancellation metadata writes')
                    count += 1
                    clears += sum(event[0] != 'flag' for event in m.trace)
    return count, unwinds, clears


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in cases(record)]
    require(len(results) == 24 and before == comparison.capture.sources(), 'complete unchanged destructor matrix')
    totals = tuple(sum(values[i] for values in results) for i in range(3))
    require(totals == (512, 256, 2624), 'complete destructor scenario coverage')
    print(f'Debug verifier destructors: 24 paths; cases={totals[0]}; modeled unwinds={totals[1]}; clear requests={totals[2]} PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Clear bodies and suffix consumption remain separate; no physical/native unwind or whole-verifier/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
