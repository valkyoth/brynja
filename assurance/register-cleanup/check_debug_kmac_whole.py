#!/usr/bin/env python3
"""Complete verifier control-flow replay; payload leaf contracts stay explicit."""
import argparse
from pathlib import Path
from unittest.mock import patch

import check_debug_verifier_destructors as retained
from debug_kmac_whole import closure, model, comparison, require, destruction
from debug_kmac_whole_model import WholeModel


def scenarios(fast=False):
    for length in ((0, 1, 65, 130) if fast else (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 130, 193)):
        for valid in ((0,) if not length else ((1, 8) if fast else range(1, 9))):
            for mismatch in (None, 0, length - 1) if length else (None,):
                yield length, valid, True, True, False, None, mismatch, None
    for present, strong, production in ((False, True, False), (True, False, True), (True, True, True)):
        for length in (1, 16, 17):
            for expected in (None, 999):
                yield length, 8, present, strong, production, expected, None, None
    for stage in ('suffix', 'bulk', 'final'):
        for error in range(7):
            yield 130, 3, True, True, False, None, None, (stage, error, 2) if stage == 'bulk' else (stage, error)


def run(function, definitions, names, text, scenario, inject=None, linked=None):
    root, functions, boundaries, constants, accelerated = linked or closure(function, definitions, names, text)
    m = WholeModel(functions, names, boundaries, constants, accelerated, scenario)
    m.inject = inject
    length, valid, present, strong, production, expected, mismatch, failure = scenario
    p = model.Pointer
    for region, size, payload in (('self', 32, False), ('input', 32, False), ('candidate_desc', 32, False),
            ('candidate', 32 + length, True), ('engine', 1120, True), ('metadata', 98, True),
            ('scratch', 168, True), ('exception', 0, False)):
        m.allocate(region, size, payload)
    m.fields(p('self'), [(0, 8, p('metadata', 32))])
    if accelerated:
        m.fields(p('self'), [(8, 8, p('engine', 32) if present else 0), (16, 8, p('scratch')), (24, 8, 168)])
    else:
        if present:
            m.store(p('self', 8), 8, p('engine', 32))
        m.store(p('self', 16), 1, 1 if present else 2)
    bits = (length - 1) * 8 + valid if length else 0
    m.store(p('input'), 8, 0)
    if getattr(m, 'message', None) is not None:
        m.fields(p('input'), m.message)
    m.fields(p('candidate_desc'), [(0, 8, p('candidate', 32)), (8, 8, length), (16, 8, bits), (24, 1, valid)])
    args = [p('self'), p('input'), p('candidate_desc'), int(expected is not None), expected or 0, 128, int(production)]
    try:
        result = m.run(root, args)
    except model.Unwind as error:
        require(inject is not None and error.value == (p('exception'), 37), 'whole verifier resumes original exception')
        result = 'unwind'
    return m, result, root


def inspect(function, definitions, names, text, fast=False, injections=True):
    total = comparisons = unwinds = 0
    linked = closure(function, definitions, names, text)
    for scenario in scenarios(fast):
        m, result, root = run(function, definitions, names, text, scenario, linked=linked)
        length, valid, present, strong, production, expected, mismatch, failure = scenario
        bits = (length - 1) * 8 + valid if length else 0
        # Error variants differ with the feature-enabled enum. Read the actual
        # invalid-shape literal, independently of the returned value.
        body = model.blocks(function)
        literals = [int(line.split()[2].rstrip(',')) for lines in body.values() for line in lines
                    if line.startswith(('store i8 6,', 'store i8 18,'))]
        require(literals and len(set(literals)) == 1, 'bound invalid-bit-string variant')
        base = literals[0] - 6
        error = (base + 6 if expected is not None and expected != bits else base if not present else
                 base + 1 if production and not strong else base + 2 if production and bits < 128 else
                 failure[1] if failure else None)
        require(result == ((0, int(mismatch is None)) if error is None else (1, error)), 'whole verifier exact result')
        require(not m.output_live, 'no live output owner after actual return')
        require([x for x in m.trace if x[0] == 'metadata'] == [('metadata', *item) for item in destruction.METADATA],
                'one complete original metadata cleanup on return')
        engine = [x for x in m.trace if x[0] == 'engine']
        require(engine == ([('engine', *item) for item in (destruction.ACCELERATED if m.accelerated else destruction.PORTABLE)] if present else []),
                'original live state/reader destruction exactly once')
        if error is None:
            complete = length - int(valid not in (0, 8))
            reads = [('bulk', min(64, complete - start)) for start in range(0, complete, 64)]
            if valid not in (0, 8):
                reads.append(('final', 1))
            require(m.reads == reads and m.outputs == [n for _, n in reads] and len(m.pairs) == length,
                    'complete exact chunk/final comparison and output Drop')
        total += 1
        comparisons += len(m.pairs)
    if not injections:
        return total, comparisons, unwinds
    scenario = (130, 3, True, True, False, None, None, None)
    baseline, _, _ = run(function, definitions, names, text, scenario, linked=linked)
    for role in ('suffix', 'bulk', 'final', 'expose', 'accumulate', 'predicate', 'get', 'get_mut', 'chunks', 'last', 'first'):
        for occurrence in (1, baseline.boundary_counts[role]):
            m, result, _ = run(function, definitions, names, text, scenario, (role, occurrence), linked)
            require(result == 'unwind' and not m.output_live, 'whole-call selected unwind destroys output owner')
            require([x for x in m.trace if x[0] == 'metadata'] == [('metadata', *item) for item in destruction.METADATA],
                    'whole-call unwind clears metadata once')
            expected = destruction.ACCELERATED if m.accelerated else destruction.PORTABLE
            require([x for x in m.trace if x[0] == 'engine'] == [('engine', *item) for item in expected],
                    'whole-call unwind destroys original state/reader once')
            unwinds += 1
    return total, comparisons, unwinds


def main(record):
    before = comparison.capture.sources()
    results = []
    for case in retained.cases(record):
        results.append(inspect(*case))
        print(f'Whole verifier: {len(results)}/24 paths; {results[-1]} PASS', flush=True)
    require(len(results) == 24 and before == comparison.capture.sources(), 'complete unchanged whole-verifier matrix')
    print('Totals: ' + repr(tuple(sum(row[i] for row in results) for i in range(3))))
    print('Complete caller CFG under explicit payload/backend/iterator contracts; not whole-call physical erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
