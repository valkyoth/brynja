#!/usr/bin/env python3
"""Reconcile same-row KMAC caller/reader checks; not a new release gate."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_whole as whole
import check_debug_bulk_guard as bulk
import check_debug_filled_squeeze as filled
import check_debug_filled_consuming as final
import check_debug_reader_session as accelerated
import check_kmac_final_chain as optimized
import check_kmac_accelerated_readers as optimized_accelerated

comparison, model, require = whole.comparison, whole.model, whole.require


def merge(left, right):
    result = dict(left)
    for name, body in right.items():
        require(name not in result or
                (model.parameters(body), model.blocks(body)) ==
                (model.parameters(result[name]), model.blocks(result[name])),
                'identical instructions for every shared review dependency')
        result[name] = body
    return result


def bind(function, functions, root):
    require(root in functions and re.search(comparison.SYMBOL, function.splitlines()[0])[1] == root,
            'original caller boundary is a reviewed defined root')
    require((model.parameters(function), model.blocks(function)) ==
            (model.parameters(functions[root]), model.blocks(functions[root])),
            'exact body/ABI at the caller-to-reader review link')


def debug_readers(record):
    links = {}
    def add(text, root, functions, kind):
        key = text, root
        require(key not in links, 'unique same-row reader qualification link')
        bind(comparison.definitions(text)[root], functions, root)
        links[key] = functions, kind
    for case in bulk.cases(record):
        producer, _, functions = bulk.closure(case)
        filled_producer, _, filling = filled.closure(case.inner)
        require(producer == filled_producer, 'bulk and filled review use identical producer')
        add(case.outer.kmac, case.outer.root, merge(functions, filling), 'portable-bulk')
        _, _, _, functions = final.closure(case.inner)
        add(case.inner.kmac, case.inner.root, functions, 'portable-final')
    for case, cpu in accelerated.cases(record):
        for consuming in (False, True):
            root, _, _, functions = accelerated.closure(case, cpu, consuming)
            add(case.kmac, root, functions, 'accelerated-final' if consuming else 'accelerated-bulk')
    require(len(links) == 48, 'sixteen portable and eight accelerated reader pairs')
    return links


def debug_link(case, links):
    function, definitions, names, text = case
    _, _, boundaries, _, is_accelerated = whole.closure(*case)
    roles = []
    for root, role in boundaries.items():
        if role not in ('bulk', 'final'):
            continue
        require((text, root) in links, 'missing same-row reader coverage')
        functions, kind = links[text, root]
        require(kind == ('accelerated-' if is_accelerated else 'portable-') + role,
                'correct route and consuming/nonconsuming boundary')
        bind(definitions[root], functions, root)
        roles.append(role)
    require(sorted(roles) == ['bulk', 'final'], 'both actual verifier reader boundaries covered')
    return len(roles)


def optimized_links(record):
    portable, accelerated_count = 0, 0
    # These existing inspectors derive both actual reader symbols from each
    # optimized verifier, then resolve the producer and its helper bodies from
    # that very row. No symbol-only cross-build lookup is used.
    for case in optimized.cases(record):
        optimized.inspect(case, thorough=False)
        portable += 1
    for case in optimized_accelerated.cases(record):
        optimized_accelerated.inspect(case)
        accelerated_count += 1
    require((portable, accelerated_count) == (16, 8), 'complete optimized reader-pair matrix')
    return portable, accelerated_count


def main(record):
    before = comparison.capture.sources()
    links = debug_readers(record)
    counts = [debug_link(case, links) for case in whole.retained.cases(record)]
    require(len(counts) == 24 and sum(counts) == 48, 'complete debug verifier-to-reader links')
    print('KMAC debug review reconciliation: 24 verifiers, 48 exact reader links PASS', flush=True)
    counts = optimized_links(record)
    require(before == comparison.capture.sources(), 'captured sources unchanged')
    print(f'KMAC optimized review reconciliation: {counts[0]} portable and {counts[1]} accelerated pairs PASS')
    print('Existing contracts compose by exact row/body/ABI; leaf effects retain their separately stated scope.')
    print('Not exhaustive execution, native platform evidence, or whole-call register/spill erasure.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
