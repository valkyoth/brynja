#!/usr/bin/env python3
"""Reject missing, wrong-route and altered KMAC review links without recompiling."""
import argparse
from pathlib import Path
from unittest.mock import patch

import check_kmac_review_links as check
from test_debug_accelerated_model import rejects


def main(record):
    before = check.comparison.capture.sources()
    links = check.debug_readers(record)
    total = controls = 0
    for case in check.whole.retained.cases(record):
        function, definitions, names, text = case
        assert check.debug_link(case, links) == 2
        _, _, boundaries, _, _ = check.whole.closure(*case)
        for root, role in boundaries.items():
            if role not in ('bulk', 'final'):
                continue
            key = text, root
            functions, kind = links[key]
            missing = dict(links)
            del missing[key]
            total += rejects(lambda: check.debug_link(case, missing))
            total += rejects(lambda: check.debug_link(case, {**links, key: (functions, 'wrong-route')}))
            changed = functions[root].splitlines()[0] + '\nstart:\n  ret void\n}'
            total += rejects(lambda: check.debug_link(case, {**links, key: ({**functions, root: changed}, kind)}))
            total += rejects(lambda: check.bind(definitions[root], {root: changed}, root))
            total += rejects(lambda: check.merge(functions, {root: changed}))
            assert check.merge(functions, {root: functions[root]}) == functions
            assert check.bind(definitions[root], dict(reversed(list(functions.items()))), root) is None
            controls += 2
        print(f'KMAC review-link regressions: {total} rejections; {controls} controls PASS', flush=True)
    assert (total, controls) == (240, 96)
    assert before == check.comparison.capture.sources()
    print('Exact row/body/ABI links reject missing coverage, wrong routes and stale/no-op helpers; unchanged source PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
