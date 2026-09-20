#!/usr/bin/env python3
"""Negative controls on retained actual assembly; no compiler/execution reruns."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_recorded_boundaries as check


def main(record):
    for inventory in (check.CHECKS[:-1], (*check.CHECKS[:-1], check.CHECKS[0])):
        with patch.object(check, 'CHECKS', inventory):
            try:
                next(check.cases(record))
            except ValueError:
                continue
        raise AssertionError('incomplete/duplicate boundary inventory accepted')
    count = 0
    for package, name, marker, arm, inspect, text in check.cases(record):
        inspect(text, arm)
        # Shared markers can occur in multiple native functions within a crate;
        # the existing validator still selects its exact one function identity.
        end = r'(?m)^(.*BRYNJA_' + marker + r'_END.*)$'
        mutants = (
            text.replace('BRYNJA_' + marker + '_ERASE', 'MISSING_ERASE'),
            re.sub(r'(?m)^(.*BRYNJA_' + marker + r'_ERASE[^\n]*\n)[^\n]+\n', r'\1', text),
            re.sub(end, ('ldr x4, [x0]' if arm else 'movq (%rdi), %rax') + r'\n\1', text),
            re.sub(end, r'\1\n' + ('ldr x4, [x0]' if arm else 'movq (%rdi), %rax'), text),
            re.sub(r'(?m)^(.*BRYNJA_' + marker + r'_BEGIN.*)$',
                   r'\1\n' + ('str x4, [sp]' if arm else 'pushq %rax'), text),
        )
        for mutant in mutants:
            if mutant == text:
                raise AssertionError('missing boundary mutation: ' + package + '/' + name)
            try:
                inspect(mutant, arm)
            except ValueError:
                count += 1
                continue
            raise AssertionError('actual assembly boundary mutant accepted: ' + package + '/' + name)
    if count != 8 * len(check.CHECKS) * 5:
        raise AssertionError('incomplete boundary mutation coverage')
    print(f'Actual crate assembly rejects {count} missing-boundary, missing-wipe, cleanup-load, post-cleanup-load and spill mutations')
    print('Missing/duplicate boundary inventories rejected; subprocess execution forbidden during this test')
    print('Assembly-text mutants, not compiled/runtime mutations; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('inspection must not rerun a compiler or runtime')):
        main(parser.parse_args().record)
