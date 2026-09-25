#!/usr/bin/env python3
"""Reject missing/malformed retained primitive ABIs without running compilers."""
import argparse
from pathlib import Path
from unittest.mock import patch

import check_debug_accelerated_read as check
from test_debug_portable_final_bridge import changed


def main(record):
    count = controls = 0
    for case in check.preflight.operation.cases(record):
        names, _, _ = check.closure(case)
        for role in ('session', 'permutation'):
            lines = [line for line in case.sha3.splitlines() if line.startswith('declare i8 @') and names[role] + '(' in line]
            assert len(lines) == 1
            body = lines[0]
            replacements = ('', body.replace('declare i8', 'declare i32', 1),
                            body.replace('ptr align 32', 'ptr byval([864 x i8]) align 32', 1),
                            body.replace('ptr align 32', 'i64', 1))
            for replacement in replacements:
                assert replacement != body
                try:
                    check.closure(changed(case, body, replacement))
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('invalid primitive declaration accepted: ' + role)
            control = body.replace('ptr align 32', 'ptr nonnull align 32' if role == 'session' else 'ptr', 1)
            assert control != body
            check.closure(changed(case, body, control))
            controls += 1
        for role, source in (('split', 'sha3'), ('lane_copy', 'core'), ('wipe', 'core')):
            body = check.comparison.definitions(getattr(case, source))[names[role]]
            replacements = ['', body.replace('ptr ', 'ptr byval([32 x i8]) ', 1),
                            body.replace('i64 ', 'i32 ', 1)]
            if role == 'split':
                replacements.append(body.replace('sret([32 x i8])', 'sret([16 x i8])', 1))
            for replacement in replacements:
                assert replacement != body
                try:
                    check.closure(changed(case, body, replacement))
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('invalid primitive definition accepted: ' + role)
    assert (count, controls) == (144, 16)
    print(f'Engine-read ABI bindings: {count} missing/width/by-value failures rejected; {controls} pointer-attribute controls PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
