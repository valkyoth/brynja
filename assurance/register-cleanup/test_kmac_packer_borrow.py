#!/usr/bin/env python3
"""Input-byte borrow regressions over retained LLVM; no compiler execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_packer_borrow as check
from test_debug_accelerated_model import rejects


def main(record):
    before = check.comparison.capture.sources()
    mutations = controls = 0
    for body, core, assembly, arm in check.cases(record):
        baseline = check.inspect(body, core, assembly, arm)
        for instruction in ('%leak = load i8, ptr %byte, align 1',
                            '%leak = ptrtoint ptr %byte to i64',
                            'call void @unchecked(ptr %byte)',
                            '%alias = getelementptr i8, ptr %byte, i64 0'):
            changed = body.replace('start:\n', 'start:\n  ' + instruction + '\n', 1)
            assert changed != body
            mutations += rejects(lambda: check.inspect(changed, core, assembly, arm))
        call = next(line for lines in check.model.blocks(body).values() for line in lines
                    if 'call ' in line and 'secret_memory20xor_secret_byte_bits' in line)
        changed = body.replace(call, call.replace('%byte', '%self'), 1)
        mutations += rejects(lambda: check.inspect(changed, core, assembly, arm))
        changed = body.replace('start:\n', 'start:\n; harmless review comment\n', 1)
        assert changed != body and check.inspect(changed, core, assembly, arm) == baseline
        controls += 1
    assert (mutations, controls) == (440, 88)
    assert before == check.comparison.capture.sources()
    print('KMAC input-byte borrow: 440 payload/escape/alias/wrong-source mutations reject; 88 controls PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
