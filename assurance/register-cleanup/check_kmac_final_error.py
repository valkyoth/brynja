#!/usr/bin/env python3
"""Retained portable final-adapter reader-error descriptor conversion."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_final_adapter as adapter

comparison = adapter.comparison
require = adapter.require
SSA = adapter.SSA
# Reviewed retained compiler-private layouts, not a Rust ABI promise.
# Input: StateConsumed, MessageTooLong, OutputTooLong, OutputLength, SecretMemory.
MAPPINGS = {'portable': (0, 3, 4, 4, 5), 'accelerated': (12, 15, 16, 16, 17)}


def inspect(function, callees, mode):
    require(mode in MAPPINGS, 'known retained KMAC feature layout')
    trace = adapter.inspect(function, callees)
    _, _, error, _, returning, result = trace.adapter_details
    lines = trace.graph[error]
    require(len(lines) == 10, 'closed reader-error conversion block')

    def assignment(index, pattern, label):
        match = re.fullmatch('(' + SSA + ') = ' + pattern, lines[index])
        require(match is not None, label)
        return match[1]

    field = assignment(0, r'getelementptr inbounds nuw i8, ptr ' + re.escape(result) + r', i64 8',
                       'read error field of actual failed reader result')
    code = assignment(1, r'load i8, ptr ' + re.escape(field) + r', align 8', 'reader error byte')
    shift = assignment(2, r'shl nuw nsw i8 ' + re.escape(code) + ', 3', 'one byte per error entry')
    wide = assignment(3, r'zext nneg i8 ' + re.escape(shift) + ' to i40', 'bounded unsigned table shift')
    packed = sum(code << (8 * index) for index, code in enumerate(MAPPINGS[mode]))
    shifted = assignment(4, 'lshr i40 ' + str(packed) + ', ' + re.escape(wide), 'reviewed complete error mapping')
    mapped = assignment(5, 'trunc i40 ' + re.escape(shifted) + ' to i8', 'selected mapped error byte')
    output = assignment(6, r'getelementptr inbounds nuw i8, ptr %_0, i64 8', 'only caller result error field')
    require(lines[7:] == [f'store i8 {mapped}, ptr {output}, align 8',
                         'store i64 2, ptr %_0, align 8', 'br label %' + returning],
            'error result remains an error and returns without payload work')
    # Exercise each valid retained enum value, including shift flag premises.
    for code, expected in enumerate(MAPPINGS[mode]):
        amount = code << 3
        require(amount < 128 and amount < 40 and (packed >> amount) & 255 == expected,
                'all five valid errors map without poison or truncation loss')
    return trace, error


def cases(record):
    for row, function, callees in adapter.cases(record):
        yield function, callees, row['mode']


def main(record):
    before = comparison.capture.sources()
    checked = [inspect(*case) for case in cases(record)]
    require(len(checked) == 16 and before == comparison.capture.sources(), 'complete unchanged reader-error matrix')
    print('KMAC final reader error: 16 adapters, 80 valid error mappings, error-only descriptor writes PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Compiler-private valid-enum mapping only; not destination clearing, reader correctness or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
