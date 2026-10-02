#!/usr/bin/env python3
"""Native capture encoding/completeness regressions; not VBS execution."""
import copy
import struct
import windows_enclave_keccak_simd_native as native


def rejected(call):
    try:
        call()
    except (ValueError, RuntimeError):
        return
    raise AssertionError('Invalid native evidence accepted')


def main():
    rows = native.cases()
    assert len(rows) == 52
    assert {i for row in rows for i, *_ in row[0]} == set(range(1, 9))
    assert any(not any(row[1]) for row in rows)
    assert any(any(v == 0 for _, v, *_ in row[0]) for row in rows)
    for layout, data, expected in rows:
        assert len(expected) == 1024 and len(data) == 12
        pointers = [0x10000 + 0x1000*part for part in range(12)]
        for op in (100, 101, 102):
            words = native.words_for(op, 37, layout, pointers)
            assert len(struct.pack('<48Q', *words)) == 384
            assert words[:4] == [22, 37, 1000 if op == 100 else 0, 2]
            for lane, (identity, ob, mb, nb, sb) in enumerate(layout):
                assert words[4+lane*11:6+lane*11] == ([identity, ob] if op != 102 else [0, 0])
                for part, bits in enumerate((mb, nb, sb)):
                    index = lane*3+part
                    want = [(bits+7)//8, 1+(bits-1)%8, pointers[index]] if op == 100 and bits else [0, 0, 0]
                    offset = 6+lane*11+part*3
                    assert words[offset:offset+3] == want
                    assert len(data[index]) == (bits+7)//8
                    if bits % 8:
                        assert data[index][-1] >> (bits % 8) == 0
        present = sum(bool(item) for item in data)
        assert native.copy_counts(100, None, layout) == [1, present, 0, 0]
        assert native.copy_counts(101, None, layout) == [1, 0, 1, 0]
    layout, _, _ = native.failure_row()
    for part in range(12):
        assert native.copy_counts(100, f'payload-{part}', layout) == [1, part, 0, 1]
    for fault in ('version', 'sequence', 'route', 'identity', 'length', 'last'):
        assert native.copy_counts(100, fault, layout) == [1, 0, 0, 0]
    for fault in ('budget', 'bits'):
        assert native.copy_counts(100, fault, layout) == [1, 12, 0, 0]
    assert native.copy_counts(100, 'header-copy', layout) == [0, 0, 0, 1]
    assert native.copy_counts(101, 'output-copy', layout) == [1, 0, 0, 1]
    good = dict(comparisons=53, lane_comparisons=212, calls=[{}]*318, deleted=True,
        production_qualified=False, private_worker_enclave_execution=True, multi_message_simd=True)
    native.validate_completion(good)
    for key, value in dict(comparisons=52, lane_comparisons=208, calls=[{}]*317, deleted=False,
        production_qualified=True, private_worker_enclave_execution=False, multi_message_simd=False).items():
        bad = copy.deepcopy(good); bad[key] = value
        rejected(lambda: native.validate_completion(bad))
    print('Keccak SIMD capture: 52 four-lane encodings, sparse copy receipts and 7 completeness regressions PASS')


if __name__ == '__main__':
    main()
