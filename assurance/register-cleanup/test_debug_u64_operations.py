#!/usr/bin/env python3
"""Focused unsigned-64 bit operations and checked multiplication semantics."""
import debug_write_model as model
from test_debug_counter_operations import evaluate


def main():
    controls = rejected = 0
    for a in (0, 1, 127, 255, 1 << 63, model.MASK):
        for b in (0, 1, 127, 255, 1 << 63, model.MASK):
            assert evaluate('and', 64, a, b) == a & b
            assert evaluate('or', 64, a, b) == a | b
            assert model.Model({}, '', '').run('llvm.umul.with.overflow.i64', [a, b]) == (
                (a * b) & model.MASK, int(a * b > model.MASK))
            controls += 3
        for b in (0, 1, 7, 63):
            assert evaluate('shl', 64, a, b) == (a << b) & model.MASK
            assert evaluate('lshr', 64, a, b) == a >> b
            controls += 2
    for op, a, b in [('shl', 1, 64), ('lshr', 1, 64), ('shl', 1, -1), ('lshr', 1, -1),
                     ('and', model.UNKNOWN, 0), ('or', 0, model.UNKNOWN), ('shl', model.UNKNOWN, 0)]:
        try:
            evaluate(op, 64, a, b)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('invalid unsigned-64 bit operation accepted')
    for args in ([], [1], [1, 2, 3], [-1, 0], [0, 1 << 64], [model.UNKNOWN, 1], [True, 1]):
        try:
            model.Model({}, '', '').run('llvm.umul.with.overflow.i64', args)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('invalid checked u64 multiplication accepted')
    assert (controls, rejected) == (156, 14)
    print(f'Unsigned-64 operations: {controls} controls; {rejected} poison/width/operand failures rejected')


if __name__ == '__main__':
    main()
