#!/usr/bin/env python3
"""Focused model bit operations, checked multiplication and 32-bit constants."""
import debug_write_model as model


def evaluate(op, width, a, b):
    body = f'''define i{width} @entry(i{width} %a, i{width} %b) {{
start:
  %value = {op} i{width} %a, %b
  ret i{width} %value
}}'''
    return model.Model({'entry': (model.parameters(body), model.blocks(body))}, '', '').run('entry', [a, b])


def main():
    controls = rejected = 0
    for width in (32, 128):
        mask = (1 << width) - 1
        values = (0, 1, 127, 255, 1 << (width - 1), mask)
        for a in values:
            for b in values:
                assert evaluate('and', width, a, b) == a & b
                assert evaluate('or', width, a, b) == a | b
                controls += 2
            for b in (0, 1, 7, width - 1):
                assert evaluate('shl', width, a, b) == (a << b) & mask
                controls += 1
        for op, a, b in [('shl', 1, width), ('shl', 1, -1), ('and', model.UNKNOWN, 0),
                         ('or', 0, model.UNKNOWN), ('shl', model.UNKNOWN, 0)]:
            try:
                evaluate(op, width, a, b)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid bit operation accepted')
    for a in (0, 1, 8, (1 << 29) - 1, 1 << 29, (1 << 32) - 1):
        for b in (0, 1, 8, (1 << 32) - 1):
            assert model.Model({}, '', '').run('llvm.umul.with.overflow.i32', [a, b]) == (
                (a * b) & ((1 << 32) - 1), int(a * b >= 1 << 32))
            controls += 1
    for args in ([], [1], [1, 2, 3], [-1, 0], [0, 1 << 32], [model.UNKNOWN, 1]):
        try:
            model.Model({}, '', '').run('llvm.umul.with.overflow.i32', args)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('invalid checked multiply accepted')
    for tag, initializer in ((0, 'zeroinitializer'), (1, r'c"\01\00\00\00"')):
        constant = '@anon.test = private unnamed_addr constant <{ [4 x i8], [4 x i8] }> <{ [4 x i8] ' + initializer + ', [4 x i8] undef }>, align 4'
        machine = model.Model({}, constant, '')
        assert machine.load(model.Pointer('@anon.test'), 4) == tag
        assert machine.load(model.Pointer('@anon.test', 4), 4) is model.UNKNOWN
        controls += 1
        for pointer, width in ((model.Pointer('@anon.test'), 8), (model.Pointer('@anon.test', 8), 4)):
            try:
                machine.load(pointer, width)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid constant load accepted')
        try:
            machine.store(model.Pointer('@anon.test'), 4, 0)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('constant write accepted')
    assert (controls, rejected) == (218, 22)
    print(f'Counter model operations: {controls} positive controls; {rejected} poison/operand/constant failures rejected')


if __name__ == '__main__':
    main()
