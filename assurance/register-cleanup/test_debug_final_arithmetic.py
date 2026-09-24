#!/usr/bin/env python3
"""Public final-bit arithmetic: exact results and rejection of poison inputs."""
import debug_write_model as model


def execute(op, bits, a, b):
    body = f'''define i{bits} @entry(i{bits} %a, i{bits} %b) {{
start:
  %result = {op} i{bits} %a, %b
  ret i{bits} %result
}}'''
    return model.Model({'entry': (model.parameters(body), model.blocks(body))}, '', '').run('entry', [a, b])


def rejects(action):
    try:
        action()
    except ValueError:
        return 1
    raise AssertionError('invalid final-bit arithmetic accepted')


def main():
    controls = rejected = 0
    maximum = (1 << 128) - 1
    values = (0, 1, 7, 8, 255, (1 << 64) - 1, maximum // 8, maximum)
    for a in values:
        for b in values:
            assert model.Model({}, '', '').run('llvm.umul.with.overflow.i128', [a, b]) == (
                (a * b) & maximum, int(a * b > maximum))
            controls += 1
            if b:
                assert execute('udiv', 128, a, b) == a // b
                controls += 1
            else:
                rejected += rejects(lambda: execute('udiv', 128, a, b))
    for a in range(256):
        for shift in range(8):
            assert execute('lshr', 8, a, shift) == a >> shift
            assert execute('shl', 8, a, shift) == (a << shift) & 255
            assert execute('and', 8, a, shift) == a & shift
            assert execute('or', 8, a, shift) == a | shift
            controls += 4
    for shift in (8, 9, 255, model.UNKNOWN, model.Pointer('invalid')):
        for op in ('lshr', 'shl'):
            rejected += rejects(lambda: execute(op, 8, 255, shift))
    for args in ([0], [0, 1, 2], [-1, 8], [maximum + 1, 8], [model.UNKNOWN, 8], [0, model.Pointer('invalid')]):
        rejected += rejects(lambda: model.Model({}, '', '').run('llvm.umul.with.overflow.i128', args))
    for args in ((model.UNKNOWN, 8), (1, model.UNKNOWN), (model.Pointer('invalid'), 8)):
        rejected += rejects(lambda: execute('udiv', 128, *args))
    assert (controls, rejected) == (8312, 27)
    print(f'Final-bit model: {controls} arithmetic controls; {rejected} invalid/poison cases rejected')


if __name__ == '__main__':
    main()
