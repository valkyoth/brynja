#!/usr/bin/env python3
"""Reject malformed synthetic squeeze boundary calls and arithmetic operands."""
import check_debug_squeeze_operation as check

model = check.model


def rejects(action):
    try:
        action()
    except ValueError:
        return 1
    raise AssertionError('invalid squeeze-model boundary accepted')


def main():
    names = dict(squeeze='squeeze', fill='fill', staging_get='slice', copy='copy',
                 output_write='write', writer='counter-write', counter='counter-read',
                 panics=set(), rate=168, success=255)
    machine = check.SqueezeModel({}, '', names, 0, 169)
    machine.allocate('storage', 1040, payload=True)
    owner = machine.allocate('owner', 24)
    destination = machine.allocate('output', 169, payload=True)
    machine.fields(owner, [(0, 8, destination), (8, 8, 169), (16, 8, 0)])
    controls = rejected = 0
    for first in (0, 1, 168, model.MASK):
        for second in (0, 1, 168, model.MASK):
            assert machine.run('llvm.usub.sat.i64', [first, second]) == max(0, first - second)
            controls += 1
    for args in ([0], [0, -1], [model.MASK + 1, 0], [model.UNKNOWN, 0], [0, model.Pointer('storage')]):
        rejected += rejects(lambda: machine.run('llvm.usub.sat.i64', args))
    for args in ([model.Pointer('storage'), 0], [model.Pointer('storage'), 169],
                 [model.Pointer('storage', 1), 1], [model.Pointer('storage'), model.UNKNOWN],
                 [model.Pointer('storage')]):
        rejected += rejects(lambda: machine.run('fill', args))
    assert machine.run('fill', [model.Pointer('storage'), 168]) == 255
    controls += 1
    for args in ([destination, model.Pointer('storage', 585), 168],
                 [model.Pointer('output', 1), model.Pointer('storage', 584), 168],
                 [destination, model.Pointer('storage', 584), 167], [destination]):
        rejected += rejects(lambda: machine.run('copy', args))
    assert machine.run('copy', [destination, model.Pointer('storage', 584), 168]) is None
    controls += 1
    for args in ([model.Pointer('storage', 1), owner, 169], [model.Pointer('storage'), owner, 168],
                 [model.Pointer('storage'), destination, 169]):
        rejected += rejects(lambda: machine.run('squeeze', args))
    assert (controls, rejected) == (18, 17)
    print(f'Squeeze model: {controls} saturation/boundary controls; {rejected} malformed calls rejected')


if __name__ == '__main__':
    main()
