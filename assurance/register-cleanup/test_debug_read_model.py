#!/usr/bin/env python3
"""Bound read-model primitive calls and counter/metadata mutation permissions."""
import debug_accelerated_read_model as read
from test_debug_preflight_model import fixture as preflight_fixture
from test_debug_accelerated_model import rejects


def fixture():
    names = dict(preflight_fixture().names, writer='writer', permutation='permutation', lane_copy='lane_copy',
                 split='split', lane_get='lane_get', end_add='end_add', copy_success=255, session_success=255)
    machine = read.ReadModel({}, '', names, 169, 7, 168, 0, 0, 1, 255, None)
    machine.allocate('storage', 1088, payload=True)
    machine.allocate('output', 169, payload=True)
    machine.allocate('local-split', 32)
    machine.in_read = True
    return machine


def main():
    pointer = read.model.Pointer
    good = [('permutation', [pointer('storage'), pointer('storage', 656)]),
            ('lane_copy', [pointer('output'), 168, pointer('storage', 656), 168]),
            ('split', [pointer('local-split'), pointer('output'), 169, 168, pointer('@location')]),
            ('wipe', [pointer('storage', 656), 200])]
    for name, args in good:
        fixture().run(name, args)
    count = 0
    for name, args in good:
        machine = fixture()
        machine.in_read = False
        count += rejects(lambda: machine.run(name, args))
    for name, args in [('permutation', [0, pointer('storage', 656)]),
                       ('permutation', [pointer('storage'), pointer('storage', 657)]),
                       ('lane_copy', [pointer('output', 1), 168, pointer('storage', 656), 168]),
                       ('lane_copy', [pointer('output'), 168, pointer('storage', 656), 167]),
                       ('lane_copy', [pointer('output'), 169, pointer('storage', 656), 169]),
                       ('split', [0, pointer('output'), 169, 168, pointer('@location')]),
                       ('split', [pointer('local-split'), pointer('output'), 169, 170, pointer('@location')]),
                       ('split', [pointer('output'), pointer('output'), 169, 168, pointer('@location')]),
                       ('wipe', [0, 200]), ('wipe', [pointer('output'), 169]),
                       ('writer', []), ('writer', [pointer('storage', 624), 0])]:
        count += rejects(lambda: fixture().run(name, args))
    for ptr, width in ((pointer('storage', 656), 1), (pointer('output'), 1),
                       (pointer('storage', 640), 16), (pointer('storage', 608), 1)):
        count += rejects(lambda: fixture().load(ptr, width))
    for ptr, width, value in ((pointer('storage', 608), 8, 136), (pointer('storage', 858), 1, 0),
                              (pointer('storage', 640), 1, 0), (pointer('output'), 1, 0), (0, 1, 0)):
        count += rejects(lambda: fixture().store(ptr, width, value))
    machine = fixture()
    machine.writing = True
    for ptr, width, value in ((pointer('storage', 639), 1, 0), (pointer('storage', 656), 1, 0),
                              (pointer('storage', 640), 16, 0), (pointer('storage', 640), 1, 256)):
        count += rejects(lambda: machine.store(ptr, width, value))
    assert count == 29
    print(f'Engine read model: four primitive controls; {count} pointer/width/phase/payload rejections')


if __name__ == '__main__':
    main()
