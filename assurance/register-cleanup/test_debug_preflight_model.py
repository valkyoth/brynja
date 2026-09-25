#!/usr/bin/env python3
"""Focused engine metadata permissions and original preflight/session bindings."""
import check_debug_accelerated_preflight as check
from test_debug_accelerated_model import fixture as operation_fixture, rejects


def fixture():
    names = dict(operation_fixture().names, session='session', counter='counter', panics={'panic'})
    machine = check.PreflightModel({}, '', names, 169, 0, check.model.UNKNOWN, 'producer',
                                   int.from_bytes(bytes(range(16)), 'little'), 0, 1, 255, True)
    machine.allocate('storage', 1088, payload=True)
    machine.in_preflight = True
    return machine


def main():
    pointer = check.model.Pointer
    controls = count = 0
    machine = fixture()
    assert machine.load(pointer('storage', 858), 1) == 1
    assert machine.load(pointer('storage', 859), 1) == 0
    assert machine.run('session', [pointer('storage')]) == 255
    controls += 3
    machine.decoding = True
    for byte in range(16):
        assert machine.load(pointer('storage', 640 + byte), 1) == byte
        controls += 1
    assert machine.reads == list(range(16))
    machine = fixture()
    for ptr, width in ((pointer('storage'), 1), (pointer('storage', 858), 2),
                       (pointer('storage', 640), 1), (pointer('storage', 864), 1)):
        count += rejects(lambda: machine.load(ptr, width))
    for ptr, width, value in ((pointer('storage', 859), 1, 1), (pointer('storage', 616), 8, 0),
                              (pointer('storage', 640), 1, 0)):
        count += rejects(lambda: machine.store(ptr, width, value))
    machine.decoding = True
    for ptr, width in ((pointer('storage', 639), 1), (pointer('storage', 656), 1),
                       (pointer('storage', 640), 16), (pointer('storage', 858), 1)):
        count += rejects(lambda: machine.load(ptr, width))
    count += rejects(lambda: machine.run('session', [pointer('storage')]))
    machine = fixture()
    for args in ([], [0], [pointer('storage', 1)], [pointer('storage'), 169]):
        count += rejects(lambda: machine.run('session', args))
    machine.in_preflight = False
    count += rejects(lambda: machine.run('session', [pointer('storage')]))
    count += rejects(lambda: machine.load(pointer('storage', 859), 1))
    for args in ([pointer('storage', 1), 169], [pointer('storage'), 168], [0, 169]):
        count += rejects(lambda: machine.run('preflight', args))
    machine.in_preflight = True
    count += rejects(lambda: machine.run('preflight', [pointer('storage'), 169]))
    count += rejects(lambda: machine.run('counter', [pointer('storage', 624)]))
    count += rejects(lambda: machine.run('panic', []))
    assert (controls, count) == (19, 24)
    print(f'Preflight boundaries: {controls} controls; {count} payload/metadata/authority rejections')


if __name__ == '__main__':
    main()
