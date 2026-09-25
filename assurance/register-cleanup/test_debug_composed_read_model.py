#!/usr/bin/env python3
"""Fail closed on wrong staging aliases and inactive composed-read boundaries."""
from debug_composed_read_model import ComposedRead, model
from test_debug_read_model import fixture as read_fixture
from test_debug_accelerated_model import rejects
import check_debug_composed_read as check


def fixture():
    machine = ComposedRead({}, '', read_fixture().names, 168, 0, model.UNKNOWN, 'producer',
                           3, 168, 0, 0, 1, None, None, None)
    machine.allocate('storage', 1088, payload=True)
    machine.allocate('output', 337, payload=True)
    machine.allocate('local-split', 32)
    machine.in_read = True
    return machine


def main():
    p = model.Pointer
    good = [('lane_copy', [p('storage', 864), 168, p('storage', 656), 168]),
            ('split', [p('local-split'), p('storage', 864), 168, 168, p('@location')])]
    for name, args in good:
        fixture().run(name, args)
    count = 0
    for name, args in good:
        for index, value in ((0, 0), (1, 0), (2, 0), (3, 169)):
            wrong = list(args)
            wrong[index] = value
            count += rejects(lambda: fixture().run(name, wrong))
        machine = fixture()
        machine.in_read = False
        count += rejects(lambda: machine.run(name, args))
    for args in ([p('output'), 168, p('storage', 656), 168],
                 [p('storage', 656), 168, p('storage', 656), 168],
                 [p('storage', 865), 168, p('storage', 656), 168],
                 [p('storage', 864), 168, p('storage', 657), 168],
                 [p('storage', 864), 167, p('storage', 656), 167]):
        count += rejects(lambda: fixture().run('lane_copy', args))
    for args in ([p('output'), p('storage', 864), 168, 168, p('@location')],
                 [p('local-split'), p('output'), 168, 168, p('@location')],
                 [p('local-split'), p('storage', 865), 168, 168, p('@location')]):
        count += rejects(lambda: fixture().run('split', args))
    for pointer, width in ((p('storage', 864), 1), (p('storage', 656), 1), (p('output'), 1)):
        count += rejects(lambda: fixture().load(pointer, width))
        count += rejects(lambda: fixture().store(pointer, width, 0))
    for name, args in (('read', [p('storage'), p('storage', 864), 168]),
                       ('preflight', [p('storage'), 168])):
        count += rejects(lambda: fixture().run(name, args))
    machine = fixture()
    machine.in_read = False
    machine.store(p('storage', 859), 1, 1)
    machine.store(p('storage', 616), 8, 0)
    assert machine.failed == 1 and machine.position == 0
    assert count == 26
    print(f'Composed read model: three controls; {count} alias/phase/width/payload failures rejected')
    faults = 0
    for consuming in (False, True):
        for scenario in check.scenarios(True, consuming):
            length, valid, counter, rate, position, failed, squeezing, session, inner, outer = scenario
            if session is None and inner is None and outer is None:
                continue
            outcome = check.expected(length, consuming, valid if consuming else model.UNKNOWN,
                                     counter, rate, position, failed, squeezing, session, inner, outer,
                                     {'session_success': 255})
            assert not outcome[2], 'fault campaign must actually reach its injected failure'
            faults += 1
    assert faults == 161
    print(f'Fault campaign oracle: all {faults} injected scenarios predict failure, none vacuous')


if __name__ == '__main__':
    main()
