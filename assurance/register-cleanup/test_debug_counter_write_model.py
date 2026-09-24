#!/usr/bin/env python3
"""Writer-model logical shifts, byte constants and exact mutation boundaries."""
import check_debug_counter_write as check
from test_debug_counter_operations import evaluate

model = check.model


def rejects(action):
    try:
        action()
    except ValueError:
        return 1
    raise AssertionError('invalid writer-model operation accepted')


def main():
    controls = rejected = 0
    for width in (32, 128):
        mask = (1 << width) - 1
        for value in (0, 1, 255, 1 << (width - 1), mask):
            for shift in (0, 1, 7, width - 1):
                assert evaluate('lshr', width, value, shift) == value >> shift
                controls += 1
        for value, shift in ((1, width), (1, -1), (model.UNKNOWN, 0), (0, model.UNKNOWN)):
            rejected += rejects(lambda: evaluate('lshr', width, value, shift))
    for tag, initializer in ((0, 'zeroinitializer'), (1, r'c"\01"')):
        constant = '@anon.test = private unnamed_addr constant <{ [1 x i8], [1 x i8] }> <{ [1 x i8] ' + initializer + ', [1 x i8] undef }>, align 1'
        machine = model.Model({}, constant, '')
        assert machine.load(model.Pointer('@anon.test'), 1) == tag
        assert machine.load(model.Pointer('@anon.test', 1), 1) is model.UNKNOWN
        controls += 1
        rejected += rejects(lambda: machine.load(model.Pointer('@anon.test'), 2))
        rejected += rejects(lambda: machine.load(model.Pointer('@anon.test', 2), 1))
        rejected += rejects(lambda: machine.store(model.Pointer('@anon.test'), 1, 0))
        wrong = constant.replace(initializer, r'c"\01\00\00\00"')
        rejected += rejects(lambda: model.Model({}, wrong, ''))
    machine = check.WriterModel({}, '', {'writer': 'write', 'counter': 'read', 'panics': set()}, 0)
    machine.allocate('storage', 1040, payload=True)
    rejected += rejects(lambda: machine.store(model.Pointer('storage', 16), 1, 1))
    machine.writing = True
    for offset, width, value in ((15, 1, 1), (32, 1, 1), (16, 8, 1), (16, 1, -1), (16, 1, 256), (16, 1, model.UNKNOWN)):
        previous = bytes(machine.counter_bytes)
        rejected += rejects(lambda: machine.store(model.Pointer('storage', offset), width, value))
        assert bytes(machine.counter_bytes) == previous and not machine.writes
    rejected += rejects(lambda: machine.load(model.Pointer('storage', 16), 1))
    for offset in range(16):
        machine.store(model.Pointer('storage', 16 + offset), 1, 255 - offset)
    assert machine.writes == [(offset, 255 - offset) for offset in range(16)]
    assert list(machine.counter_bytes) == list(range(255, 239, -1))
    controls += 1
    machine.writing = False
    for args in ([model.Pointer('storage'), 0], [model.Pointer('storage', 16), -1],
                 [model.Pointer('storage', 16), 1 << 128], [model.Pointer('storage', 16)],
                 [model.Pointer('storage', 16), model.UNKNOWN]):
        rejected += rejects(lambda: machine.run('write', args))
    assert (controls, rejected) == (43, 29)
    print(f'Counter writer model: {controls} shift/constant/exact-write controls; {rejected} poison/constant/boundary rejections')


if __name__ == '__main__':
    main()
