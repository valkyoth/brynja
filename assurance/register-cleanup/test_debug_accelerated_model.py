#!/usr/bin/env python3
"""Check accelerated composition boundary assumptions without captured payloads."""
import check_debug_accelerated_operation as check

model = check.model


def fixture():
    roles = ('begin', 'clear', 'operation', 'preflight', 'slice', 'last', 'as_mut', 'subtract',
             'read', 'mask', 'copy', 'write', 'finish', 'deref', 'take', 'predicate', 'guard', 'wipe')
    names = {role: role for role in roles}
    names['success'] = 255
    machine = check.OperationModel({}, '', names, 169, 1, 7, None)
    storage = machine.allocate('storage', 1088, payload=True)
    machine.allocate('output', 169, payload=True)
    machine.guard_pointer = machine.allocate('guard-local', 16)
    machine.fields(machine.guard_pointer, [(0, 8, storage), (8, 1, 0)])
    machine.in_guard = machine.inside_operation = True
    machine.iteration, machine.chunk, machine.progress = 2, 1, 168
    machine.events.clear()
    return machine


def rejects(action):
    try:
        action()
    except ValueError:
        return 1
    raise AssertionError('accepted malformed accelerated boundary')


def main():
    pointer = model.Pointer
    good = [('preflight', [pointer('storage'), 169]),
            ('read', [pointer('storage'), pointer('storage', 864), 1]),
            ('mask', [pointer('storage', 864), 127, 0]),
            ('copy', [pointer('output', 168), pointer('storage', 864), 1])]
    for name, args in good:
        fixture().run(name, args)
    count = 0
    for name, args in good:
        for index, value in enumerate(args):
            changed = list(args)
            changed[index] = pointer(value.region, value.offset + 1) if isinstance(value, pointer) else value + 1
            count += rejects(lambda: fixture().run(name, changed))
        machine = fixture()
        machine.in_guard = False
        count += rejects(lambda: machine.run(name, args))
        machine = fixture()
        machine.store(pointer('guard-local', 8), 1, 1)
        count += rejects(lambda: machine.run(name, args))
    for value in (-1, 256, model.UNKNOWN):
        count += rejects(lambda: fixture().run('llvm.usub.sat.i8', [8, value]))
    count += rejects(lambda: fixture().run('write', [0, pointer('storage', 864), 1]))
    count += rejects(lambda: fixture().run('operation', [pointer('output'), 0, pointer('storage')]))
    for args, expected in (([8, 0], 8), ([8, 8], 0), ([8, 255], 0)):
        assert fixture().run('llvm.usub.sat.i8', args) == expected
    for ptr in (pointer('storage'), pointer('storage', 864), pointer('output')):
        count += rejects(lambda: fixture().load(ptr, 1))
        count += rejects(lambda: fixture().store(ptr, 1, 0))
    print(f'Accelerated model: seven primitive/saturation controls; {count} binding/guard/payload/width rejections')


if __name__ == '__main__':
    main()
