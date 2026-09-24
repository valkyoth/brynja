#!/usr/bin/env python3
"""Keep packed result fields precise without inventing initialized ABI padding."""
import check_debug_counter_decode as check

model = check.model


def main():
    controls = rejected = 0
    for fields in (((0, 1, 0), (4, 4, 0)), ((0, 1, 0), (4, 4, (1 << 32) - 1)),
                   ((0, 1, 1), (1, 1, 2))):
        machine = check.CounterModel({}, '', {}, 0)
        source = machine.allocate('1:source', 8)
        dest = machine.allocate('2:destination', 8)
        other = machine.allocate('3:copy', 8)
        machine.fields(source, fields)
        packed = machine.load(source, 8)
        assert isinstance(packed, check.PackedResult) and set(packed.fields) == set(fields)
        machine.store(dest, 8, packed)
        machine.run('llvm.memcpy.p0.p0.i64', [other, dest, 8, 0])
        for ptr in (source, dest, other):
            for offset, width, value in fields:
                assert machine.load(model.Pointer(ptr.region, offset), width) == value
            assert machine.load(model.Pointer(ptr.region, 2), 1) is model.UNKNOWN
            assert set(machine.load(ptr, 8).fields) == set(fields)
            controls += 1
        for ptr, width in ((source, 4), (model.Pointer(source.region, 4), 8)):
            try:
                machine.load(ptr, width)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid packed read accepted')
        for ptr, width in ((dest, 4), (machine.allocate('output', 8), 8)):
            try:
                machine.store(ptr, width, packed)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid packed store accepted')
        for args in ([dest, dest, 8, 0], [other, source, 8, 1], [other, model.Pointer('output'), 8, 0]):
            try:
                machine.run('llvm.memcpy.p0.p0.i64', args)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid packed copy accepted')
        body = '''define i64 @entry(i64 %value) {
start:
  %result = add i64 %value, 0
  ret i64 %result
}'''
        machine.functions['entry'] = (model.parameters(body), model.blocks(body))
        try:
            model.Model.run(machine, 'entry', [packed])
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('arithmetic on unknown padding accepted')
    assert (controls, rejected) == (9, 24)
    print(f'Counter ABI packing: {controls} field/padding round-trip controls; {rejected} width/escape/copy/arithmetic failures rejected')


if __name__ == '__main__':
    main()
