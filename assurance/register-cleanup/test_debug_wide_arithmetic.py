#!/usr/bin/env python3
"""Focused 64/128-bit descriptor arithmetic and constant-layout regressions."""
import debug_write_model as model


def arithmetic(bits, op, flag, a, b):
    body = f'''define i{bits} @entry(i{bits} %a, i{bits} %b) {{
start:
  %result = {op}{flag} i{bits} %a, %b
  ret i{bits} %result
}}'''
    machine = model.Model({'entry': (model.parameters(body), model.blocks(body))}, '', '')
    return machine.run('entry', [a, b])


def main():
    good = rejected = 0
    for bits in (64, 128):
        limit = (1 << bits) - 1
        values = (0, 1, (1 << (bits - 1)) - 1, 1 << (bits - 1), limit - 1, limit)
        for a in values:
            for b in values:
                machine = model.Model({}, '', '')
                assert machine.run(f'llvm.uadd.with.overflow.i{bits}', [a, b]) == ((a + b) & limit, int(a + b > limit))
                good += 1
                for op in ('add', 'sub'):
                    total = a + b if op == 'add' else a - b
                    assert arithmetic(bits, op, '', a, b) == total & limit
                    good += 1
                    if 0 <= total <= limit:
                        assert arithmetic(bits, op, ' nuw', a, b) == total
                        good += 1
                    else:
                        try:
                            arithmetic(bits, op, ' nuw', a, b)
                        except ValueError:
                            rejected += 1
                        else:
                            raise AssertionError('poison arithmetic accepted')
        for args in ([0], [0, 1, 2], [-1, 0], [limit + 1, 0], [0, model.UNKNOWN]):
            try:
                model.Model({}, '', '').run(f'llvm.uadd.with.overflow.i{bits}', args)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid intrinsic operands accepted')
    for width in (8, 16):
        definition = f'@anon.none = private unnamed_addr constant <{{ [{width} x i8], [{width} x i8] }}> <{{ [{width} x i8] zeroinitializer, [{width} x i8] undef }}>, align {width}'
        machine = model.Model({}, definition, '')
        assert machine.load(model.Pointer('@anon.none'), width) == 0
        assert machine.load(model.Pointer('@anon.none', width), width) is model.UNKNOWN
        assert machine.sizes['@anon.none'] == width * 2
        good += 1
        for pointer, size in ((model.Pointer('@anon.none'), width // 2), (model.Pointer('@anon.none', width * 2), width)):
            try:
                machine.load(pointer, size)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('wrong-width/out-of-range global access accepted')
        try:
            machine.store(model.Pointer('@anon.none'), width, 1)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('write to constant accepted')
    assert (good, rejected) == (302, 76)
    print(f'Wide metadata model: {good} arithmetic/constant controls and {rejected} poison/arity/range/readonly rejections PASS')


if __name__ == '__main__':
    main()
