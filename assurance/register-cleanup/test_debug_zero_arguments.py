#!/usr/bin/env python3
"""Zero-argument retained-LLVM parser/execution regressions; no compiler needed."""
import debug_write_model as model


LEAF = '''define internal i8 @leaf() {
start:
  ret i8 2
}'''
CALL = '''define internal i8 @entry() {
start:
  %result = call i8 @leaf()
  ret i8 %result
}'''
INVOKE = '''define internal i8 @entry() personality ptr @rust_eh_personality {
start:
  %result = invoke i8 @leaf()
          to label %done unwind label %failure
done:
  ret i8 %result
failure:
  %error = landingpad { ptr, i32 }
          cleanup
  resume { ptr, i32 } %error
}'''


def run(leaf, entry, args=(), unwind=False):
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in (('leaf', leaf), ('entry', entry))}
    class Machine(model.Model):
        def run(self, name, arguments, depth=0):
            if name == 'leaf' and unwind:
                assert arguments == []
                raise model.Unwind((model.Pointer('exception', 7), 19))
            return super().run(name, arguments, depth)
    return Machine(functions, '', '').run('entry', list(args))


def main():
    for entry in (CALL, INVOKE):
        assert run(LEAF, entry) == 2
        assert run(LEAF.replace('@leaf()', '@leaf( )'), entry.replace('@leaf()', '@leaf( )')) == 2
        assert run(LEAF.replace('@leaf()', '@leaf(i8 %value)'), entry.replace('@leaf()', '@leaf(i8 3)')) == 2
        try:
            run(LEAF, entry, unwind=True)
        except model.Unwind as error:
            assert error.value == (model.Pointer('exception', 7), 19)
        else:
            raise AssertionError('zero-argument unwind swallowed')
    rejected = 0
    for entry in (CALL, INVOKE):
        for leaf, call, args in (
            (LEAF, entry, (1,)),
            (LEAF, entry.replace('@leaf()', '@leaf(i8 1)'), ()),
            (LEAF.replace('@leaf()', '@leaf(i8 %value)'), entry, ()),
            (LEAF, entry.replace('@leaf()', '@leaf(i8 1,)'), ()),
            (LEAF, entry.replace('@leaf()', '@leaf(,i8 1)'), ()),
            (LEAF, entry.replace('@leaf()', '@leaf(,)'), ()),
            (LEAF.replace('@leaf()', '@leaf(,)'), entry, ()),
        ):
            try:
                run(leaf, call, args)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('malformed/mismatched argument list accepted')
    assert rejected == 14
    print('Zero-argument model: 8 normal/whitespace/parameter/unwind controls and 14 malformed/arity rejections PASS')


if __name__ == '__main__':
    main()
