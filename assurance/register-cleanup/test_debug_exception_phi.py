#!/usr/bin/env python3
"""Bound exception-phi interpretation to the actual predecessor and identity."""
from copy import deepcopy

import debug_write_model as model


GRAPH = {
    'start': ['br i1 %which, label %left, label %right'],
    'left': ['invoke void @first()', 'to label %done unwind label %left_cleanup'],
    'right': ['invoke void @second()', 'to label %done unwind label %right_cleanup'],
    'left_cleanup': ['%a = landingpad { ptr, i32 }', 'cleanup', 'br label %merge'],
    'right_cleanup': ['%b = landingpad { ptr, i32 }', 'cleanup', 'br label %merge'],
    'merge': ['%joined = phi { ptr, i32 } [ %a, %left_cleanup ], [ %b, %right_cleanup ]',
              'resume { ptr, i32 } %joined'],
    'done': ['ret void'],
}


class Machine(model.Model):
    def __init__(self, graph, throws):
        super().__init__({'root': (['%which'], graph)}, '', '')
        self.throws = throws

    def run(self, name, args, depth=0):
        if name in ('first', 'second'):
            assert args == []
            if self.throws:
                raise model.Unwind((model.Pointer(name, 7), 19 if name == 'first' else 23))
            return None
        return super().run(name, args, depth)


def check(graph, which, throws=True):
    machine = Machine(graph, throws)
    try:
        machine.run('root', [which])
    except model.Unwind as error:
        assert throws
        assert error.value == (model.Pointer('first' if which else 'second', 7), 19 if which else 23)
    else:
        assert not throws


def main():
    for which in (0, 1):
        for throws in (False, True):
            check(GRAPH, which, throws)
    phi = GRAPH['merge'][0]
    broken = [
        phi.replace('%a, %left_cleanup', '%b, %left_cleanup'),
        phi.replace('%b, %right_cleanup', '%a, %right_cleanup'),
        phi.replace('%right_cleanup', '%left_cleanup'),
        phi.replace('%left_cleanup', '%absent'),
        phi.replace('[ %a, %left_cleanup ], ', ''),
        phi.replace(', [ %b, %right_cleanup ]', ''),
        phi.replace('%a,', '%which,'),
        phi.replace(' ], [', ' ], junk ['),
    ]
    count = 0
    for mutant in broken:
        graph = deepcopy(GRAPH)
        graph['merge'][0] = mutant
        rejected = False
        for which in (0, 1):
            try:
                check(graph, which)
            except (ValueError, AssertionError):
                rejected = True
        assert rejected, mutant
        count += 1
    graph = deepcopy(GRAPH)
    graph['start'] = GRAPH['merge']
    try:
        check(graph, 1)
    except ValueError:
        count += 1
    else:
        raise AssertionError('entry phi has no predecessor')
    print(f'Exception phi: four normal/unwind controls; {count} predecessor/identity/syntax regressions rejected')


if __name__ == '__main__':
    main()
