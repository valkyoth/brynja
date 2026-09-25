#!/usr/bin/env python3
"""Retained static Keccak session authority, dispatch and cleanup guards."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_keccak_session_model import Case, SessionModel, cases, closure, comparison, model, require, REGIONS


def compiled(case, kernel, success):
    if kernel in ((0, 1, 4) if case.arm else (2, 3, 5)):
        return 0
    if not case.arm and kernel in (0, 1):
        return 1
    return success  # Retained flags: x86 +avx2; Arm +neon,+sha2,+sha3.


def expected(case, permute, kernel, health, owner_generation, session_generation, result, revocation, success):
    events = [('authority',)]
    effective = 2 if revocation == 1 else health
    error = (3 if effective == 0 else 4 if effective == 2 else 5 if owner_generation != session_generation
             else compiled(case, kernel, success))
    if error == success and kernel not in (4, 5):
        error = 2
    if error != success or not permute:
        return error, events, False, effective, owner_generation
    events.append(('authority',))
    if revocation == 2:
        return 4, events, False, 2, owner_generation
    events += [('kernel',)] + [('wipe', *region) for region in REGIONS]
    if result != success:
        events += [('quarantine',), ('authority-store', 8, 1, 2), ('authority-store', 0, 8, 3)]
        return result, events, result == 'unwind', 2, 3
    return success, events, False, health, owner_generation


def scenarios(case, success):
    native = 5 if case.arm else 4
    for kernel in range(6):
        for health in range(3):
            for owner, borrowed in ((2, 2), (2, 1), (0, 0), (model.MASK, model.MASK), (0, model.MASK)):
                yield kernel, health, owner, borrowed, success, None
    for result in (*range(7), 'unwind'):
        yield native, 1, 2, 2, result, None
    for at in (1, 2):
        yield native, 1, 2, 2, success, at


def inspect(case):
    names, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.cpu, case.core) for line in text.splitlines()
                                      if line.startswith(('@anon.', '@alloc_'))))
    count, visited = 0, set()
    for permute in (False, True):
        for scenario in scenarios(case, names['success']):
            machine = SessionModel(functions, constants, names, *scenario)
            args = [model.Pointer('session')] + ([model.Pointer('state')] if permute else [])
            unwound, returned = False, None
            try:
                returned = machine.run(names['permute' if permute else 'check'], args)
            except model.Unwind as exception:
                require(exception.value == machine.exception, 'original kernel exception identity')
                unwound = True
            error, events, unwind, health, generation = expected(case, permute, *scenario, names['success'])
            require(machine.events == events and unwound == unwind and (unwound or returned == error),
                    'exact authority/kernel/cleanup/result sequence: ' + repr((permute, scenario, machine.events, returned)))
            require(machine.load(model.Pointer('authority', 8), 1) == health and machine.load(machine.owner, 8) == generation,
                    'terminal owner state and exact generation')
            if ('quarantine',) in events:
                machine.events.clear()
                machine.run(names['quarantine'], [machine.owner])
                require(machine.events == [('quarantine',)], 'repeated quarantine is idempotent')
                machine.events.clear()
                require(machine.run(names['check'], [model.Pointer('session')]) == 4
                        and machine.events == [('authority',)], 'revoked authority cannot reenter')
            visited.update(machine.visited)
            count += 1
    for role in ('check', 'permute', 'authority', 'quarantine', 'scratch'):
        name = names[role]
        graph = functions[name][1]
        live = {block for block, lines in graph.items() if lines != ['unreachable'] and block != 'terminate'}
        reached = {block for function, block in visited if function == name}
        omitted = live - reached
        if role == 'check' and not case.arm:
            # This retained +avx2 build admits only X86Keccak: other same-arch
            # kernels fail their feature check before WrongOperation is reachable.
            require(len(omitted) == 1 and any('store i8 2,' in line for line in graph[next(iter(omitted))]),
                    'only compile-time-ineligible wrong-operation branch omitted')
        else:
            require(not omitted, 'all non-abort root blocks visited: ' + role + repr(omitted))
    return count, len(selected), visited


def main(record):
    before = comparison.capture.sources()
    builds = count = 0
    for case in cases(record):
        current, functions, _ = inspect(case)
        count += current
        builds += 1
        print(f'Static Keccak session: {case.compiler}; arm={case.arm}; {current} cases; {functions} functions PASS', flush=True)
    require(builds == 4 and before == comparison.capture.sources(), 'four unchanged retained static builds')
    print(f'Static session matrix: {count} cases PASS; source-bound to SHA-3 imported identities')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Kernel and volatile payloads opaque; static-only; no caller composition or whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
