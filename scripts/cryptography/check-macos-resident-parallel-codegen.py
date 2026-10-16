#!/usr/bin/env python3
"""Bounded Darwin ParallelHash compiler checks, not whole-image erasure proof.

Run on release artifacts with macos-resident-acceleration and +neon,+sha3,
separately for panic=abort/unwind. Native fault/concurrency tests establish
join-before-clear control flow; this checks retained calls and opaque kernels.
"""
import argparse
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('resident_batch_codegen',
    Path(__file__).with_name('check-macos-resident-batch-codegen.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
require, function, machine = shared.require, shared.function, shared.machine


def population(llvm, tokens, count):
    found = [body for body in re.findall(r'^define .*?^}', llvm, re.M | re.S)
             if all(t in body.splitlines()[0] for t in ('macos_resident', *tokens))]
    require(len(found) == count, 'exact compiler population: ' + repr(tokens))
    return found


def inspect(llvm, assembly, cpu, sha3, *, panic):
    require('target triple = "arm64-apple-macosx' in llvm, 'native Darwin target')
    admission = function(llvm, 'macos_resident', '7Mapping3new')
    for call in ('@mmap(', '@mach_vm_inherit(', '@mprotect(', '@mlock('):
        require(call in admission, 'mapping admission: ' + call)
    require(re.search(r'@mach_vm_inherit\([^\n]*i32 noundef 2\)', admission), 'VM_INHERIT_NONE')
    release = function(llvm, 'macos_resident', '7Mapping', '4Drop4drop')
    require('clear_owned_region' in release and '@munmap(' in release
            and release.index('clear_owned_region') < release.index('@munmap('),
            'mapping clear precedes release textually; native tests cover control flow')
    for group in population(llvm, ('group', '8join_all'), 6):
        for token in ('@pthread_join(', 'clear_owned_region', 'abort'):
            require(token in group, 'join/clear/fail-stop group boundary: ' + token)
        symbol = re.search(r'@([^ (]+)\(', group.splitlines()[0])[1]
        code = machine(assembly, symbol)
        for token in ('_pthread_join', 'clear_owned_region', 'abort'):
            require(re.search(r'\b(?:bl|b)\s+\S*' + token, code), 'machine group boundary: ' + token)
    # LLVM inlines joins into drop glue; four abort-profile glue instances are
    # additionally inlined at their callers. This is the observed exact shape,
    # not an assertion that abort executes unwind destructors.
    unwind = panic == 'unwind'
    for drop in population(llvm, ('drop_glue', 'group', '5Group'), 6 if unwind else 2):
        for token in ('@pthread_join(', 'clear_owned_region', 'abort'):
            require(token in drop, 'partial-launch/unwind destructor boundary: ' + token)
    for worker in population(llvm, ('thread5enter',), 15):
        require('ret ptr null' in worker, 'worker exports no result value')
        header = worker.splitlines()[0]
        if '8compiled' in header and '3run0' not in header:
            require('Authority3new' in worker or 'Authority19for_compiled_target' in worker,
                    'worker-local acceleration admission')
    for root in population(llvm, ('@_RNvM', '7compute'), 2):
        calls = '\n'.join(line for line in root.splitlines()
                          if not line.lstrip().startswith(';') and re.search(r'\b(call|invoke)\b', line))
        require(not re.search(r'@\S*(?:Workspace3new|Authority3new|for_compiled_target)', calls),
                'no coordinator state/authority construction')
        require('clear_owned_region' in calls, 'coordinator cleanup retained')
    for owner in ('7Buffers', '6Output'):
        require('clear_owned_region' in function(llvm, 'macos_resident', owner, '4Drop4drop'),
                'affine owner cleanup retained')
    # The dependency emits two unrelated SHA-2 kernels as well. Inventory all
    # four rather than call them ParallelHash execution evidence.
    require(cpu.count('BRYNJA_SECRET_BEGIN') == 4, 'exact emitted CPU kernel inventory')
    for family, registers, vectors, first in (
        ('aarch64_sha29secret256', (4, 5, 6, 7, 9), range(6), False),
        ('aarch64_sha29secret512', (4, 5, 6, 7, 9), (*range(8), *range(16, 21)), False),
        ('aarch64_sha3_keccak6secret', (4, 5, 6, 7, 9), range(4), False),
        ('keccak_hardened_batch3arm6secret', range(4, 7), range(4), True),
    ):
        names = re.findall(r'^(__R[^\n:]*' + family + r'[^\n:]*):$', cpu, re.M)
        require(len(names) == 1, 'exact kernel: ' + family)
        shared.kernels_check(machine(cpu, names[0][1:]), 'SECRET', 1, registers, vectors, first)
    shared.kernels_check(cpu, 'TRANSFER', 2, range(4, 8))
    shared.kernels_check(sha3, 'SCALAR', 1, range(4, 11))


def regressions(texts, panic):
    count = 0
    for index, old, new in (
        (0, '@mlock(', '@removed_lock('), (0, '@mach_vm_inherit(', '@removed_inherit('),
        (0, '@pthread_join(', '@removed_join('), (0, '8join_all', '8removed_'),
        (0, 'ret ptr null', 'ret ptr %secret'), (0, 'clear_owned_region', 'removed_clear'),
        (0, 'for_compiled_target', 'removed_admission'), (0, 'Authority3new', 'removed_admission'),
        (0, 'abort', 'removed_stop'),
        (1, '_pthread_join', '_removed_join'), (1, 'clear_owned_region', 'removed_clear'),
        (2, 'BRYNJA_REGISTER_ERASE', 'removed_erase'),
        (2, 'BRYNJA_SECRET_BEGIN', 'BRYNJA_SECRET_BEGIN\n\tstr x5, [sp]'),
        (2, 'mov\tx5, xzr', 'mov\tx5, x4'), (3, 'BRYNJA_SCALAR_ERASE', 'removed_scalar'),
    ):
        changed = list(texts)
        changed[index] = changed[index].replace(old, new)
        require(changed != texts, 'mutation anchor present')
        try:
            inspect(*changed, panic=panic)
        except ValueError:
            count += 1
        else:
            raise ValueError('ParallelHash compiler mutant survived: ' + old)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('--panic', choices=('abort', 'unwind'), required=True)
    args = parser.parse_args()
    texts = []
    for pattern in ('brynja_hash_parallel_std-*.ll', 'brynja_hash_parallel_std-*.s',
                    'brynja_crypto_cpu-*.s', 'brynja_hash_sha3-*.s'):
        paths = list(args.artifacts.glob(pattern))
        require(len(paths) == 1, 'exact artifact: ' + pattern)
        texts.append(paths[0].read_text())
    inspect(*texts, panic=args.panic)
    count = regressions(texts, args.panic)
    print(f'Darwin resident ParallelHash: 15 workers, 6 join groups, 7 emitted opaque blocks; '
          f'{count} artifact mutants rejected; bounded scope PASS')


if __name__ == '__main__':
    main()
