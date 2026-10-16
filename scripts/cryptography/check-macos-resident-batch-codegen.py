#!/usr/bin/env python3
"""Bounded resident batch Darwin compiler checks; NOT whole-image erasure.

Inspect release artifacts built with only macos-resident-batch and +neon,
separately for panic=abort/unwind. Native lifecycle tests cover conditional
cleanup and placement; these checks cover retained calls and opaque erase tails.
"""
import argparse
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('resident_codegen',
    Path(__file__).with_name('check-macos-resident-codegen.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
function, machine, require = shared.function, shared.machine, shared.require


def kernels_check(text, kind, count, registers, vectors=(), general_first=False):
    begin, end = f'BRYNJA_{kind}_BEGIN', f'BRYNJA_{kind}_END'
    erase = 'BRYNJA_REGISTER_ERASE' if kind == 'SECRET' else f'BRYNJA_{kind}_ERASE'
    require(text.count(begin) == text.count(end) == text.count(erase) == count,
            'exact opaque population: ' + kind)
    for block in re.findall(begin + r'(.*?)' + end, text, re.S):
        require(not re.search(r'\b(?:sp|wsp)\b|\b(?:bl|blr)\b', block), 'no opaque stack/call')
        body, tail = block.split(erase)
        require(body.strip(), 'nonempty computation')
        general = [f'mov x{n}, xzr' for n in registers]
        vector = [f'movi.16b v{n}, #0' for n in vectors]
        expected = (general + vector if general_first else vector + general) + ['cmp xzr, xzr']
        actual = [' '.join(line.split()) for line in tail.splitlines() if line.strip() and line.strip() != ';']
        require(actual == expected, 'exact opaque erase tail')


def inspect(llvm, assembly, cpu, sha2, sha3):
    require('target triple = "arm64-apple-macosx' in llvm, 'Darwin Arm artifact')
    admission = function(llvm, 'macos_resident', '7Mapping3new')
    for call in ('@mmap(', '@mach_vm_inherit(', '@mprotect(', '@mlock('):
        require(call in admission, 'retained resource admission: ' + call)
    require(re.search(r'@mach_vm_inherit\([^\n]*i32 noundef 2\)', admission), 'VM_INHERIT_NONE')
    release = function(llvm, 'macos_resident', '7Mapping', '4Drop4drop')
    require('clear_owned_region' in release and '@munmap(' in release
            and release.index('clear_owned_region') < release.index('@munmap('),
            'clear precedes release textually; native tests cover paths')
    for method in ('7Session3new', '7Session6digest'):
        root = function(llvm, '@_RNvM', 'macos_resident', '5batch', method)
        shared.attribute_setup(llvm, assembly, root)
        for call in ('@pthread_create(', '@pthread_join('):
            require(call in root, 'retained coordinator call: ' + call)
        require('clear_owned_region' in root[root.index('@pthread_join('):], 'post-join stack clear')
        calls = '\n'.join(line for line in root.splitlines() if not line.lstrip().startswith(';')
                          and re.search(r'\b(call|invoke)\b', line))
        require(not re.search(r'@\S*(?:Workspace3new|for_compiled_target|digest_secret)', calls),
                'no coordinator computation/authority construction')
        symbol = re.search(r'@([^ (]+)\(', root.splitlines()[0])[1]
        code = machine(assembly, symbol)
        for call in ('_pthread_create', '_pthread_join', 'clear_owned_region'):
            require(re.search(r'\b(?:bl|b)\s+\S*' + call, code), 'machine coordinator: ' + call)
        worker = function(llvm, 'macos_resident', 'thread5enter', '5batch', method + '0')
        require('ret ptr null' in worker, 'no worker secret return value')
        for family in ('sha256_hardened_batch', 'sha512_hardened_batch', 'keccak_hardened_batch'):
            require(re.search(r'@\S*' + family + r'\S*Authority19for_compiled_target\(', worker),
                    'worker performs required authority admission')
        if 'digest' in method:
            for crate, family in (('brynja_hash_sha2', '14hardened_batch'),
                                  ('brynja_hash_sha2', '17hardened_batch512'),
                                  ('brynja_hash_sha3', '14hardened_batch')):
                for token in ('Workspace3new', 'digest_secret'):
                    require(re.search(r'@\S*' + crate + family + r'\S*' + token + r'\(', worker),
                            'worker owns every family workspace/dispatch')
    for owner in ('7Buffers', '6Output'):
        body = function(llvm, 'macos_resident', '5batch', owner, '4Drop4drop')
        require('clear_owned_region' in body, 'owner clear retained')
    require(cpu.count('BRYNJA_SECRET_BEGIN') == 3, 'exact three NEON kernels')
    for family in ('sha256', 'sha512', 'keccak'):
        names = re.findall(r'^(__R[^\n:]*' + family + r'_hardened_batch3arm6secret[^\n:]*):$', cpu, re.M)
        require(len(names) == 1, 'exact NEON symbol: ' + family)
        code = machine(cpu, names[0][1:])
        kernels_check(code, 'SECRET', 1, range(4, 7), range(4), family == 'keccak')
        require(re.search(r'^\s*ret\s*$', code.split('BRYNJA_SECRET_END')[1], re.M), 'normal kernel return')
    kernels_check(cpu, 'TRANSFER', 8, range(4, 8))
    require(sha2.count('BRYNJA_SCALAR_BEGIN') == 2, 'exact SHA2 scalar population')
    for name, registers in (('compress32', range(4, 11)), ('compress64', range(4, 12))):
        names = re.findall(r'^(__R[^\n:]*' + name + r'[^\n:]*6scalar[^\n:]*):$', sha2, re.M)
        require(len(names) == 1, 'exact scalar symbol: ' + name)
        kernels_check(machine(sha2, names[0][1:]), 'SCALAR', 1, registers)
    kernels_check(sha3, 'SCALAR', 1, range(4, 11))


def regressions(texts):
    cases = []
    for index, old, new in (
            (0, '@pthread_attr_setstack(', '@removed_stack('),
            (0, '@mlock(', '@removed_lock('), (0, '@mach_vm_inherit(', '@removed_inherit('),
            (0, '@pthread_join(', '@removed_join('), (0, 'ret ptr null', 'ret ptr %secret'),
            (0, 'clear_owned_region', 'removed_clear'), (0, 'for_compiled_target', 'removed_admission'),
            (0, 'Workspace3new', 'removed_workspace'), (1, '_pthread_join', '_removed_join'),
            (1, 'clear_owned_region', 'removed_clear'), (2, 'BRYNJA_REGISTER_ERASE', 'removed_erase'),
            (2, 'BRYNJA_TRANSFER_ERASE', 'removed_transfer'), (2, 'mov\tx5, xzr', 'mov\tx5, x4'),
            (2, 'movi.16b\tv0, #0', 'movi.16b\tv0, #1'),
            (2, 'BRYNJA_SECRET_BEGIN', 'BRYNJA_SECRET_BEGIN\n\tstr x5, [sp]'),
            (3, 'BRYNJA_SCALAR_ERASE', 'removed_scalar'), (4, 'BRYNJA_SCALAR_ERASE', 'removed_scalar')):
        changed = list(texts)
        changed[index] = changed[index].replace(old, new)
        require(changed != texts, 'mutation changes artifact')
        cases.append(changed)
    for changed in cases:
        try:
            inspect(*changed)
        except ValueError:
            continue
        raise ValueError('batch compiler mutation survived')
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    texts = []
    for pattern in ('brynja_crypto_cpu_std-*.ll', 'brynja_crypto_cpu_std-*.s',
                    'brynja_crypto_cpu-*.s', 'brynja_hash_sha2-*.s', 'brynja_hash_sha3-*.s'):
        paths = list(args.artifacts.glob(pattern))
        require(len(paths) == 1, 'exact artifact: ' + pattern)
        texts.append(paths[0].read_text())
    inspect(*texts)
    count = regressions(texts)
    print(f'Darwin resident batch resource/worker/14 opaque blocks: PASS; {count} mutants rejected; bounded scope')


if __name__ == '__main__':
    main()
