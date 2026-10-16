#!/usr/bin/env python3
"""Finite Darwin legacy resource/worker/opaque-tail review, not whole-image proof.

Use native release LLVM and Mach-O assembly for both panic modes, with resident
acceleration and +neon,+sha2. Native tests separately cover conditional cleanup,
placement and lifetime. Caller copies, fatal interruption and OS storage excluded.
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


def instructions(text):
    return [' '.join(line.split()) for line in text.splitlines()
            if line.strip() and line.strip() != ';']


def kernels_check(kernels, family):
    populations = {'SCALAR': 1, 'SECRET': 1, 'TRANSFER': 4 if family == 'md5' else 0}
    for kind, count in populations.items():
        begin, end = f'BRYNJA_{kind}_BEGIN', f'BRYNJA_{kind}_END'
        erase = 'BRYNJA_REGISTER_ERASE' if kind == 'SECRET' else f'BRYNJA_{kind}_ERASE'
        require(kernels.count(begin) == kernels.count(end) == kernels.count(erase) == count,
                'exact legacy opaque population: ' + kind)
        blocks = re.findall(begin + r'(.*?)' + end, kernels, re.S)
        for block in blocks:
            require(not re.search(r'\b(?:sp|wsp)\b|\b(?:bl|blr)\b', block),
                    'no opaque stack access or call')
            body, tail = block.split(erase)
            require(body.strip(), 'nonempty opaque computation')
            if kind == 'SECRET':
                wanted = [f'mov x{n}, xzr' for n in (4, 5, 6)]
                wanted += [f'movi.16b v{n}, #0' for n in range(6 if family == 'sha1' else 4)]
            else:
                end_register = 8 if kind == 'TRANSFER' else (13 if family == 'sha1' else 12)
                wanted = [f'mov x{n}, xzr' for n in range(4, end_register)]
            require(instructions(tail) == wanted + ['cmp xzr, xzr'], 'exact legacy register erase tail')


def inspect(llvm, assembly, kernels, family):
    require('target triple = "arm64-apple-macosx' in llvm, 'Darwin Arm artifact')
    admission = function(llvm, 'macos_resident', '7Mapping3new')
    for call in ('@mmap(', '@mach_vm_inherit(', '@mprotect(', '@mlock('):
        require(call in admission, 'retained admission ' + call)
    require(re.search(r'@mach_vm_inherit\([^\n]*i32 noundef 2\)', admission), 'VM_INHERIT_NONE')
    release = function(llvm, 'macos_resident', '7Mapping', '4Drop4drop')
    require('clear_owned_region' in release and '@munmap(' in release
            and release.index('clear_owned_region') < release.index('@munmap('),
            'mapping clear precedes release textually; runtime tests cover paths')
    roots = [('7Session11hash_chunks', '7Session11hash_chunks0', 'hardened_in_place')]
    if family == 'sha1':
        roots += [('15CompiledSession11hash_chunks', '15CompiledSession11hash_chunks0', '8Executor19for_compiled_target'),
                  ('15CompiledSession3new', '15CompiledSession3new0', '8Executor19for_compiled_target')]
    else:
        roots += [('7Session6digest', '7Session6digests_0', '9Workspace3new'),
                  ('5batch', '7Session3news_0', '8Executor19for_compiled_target')]
    for method, entry, owner in roots:
        tokens = ('7Session3new',) if method == '5batch' else ()
        root = function(llvm, '@_RNvM', 'macos_resident', method, *tokens)
        shared.attribute_setup(llvm, assembly, root)
        for call in ('@pthread_create(', '@pthread_join('):
            require(call in root, 'coordinator retained ' + call)
        require('clear_owned_region' in root[root.index('@pthread_join('):], 'post-join stack clearing')
        calls = '\n'.join(line for line in root.splitlines()
                          if not line.lstrip().startswith(';') and re.search(r'\b(call|invoke)\b', line))
        require(not re.search(r'@\S*(?:Workspace3new|for_compiled_target|compress_secret|6update)', calls),
                'coordinator does not perform secret computation')
        symbol = re.search(r'@([^ (]+)\(', root.splitlines()[0])[1]
        code = machine(assembly, symbol)
        for call in ('_pthread_create', '_pthread_join', 'clear_owned_region'):
            require(re.search(r'\b(?:bl|b)\s+\S*' + call, code), 'machine coordinator ' + call)
        worker = function(llvm, 'macos_resident', 'thread5enter', entry)
        require('ret ptr null' in worker and owner in worker, 'worker owns state; returns no secret')
    for owner in ('6Digest', '11OutputGuard') + (('5Guard', '6Output') if family == 'md5' else ()):
        drop = function(llvm, 'macos_resident', owner, '4Drop4drop')
        require('clear_owned_region' in drop, 'output/guard clearing')
    kernels_check(kernels, family)


def regressions(texts, family):
    llvm, assembly, kernels = texts
    cases = [(llvm.replace(old, new), assembly, kernels) for old, new in (
        ('@pthread_attr_setstack(', '@removed_stack('),
        ('@mlock(', '@removed_mlock('), ('@mach_vm_inherit(', '@removed_inherit('),
        ('@pthread_join(', '@removed_join('), ('clear_owned_region', 'removed_clear'),
        ('@munmap(', '@removed_unmap('), ('ret ptr null', 'ret ptr %secret'),
        ('8Executor19for_compiled_target', '8Executor19removed_admission'))]
    cases += [(llvm, assembly.replace('clear_owned_region', 'removed_clear'), kernels)]
    for old, new in (('BRYNJA_REGISTER_ERASE', 'removed_erase'),
                     ('movi.16b\tv0, #0', 'movi.16b\tv0, #1'),
                     ('mov\tx5, xzr', 'mov\tx5, x4'),
                     ('BRYNJA_SECRET_BEGIN', 'BRYNJA_SECRET_BEGIN\n\tstr x5, [sp]'),
                     ('BRYNJA_SCALAR_ERASE', 'removed_scalar_erase')):
        cases.append((llvm, assembly, kernels.replace(old, new)))
    if family == 'md5':
        cases.append((llvm, assembly, kernels.replace('BRYNJA_TRANSFER_ERASE', 'removed_transfer')))
    for changed in cases:
        require(changed != texts, 'mutation changes artifact')
        try:
            inspect(*changed, family)
        except ValueError:
            continue
        raise ValueError('legacy compiler mutation survived')
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    for family in ('sha1', 'md5'):
        texts = []
        for pattern in (f'brynja_legacy_{family}_std-*.ll', f'brynja_legacy_{family}_std-*.s',
                        f'brynja_legacy_{family}-*.s'):
            paths = list(args.artifacts.glob(pattern))
            require(len(paths) == 1, 'exact compiler artifact: ' + pattern)
            texts.append(paths[0].read_text())
        inspect(*texts, family)
        count = regressions(tuple(texts), family)
        print(f'Darwin resident {family}: 3 coordinator/worker roots; opaque tails; {count} artifact mutants PASS')


if __name__ == '__main__':
    main()
