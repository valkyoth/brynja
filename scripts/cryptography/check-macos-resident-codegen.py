#!/usr/bin/env python3
"""Focused Darwin resident compiler review; not whole-image erasure proof.

Inspect release LLVM/assembly emitted with macos-resident-acceleration and
+neon,+sha2,+sha3. Run separately for panic=abort and panic=unwind. Native
lifecycle tests establish the complementary conditional/lifetime behavior;
this check establishes retained calls and exact opaque kernel erase tails.
No claims about OS storage, caller copies, dumps, fatal abort or interruption.
"""
import argparse
from pathlib import Path
import re


def require(condition, label):
    if not condition:
        raise ValueError('Darwin resident compiler review: ' + label)


def function(llvm, *tokens):
    found = [body for body in re.findall(r'^define .*?^}', llvm, re.M | re.S)
             if all(token in body.splitlines()[0] for token in tokens)]
    require(len(found) == 1, 'unique LLVM function: ' + repr(tokens))
    return found[0]


def machine(assembly, symbol):
    match = re.search(r'^' + re.escape('_' + symbol) + r':\n(.*?)(?=^__R|\Z)',
                      assembly, re.M | re.S)
    require(match is not None, 'exact Mach-O symbol: ' + symbol)
    return match[1]


def attribute_setup(llvm, assembly, root):
    """Follow exactly one reviewed outlined constructor, not arbitrary callees."""
    body = root
    symbol = re.search(r'@([^ (]+)\(', root.splitlines()[0])[1]
    code = machine(assembly, symbol)
    if '@pthread_attr_setstack(' not in root:
        body = function(llvm, 'macos_resident', '10Attributes3new')
        helper = re.search(r'@([^ (]+)\(', body.splitlines()[0])[1]
        require(re.search(r'\b(?:call|invoke)\b[^\n]*@' + re.escape(helper) + r'\(', root),
                'coordinator calls exact attribute helper')
        require(re.search(r'\b(?:bl|b)\s+_' + re.escape(helper) + r'(?:\s|$)', code),
                'machine coordinator calls exact attribute helper')
        code = machine(assembly, helper)
    for call in ('pthread_attr_init', 'pthread_attr_setstack'):
        require(re.search(r'\b(?:call|invoke)\b[^\n]*@' + call + r'\(', body),
                'retained attribute call: ' + call)
        require(re.search(r'\b(?:bl|b)\s+_' + call + r'(?:\s|$)', code),
                'retained machine attribute call: ' + call)


def inspect(llvm, assembly, kernels, keyed=False):
    require('target triple = "arm64-apple-macosx' in llvm, 'Darwin Arm artifact')
    constructor = function(llvm, 'macos_resident', '7Mapping3new')
    for call in ('@mmap(', '@mach_vm_inherit(', '@mprotect(', '@mlock('):
        require(call in constructor, 'retained resource admission: ' + call)
    require(re.search(r'@mach_vm_inherit\([^\n]*i32 noundef 2\)', constructor),
            'VM_INHERIT_NONE')
    release = function(llvm, 'macos_resident', '7Mapping', '4Drop4drop')
    require('clear_owned_region' in release and '@munmap(' in release
            and release.index('clear_owned_region') < release.index('@munmap('),
            'mapping clear precedes release textually (native tests cover control flow)')
    symbol = re.search(r'@([^ (]+)\(', release.splitlines()[0])[1]
    body = machine(assembly, symbol)
    for callee in ('clear_owned_region', '_munmap'):
        require(re.search(r'\b(?:bl|b)\s+\S*' + callee, body), 'retained machine ' + callee)
    # Five request coordinators and two startup-KAT coordinators. These exact
    # roots must retain private-stack start/join/clear, not run crypto inline.
    roots = (('4sha2', '7Session11hash_chunks'),
             ('4sha3', '7Session22hash_customized_chunks'),
             ('6sha256', '13Sha256Session11hash_chunks'),
             ('4sha2', '15CompiledSession11hash_chunks'),
             ('4sha3', '15CompiledSession22hash_customized_chunks'),
             ('4sha2', '15CompiledSession3new'),
             ('4sha3', '15CompiledSession3new'))
    if keyed:
        roots += (('4kmac', '7Session7execute'), ('9tuplehash', '7Session7compute'),
                  ('4kmac', '15CompiledSession7execute'), ('9tuplehash', '15CompiledSession7compute'),
                  ('4kmac', '15CompiledSession3new'), ('9tuplehash', '15CompiledSession3new'))
    for family, method in roots:
        root = function(llvm, 'define ', '@_RNvM', 'macos_resident', family, method)
        attribute_setup(llvm, assembly, root)
        for callee in ('@pthread_create(', '@pthread_join('):
            require(callee in root, 'coordinator retained ' + callee)
        require('clear_owned_region' in root[root.index('@pthread_join('):],
                'post-join stack clear retained')
        calls = '\n'.join(line for line in root.splitlines()
                          if not line.lstrip().startswith(';') and re.search(r'\b(call|invoke)\b', line))
        require(not re.search(r'@\S*(?:Workspace3new|Authority3new|compress_secret|permute_secret)', calls),
                'no crypto construction/dispatch on coordinator')
        symbol = re.search(r'@([^ (]+)\(', root.splitlines()[0])[1]
        code = machine(assembly, symbol)
        for callee in ('_pthread_create', '_pthread_join', 'clear_owned_region'):
            require(re.search(r'\b(?:bl|b)\s+\S*' + callee, code), 'machine coordinator ' + callee)
        worker = function(llvm, 'macos_resident', 'thread5enter', family, method + '0')
        require('ret ptr null' in worker, 'worker returns no secret-bearing value')
        # TupleHash scalar is outlined rather than inlined by this compiler.
        state_owner = worker
        if family == '9tuplehash' and method == '7Session7compute' and 'Workspace' not in worker:
            outlined = function(llvm, 'macos_resident', '9tuplehash6worker3run')
            name = re.search(r'@([^ (]+)\(', outlined.splitlines()[0])[1]
            require('@' + name + '(' in worker, 'worker calls exact TupleHash body')
            state_owner = outlined
        require('Authority3new' in state_owner if 'CompiledSession' in method
                else 'Workspace' in state_owner or 'HardenedSha256' in state_owner,
                'worker owns state or startup authority')
    if keyed:
        comparison = function(llvm, 'macos_resident', '4kmac6worker7compare')
        for token in ('accumulate_secret_byte_difference', 'secret_difference_is_zero', 'clear_owned_region'):
            require(token in comparison, 'retained KMAC fixed-work/clearing call: ' + token)
        for family in ('4kmac', '9tuplehash'):
            for owner in ('7Buffers', '6Output'):
                drop = function(llvm, 'macos_resident', family, owner, '4Drop4drop')
                require('clear_owned_region' in drop, 'keyed owner clearing retained')
    # Exact population and erase sets for the three admitted Arm hardware kernels.
    expected = (('aarch64_sha29secret2568compress', range(6), (4, 5, 6, 7, 9)),
                ('aarch64_sha29secret5128compress', (*range(8), *range(16, 21)), (4, 5, 6, 7, 9)),
                ('aarch64_sha3_keccak6secret7permute', range(4), (4, 5, 6, 7, 9)))
    require(kernels.count('BRYNJA_SECRET_BEGIN') == 3, 'exact three hardware kernels')
    for token, vectors, general in expected:
        names = re.findall(r'^(__R[^\n:]*' + token + r'[^\n:]*):$', kernels, re.M)
        require(len(names) == 1, 'unique hardware kernel: ' + token)
        code = machine(kernels, names[0][1:])
        for marker in ('BRYNJA_SECRET_BEGIN', 'BRYNJA_REGISTER_ERASE', 'BRYNJA_SECRET_END'):
            require(code.count(marker) == 1, 'exact kernel marker: ' + marker)
        opaque = code.split('BRYNJA_SECRET_BEGIN')[1].split('BRYNJA_SECRET_END')[0]
        require(not re.search(r'\b(?:sp|wsp)\b|\b(?:bl|blr)\b', opaque), 'no opaque stack access or calls')
        tail = opaque.split('BRYNJA_REGISTER_ERASE')[1]
        instructions = [line.strip() for line in tail.splitlines() if line.strip() and line.strip() != ';']
        wanted = [f'movi.16b v{n}, #0' for n in vectors]
        wanted += [f'mov x{n}, xzr' for n in general] + ['cmp xzr, xzr']
        normalize = lambda line: ' '.join(line.split())
        require([normalize(line) for line in instructions] == wanted, 'exact working-register erase tail')
        after = code.split('BRYNJA_SECRET_END')[1]
        require(re.search(r'^\s*ret\s*$', after, re.M), 'kernel normal return')


def regressions(llvm, assembly, kernels, keyed=False):
    cases = [(llvm.replace(old, new), assembly, kernels) for old, new in (
        ('@mlock(', '@removed_mlock('), ('@mach_vm_inherit(', '@removed_inherit('),
        ('@pthread_attr_setstack(', '@removed_stack('),
        ('@pthread_join(', '@removed_join('), ('clear_owned_region', 'removed_clear'),
        ('@munmap(', '@removed_unmap('), ('ret ptr null', 'ret ptr %secret'))]
    cases += [(llvm, assembly.replace('clear_owned_region', 'removed_clear'), kernels)]
    cases += [(llvm, assembly, kernels.replace(old, new, 1)) for old, new in (
        ('BRYNJA_REGISTER_ERASE', 'removed_erase'), ('movi.16b\tv0, #0', 'movi.16b\tv0, #1'),
        ('mov\tx5, xzr', 'mov\tx5, x4'), ('BRYNJA_SECRET_BEGIN', 'BRYNJA_SECRET_BEGIN\n\tstr x5, [sp]'))]
    if keyed:
        comparison = function(llvm, 'macos_resident', '4kmac6worker7compare')
        for token in ('accumulate_secret_byte_difference', 'secret_difference_is_zero', 'clear_owned_region'):
            cases.append((llvm.replace(comparison, comparison.replace(token, 'removed_call')), assembly, kernels))
        for family in ('4kmac', '9tuplehash'):
            drop = function(llvm, 'macos_resident', family, '7Buffers', '4Drop4drop')
            cases.append((llvm.replace(drop, drop.replace('clear_owned_region', 'removed_clear')), assembly, kernels))
    for changed in cases:
        require(changed != (llvm, assembly, kernels), 'mutation must change artifact')
        try:
            inspect(*changed, keyed)
        except ValueError:
            continue
        raise ValueError('Darwin compiler mutation survived')
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('--keyed', action='store_true')
    args = parser.parse_args()
    texts = []
    for pattern in ('brynja_crypto_cpu_std-*.ll', 'brynja_crypto_cpu_std-*.s', 'brynja_crypto_cpu-*.s'):
        paths = list(args.artifacts.glob(pattern))
        require(len(paths) == 1, 'exact artifact: ' + pattern)
        texts.append(paths[0].read_text())
    inspect(*texts, args.keyed)
    count = regressions(*texts, args.keyed)
    print(f'Darwin resident resource/worker/kernel compiler review: PASS; rejected={count}; bounded scope only')


if __name__ == '__main__':
    main()
