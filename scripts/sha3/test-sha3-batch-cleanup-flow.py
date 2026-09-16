#!/usr/bin/env python3
"""Adversarial checks for exact complete LLVM workspace coverage, without compilation."""
import sha3_hardened_batch_codegen as check


def fixture(alignment=''):
    lines = ['define void @fixture(ptr dereferenceable(5260) %self) {', 'start:']
    offset = 1920
    for i, width in enumerate(check.WIDTHS):
        lines += [f'%p{i} = getelementptr inbounds nuw i8, ptr %self, i64 {offset}',
                  f'%r{i} = call noundef i8 @_RNv11brynja_core13secret_memory18clear_owned_region'
                  f'(ptr noalias noundef nonnull {alignment}%p{i}, i64 noundef {width})']
        offset += width
    lines += [f'%scalar = getelementptr inbounds nuw i8, ptr %self, i64 {offset}',
              'call void @_RNv16brynja_hash_sha38hardened5owner20HardenedFips202Owner4wipe'
              '(ptr noalias dereferenceable(1040) %scalar)',
              'call void @_RNv17brynja_crypto_cpu21keccak_hardened_batch9Workspace5clear'
              '(ptr noalias dereferenceable(1920) %self)', 'ret void', '}']
    return '\n'.join(lines)


def rejects(body):
    try:
        check.llvm_coverage(body)
    except ValueError:
        return
    raise AssertionError('malformed workspace coverage accepted')


def exercise():
    source = fixture()
    check.llvm_coverage(source)
    check.llvm_coverage(fixture('align 1 '))
    mutations = [
        ('dereferenceable(5260)', 'dereferenceable(5259)'),
        ('%self, i64 1920', '%self, i64 1919'),
        ('%self, i64 1920', '%self, i64 1921'),
        ('%p1, i64 noundef 800', '%p0, i64 noundef 800'),
        ('%p0, i64 noundef 800', '%external, i64 noundef 800'),
        ('%self, i64 1920', '%external, i64 1920'),
        ('%p1 = getelementptr', '%p0 = getelementptr'),
        ('i64 noundef 800)', 'i64 noundef 799)'),
        ('i64 noundef 800)', 'i64 noundef 0)'),
        ('dereferenceable(1040)', 'dereferenceable(1039)'),
        ('dereferenceable(1920)', 'dereferenceable(1919)'),
        ('20HardenedFips202Owner', '18OrdinaryFipsOwner'),
        ('21keccak_hardened_batch', '12keccak_batch'),
        ('11brynja_core13secret_memory', '12untrusted_crate'),
        ('ret void', 'store i8 1, ptr %self\nret void'),
        ('ret void', 'br label %done\ndone:\nret void'),
        ('ret void', 'ret void\nstore i8 1, ptr %self'),
        ('ret void', ''),
    ]
    for before, after in mutations:
        assert before in source
        rejects(source.replace(before, after))
    # Missing middle/final frame, even though remaining calls still clear valid regions.
    for first in (7, 19):
        lines = source.splitlines()
        lines = [line for line in lines if not any(line.startswith(f'%r{i} =') for i in range(first, first + 4))]
        rejects('\n'.join(lines))
    # A callee name appearing only in a comment cannot establish any cleanup call.
    rejects(source.replace('%r0 = call', '; %r0 = call'))
    return len(mutations) + 3


if __name__ == '__main__':
    print(f'SHA-3 workspace LLVM coverage rejects {exercise()} address/extent/control-flow regressions')
