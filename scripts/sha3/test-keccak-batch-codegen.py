#!/usr/bin/env python3
"""Reject unrelated, commented, missing and ambiguous SIMD evidence."""
import unittest
from keccak_batch_codegen import inspect

X86 = '''_R_keccak_batch_x86_permute:
 .cfi_startproc
 vpxor %ymm0, %ymm1, %ymm2
 vpandn %ymm0, %ymm1, %ymm2
 vpsllvq %ymm0, %ymm1, %ymm2
 vpsrlvq %ymm0, %ymm1, %ymm2
 .cfi_endproc
'''
ARM = '''_R_keccak_batch_arm_permute:
 .cfi_startproc
 eor v0.16b, v1.16b, v2.16b
 bic v0.16b, v1.16b, v2.16b
 ushl v0.2d, v1.2d, v2.2d
 .cfi_endproc
'''
APPLE = ARM.replace('_R_', '__R_').replace('eor v0.16b', 'eor3.16b v0').replace('bic v0.16b', 'bic.16b v0').replace('ushl v0.2d', 'ushl.2d v0')
APPLE_FUSED = APPLE.replace('bic.16b', 'bcax.16b')


class EvidenceTests(unittest.TestCase):
    def test_supported_assembly_syntax(self):
        for source, target in ((X86, 'x86_64-unknown-linux-gnu'),
                               (ARM, 'aarch64-unknown-linux-gnu'), (APPLE, 'aarch64-apple-darwin'),
                               (APPLE_FUSED, 'aarch64-apple-darwin')):
            inspect(source, target)

    def test_fail_closed_mutants(self):
        for source, target, tokens in ((X86, 'x86_64-unknown-linux-gnu', ('vpxor', 'vpandn', 'vpsllvq', 'vpsrlvq')),
                                      (ARM, 'aarch64-unknown-linux-gnu', ('eor', 'bic', 'ushl')),
                                      (APPLE, 'aarch64-apple-darwin', ('eor3', 'bic', 'ushl')),
                                      (APPLE_FUSED, 'aarch64-apple-darwin', ('eor3', 'bcax', 'ushl'))):
            mutants = [source + source, source.replace('keccak_batch', 'keccak_single'),
                       source.replace('.cfi_endproc', ''),
                       source.replace('.cfi_endproc', '.globl unrelated\n.cfi_endproc'),
                       '\n'.join('// ' + line for line in source.splitlines())]
            for token in tokens:
                mutants.extend((source.replace(token, 'removed'), source.replace(token, '// ' + token)))
            # SIMD in another function cannot rescue a scalar/no-op batch body.
            mutants.append(source.split('.cfi_startproc')[0] + '.cfi_endproc\n' + source.replace('keccak_batch', 'unrelated'))
            for mutant in mutants:
                with self.subTest(target=target, mutant=mutant):
                    with self.assertRaises(ValueError): inspect(mutant, target)

    def test_wrong_architecture(self):
        for source, target in ((ARM, 'x86_64-unknown-linux-gnu'), (X86, 'aarch64-apple-darwin'), (X86, 'riscv64gc-unknown-linux-gnu')):
            with self.assertRaises(ValueError): inspect(source, target)


if __name__ == '__main__': unittest.main()
