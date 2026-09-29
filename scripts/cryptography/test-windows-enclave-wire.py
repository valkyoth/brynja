#!/usr/bin/env python3
"""Compiled wire protocol tests; native identities still require actual enclave runs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_wire_build as build


class WireTests(unittest.TestCase):
    def test_exact_c_identity_state_machine(self):
        # Compile the actual admission function, replacing only the OS entropy
        # provider. This is a local C regression, NOT an enclave entropy test.
        source = (build.ROOT / 'assurance/windows-enclave-probe/window_wire.c').read_text()
        function = source.split('static BOOL admit_identity(void) {', 1)[1].split(
            '__declspec(noinline)', 1)[0]
        prelude = '''#include <assert.h>
#include <stddef.h>
typedef unsigned long long ULONGLONG;
typedef unsigned char *PUCHAR;
typedef int BOOL;
#define FALSE 0
#define TRUE 1
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 2
static ULONGLONG identity[2], epoch;
static int identity_state, entropy_calls, entropy_error, zero_entropy;
static int BCryptGenRandom(void *algorithm, PUCHAR out, size_t size, int flags) {
    assert(!algorithm && size == sizeof(identity) && flags == 2);
    entropy_calls++;
    ((ULONGLONG *)out)[0] = zero_entropy ? 0 : 7;
    ((ULONGLONG *)out)[1] = zero_entropy ? 0 : 8;
    return entropy_error;
}
static BOOL admit_identity(void) {'''
        checks = '''
int main(void) {
    assert(admit_identity() && epoch == 1 && entropy_calls == 1);
    assert(admit_identity() && epoch == 2 && entropy_calls == 1);
    epoch = ~(ULONGLONG)0 - 1;
    assert(admit_identity() && epoch == ~(ULONGLONG)0);
    assert(!admit_identity() && !admit_identity() && epoch == ~(ULONGLONG)0);
    epoch = 0; identity_state = 0; entropy_error = 1;
    assert(!admit_identity() && identity_state == -1 && epoch == 0);
    entropy_error = 0;
    assert(!admit_identity() && entropy_calls == 2 && epoch == 0);
    identity_state = 0; zero_entropy = 1;
    assert(!admit_identity() && identity_state == -1 && epoch == 0);
    zero_entropy = 0;
    assert(!admit_identity() && entropy_calls == 3 && epoch == 0);
    return 0;
}
'''
        mutants = (function,
                   function.replace('epoch == ~(ULONGLONG)0', 'FALSE'),
                   function.replace('identity_state = -1;', 'identity_state = 0;'),
                   function.replace('if ((identity[0] | identity[1]) == 0) { return FALSE; }', ''),
                   function.replace('epoch += 1;', 'epoch += 0;'))
        with tempfile.TemporaryDirectory(prefix='brynja-wire-identity-') as folder:
            for index, candidate in enumerate(mutants):
                source_file = Path(folder) / f'identity-{index}.c'
                source_file.write_text(prelude + candidate + checks)
                binary = source_file.with_suffix('')
                subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                str(source_file), '-o', str(binary)], check=True, timeout=30)
                result = subprocess.run([str(binary)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, index == 0, result.stderr)

    def test_compiled_wire_and_six_variants(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-enclave-wire-') as folder:
            path = Path(folder)
            commands = build.build(path, target, testing=True)
            self.assertEqual(len(commands), 15)
            expected = {'foreign': 'foreign_stale_future_and_bad_commands_are_terminal',
                        'stale': 'foreign_stale_future_and_bad_commands_are_terminal',
                        'reusable': 'public_export_then_replay_is_spent',
                        'forgotten': 'public_export_then_replay_is_spent',
                        'missing-clear': 'partial_copy_and_transport_failures_clear'}
            for variant in build.VARIANTS:
                result = subprocess.run([str(path / (variant + '-worker' + ('.exe' if os.name == 'nt' else '')))],
                                        capture_output=True, text=True, timeout=30)
                if variant == 'normal':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('5 passed', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected[variant] + ' ... FAILED', result.stdout)


if __name__ == '__main__':
    unittest.main()
