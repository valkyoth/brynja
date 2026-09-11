#!/usr/bin/env python3
"""Reject fabricated, incomplete, misbound and cross-lane native records."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import tuplehash_execution_native as evidence


def libtest_output():
    """Exercise the real libtest formatter, not only hand-written log fixtures."""
    path = Path(__file__).with_name('capture-tuplehash-execution-native.py')
    spec = importlib.util.spec_from_file_location('capture', path)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    command = capture.kernel_command()
    options = command[command.index('--') + 1:]
    assert options == ['--show-output', '--test-threads=1']
    assert 'host.execute(kernel_command(), static_env)' in path.read_text()
    with tempfile.TemporaryDirectory(prefix='brynja-libtest-format-') as temporary:
        root = Path(temporary)
        source = root / 'formatter.rs'
        executable = root / ('formatter.exe' if os.name == 'nt' else 'formatter')
        source.write_text('''
#[test] fn execution() {
    println!("HARDENED_KECCAK_EXECUTION: {}; permutations=1024",
             std::env::var("BRYNJA_FORMAT_TEST_KERNEL").unwrap());
}
#[test] fn cleanup() {}
#[test] fn quarantine() {}
#[test] fn ownership() {}
''')
        subprocess.run(['rustc', '+1.98.1', '--test', str(source), '-o', str(executable)],
                       check=True, capture_output=True, text=True, timeout=60)
        for lane in evidence.LANES:
            value = record(lane)
            env = dict(os.environ, BRYNJA_FORMAT_TEST_KERNEL=value['kernel'])
            for threads in (1, 2):
                run_options = [options[0], f'--test-threads={threads}']
                output = subprocess.run([str(executable), *run_options], env=env,
                    check=True, capture_output=True, text=True, timeout=30).stdout
                value['results']['kernel_tests'] = output
                evidence.record_check(value, lane, 'a' * 40, {'test-only.rs': 'b' * 64})
            # Reproduce the old serialized output: its marker shares the test
            # prefix. It must remain rejected rather than loosening the parser.
            output = subprocess.run([str(executable), '--nocapture', '--test-threads=1'], env=env,
                check=True, capture_output=True, text=True, timeout=30).stdout
            value['results']['kernel_tests'] = output
            try:
                evidence.record_check(value, lane, 'a' * 40, {'test-only.rs': 'b' * 64})
            except ValueError:
                pass
            else:
                raise AssertionError('prefixed execution marker was accepted')
    print('Real libtest output: captured markers pass; prefixed nocapture markers remain rejected')


def record(lane):
    target, kernel = evidence.LANES[lane]
    modes = ['portable', 'prefer-portable', 'static', 'prefer']
    if kernel == 'ArmKeccak':
        modes.append('hosted')
    package = '\n'.join(
        f'TupleHash execution oracle: PASS; mode={mode}; cases=268; kernel=' +
        ('Portable' if mode in ('portable', 'prefer-portable') else kernel)
        for mode in modes)
    return {'schema': 1, 'commit': 'a' * 40, 'lane': lane, 'target': target, 'kernel': kernel,
            'cpu': 'test-only synthetic CPU', 'os': 'test-only OS',
            'compiler': 'rustc 1.98.1 (test)\nhost: ' + target + '\nrelease: 1.98.1\n',
            'sources': {'test-only.rs': 'b' * 64}, 'native_attestation': 'operator asserts native, not QEMU',
            'results': {'package': package, 'kernel_tests':
                'HARDENED_KECCAK_EXECUTION: ' + kernel + '; permutations=1024\n'
                'test result: ok. 4 passed; 0 failed\n'}}


def main():
    count = 0
    for lane in evidence.LANES:
        original = record(lane)
        check = lambda value: evidence.record_check(value, lane, 'a' * 40, {'test-only.rs': 'b' * 64})
        check(original)
        mutants = []
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            mutants.append(changed)
        for key, value in (('schema', True), ('commit', 'c' * 40), ('lane', 'other'),
                           ('target', 'wasm32-unknown-unknown'), ('kernel', 'X86Sha256'),
                           ('sources', {}), ('cpu', ''), ('cpu', 'host\nspoof'),
                           ('os', []), ('native_attestation', 'QEMU'), ('compiler', 'rustc 1.90.0')):
            changed = copy.deepcopy(original)
            changed[key] = value
            mutants.append(changed)
        for output in original['results']:
            for line in original['results'][output].splitlines():
                changed = copy.deepcopy(original)
                changed['results'][output] = changed['results'][output].replace(line, 'omitted')
                mutants.append(changed)
        for changed in mutants:
            try:
                check(changed)
            except ValueError:
                count += 1
                continue
            raise AssertionError('native record mutant escaped')
    try:
        evidence.shared.document(b'{"schema":1,"schema":1}')
    except ValueError:
        count += 1
    else:
        raise AssertionError('duplicate JSON accepted')
    gate = (evidence.ROOT / 'scripts/tag_gate.sh').read_text()
    assert '\npython3 scripts/tuplehash/check-tuplehash-execution-native.py\n' in gate
    libtest_output()
    print(f'Hardened Keccak native schema/identity/source/results rejects {count} regressions')


if __name__ == '__main__':
    main()
