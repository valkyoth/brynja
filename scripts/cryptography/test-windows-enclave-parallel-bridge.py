"""Bounded bridge races and load-bearing publication/admission regressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import windows_enclave_parallel_concurrent_image as image
from windows_enclave_parallel_accelerated_worker_build import replace_exact


def run(command, env=None):
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=45)


def check(directory):
    record = json.loads((directory / 'parallel-concurrent-image-build.json').read_text())
    command = next(command for command in reversed(record['commands'])
                   if '--test' in command and 'parallel_concurrent_bridge' in command)
    binary = command[command.index('-o') + 1]
    results = []
    for identity in range(1, 5):
        for mode in ('normal', 'early', 'empty'):
            env = dict(os.environ, BRYNJA_PRIVATE_PARALLEL_ID=str(identity), BRYNJA_PRIVATE_PARALLEL_MODE=mode)
            result = run([binary, '--test-threads=1'], env)
            if result.returncode or '4 passed' not in result.stdout:
                raise AssertionError(result.stdout + result.stderr)
            results.append(dict(identity=identity, mode=mode, output=result.stdout))
    gate = directory / 'parallel_concurrent_gate.rs'
    original_bytes = gate.read_bytes()
    original = original_bytes.decode('utf-8')
    mutants = (
        ('state & OPEN == 0 || state & bit != 0', 'state & bit != 0'),
        ('state & OPEN == 0 || state & bit != 0', 'state & OPEN == 0'),
        ('state | bit | (bit << 4)', 'state | bit'),
        ('self.0.fetch_and(!OPEN, Ordering::AcqRel);', 'let _ = OPEN;'),
        ('self.0.load(Ordering::Acquire) & LIVE == 0', 'true'),
        ('state & (OPEN | LIVE) == 0 && state & 0x0f0f == 0x0f0f',
         'state & (OPEN | LIVE) == 0'),
    )
    mutation_results = []
    try:
        for number, (before, after) in enumerate(mutants):
            gate.write_bytes(replace_exact(original, before, after).encode('utf-8'))
            changed = list(command)
            mutant = directory / ('gate-mutant-' + str(number) + ('.exe' if os.name == 'nt' else ''))
            changed[changed.index('-o') + 1] = str(mutant)
            # An intentionally unused constant is not itself a regression test.
            changed += ['-A', 'dead_code']
            compiled = run(changed)
            if compiled.returncode:
                raise AssertionError('mutant must compile: ' + compiled.stderr)
            # Use the fully qualified name, never accept a vacuous filtered run.
            result = run([str(mutant), 'parallel_concurrent_bridge_tests::gate_closes_admission_without_releasing_live_borrows', '--exact'])
            if result.returncode == 0 or '1 failed' not in result.stdout:
                raise AssertionError('gate mutant escaped: ' + result.stdout + result.stderr)
            mutation_results.append(dict(number=number, output=result.stdout))
    finally:
        gate.write_bytes(original_bytes)
    # Bind both the tested copied inputs and their repository originals.
    for name, digest in record['source_sha256'].items():
        if hashlib.sha256((image.ROOT / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('repository source drift: ' + name)
    for name, digest in record['generated_sha256'].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('generated source drift: ' + name)
    result = dict(schema=1, status='PRIVATE_COMPONENT_ONLY', production_qualified=False,
        source_sha256=record['source_sha256'], binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        cases=results, mutations=mutation_results)
    (directory / 'bridge-regressions.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Private ParallelHash bridge: 12 identity/scheduling cases; six compiled gate mutants rejected')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    check(args.directory.resolve())
