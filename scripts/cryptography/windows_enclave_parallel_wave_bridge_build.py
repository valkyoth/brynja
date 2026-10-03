"""Private generation-bound multi-wave adapter; process tests, NOT VBS evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_waves_build as base

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_wave_gate.rs', 'parallel_wave_gate_tests.rs',
         'parallel_wave_bridge.rs', 'parallel_wave_bridge_tests.rs')


def expected():
    spec = importlib.util.spec_from_file_location('oracle', ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    bits = oracle.oracle.byte_bits(bytes(index % 256 for index in range(289)))[:2307]
    rows = [list(oracle.parallel_hash(168 if identity % 2 else 136, bits, 32, [], 512, identity > 2))
            for identity in range(1, 5)]
    return 'pub const EXPECTED: [[u8; 64]; 4] = ' + repr(rows) + ';\n'


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory / 'parallel-waves-build.json').read_text())
    for name in FILES: shutil.copyfile(SOURCE / name, directory / name)
    (directory / 'parallel_wave_expected.rs').write_text(expected())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    commands = []
    for testing in (False, True):
        command = common + ['--crate-name', 'parallel_wave_gate']
        artifact = directory / ('wave-gate-test.exe' if 'windows' in target else 'wave-gate-test') if testing else directory / 'libparallel_wave_gate.rlib'
        command += ['--test'] if testing else ['--crate-type', 'rlib']
        command += [str(directory / 'parallel_wave_gate.rs'), '-o', str(artifact)]
        base.base.base.run(command)
        commands.append(command)
    dependencies = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                                      'parallel_waves', 'parallel_wave_gate')
                    for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    artifact = directory / ('wave-bridge-test.exe' if 'windows' in target else 'wave-bridge-test')
    command = common + ['--crate-name', 'parallel_wave_bridge', '--test',
        str(directory / 'parallel_wave_bridge.rs'), '-o', str(artifact)] + dependencies
    base.base.base.run(command)
    commands.append(command)
    record.update(status='PRIVATE_GENERATION_WAVE_BRIDGE_BUILD_ONLY', enclave_execution=False,
                  production_qualified=False, commands=record['commands'] + commands)
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-wave-bridge.py']
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in directory.iterdir() if p.suffix in ('.rs', '.txt')}
    (directory / 'parallel-wave-bridge-build.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
