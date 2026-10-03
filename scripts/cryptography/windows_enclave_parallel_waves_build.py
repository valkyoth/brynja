"""Build a private safe-Rust multi-wave component, NOT an enclave image."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_concurrent_build as base

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_concurrent_waves.rs', 'parallel_concurrent_waves_tests.rs')


def vectors():
    # Existing oracle construction verifies every one of the twelve NIST samples.
    _, _, _, data = base.oracle_builder.oracle_tests()
    selected = []
    for line in data.splitlines():
        fields = line.split()
        if fields[0] == 'D':
            block, custom, total = map(int, fields[2:5])
            if block <= 1024 and custom <= 8192 and total <= 65536 * block * 8:
                selected.append(line)
    spec = importlib.util.spec_from_file_location('oracle', ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    for identity in range(1, 5):
        shapes = [(block, leaves, tail, output) for block in (1, 7, 136, 168)
                  for leaves in (5, 8, 9, 17) for tail in (0, 1) for output in (1, 259)]
        shapes += [(1024, 9, 1, 8192), (1, 128, 0, 512)]
        for block, leaves, tail, output_bits in shapes:
            total = block * leaves * 8 - tail
            custom_bits = 17
            custom = oracle.oracle.canonical(83, custom_bits)
            message = oracle.oracle.canonical(total + identity, total)
            output = oracle.parallel_hash(168 if identity % 2 else 136,
                oracle.oracle.byte_bits(message)[:total], block,
                oracle.oracle.byte_bits(custom)[:custom_bits], output_bits, identity > 2)
            selected.append(' '.join(map(str, ('D', identity, block, custom_bits, total,
                (output_bits - 1) % 8 + 1, custom.hex(), message.hex(), output.hex()))))
    if len(selected) < 400: raise ValueError('insufficient multi-wave vectors')
    return '\n'.join(selected) + '\n', len(selected)


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory / 'parallel-concurrent-build.json').read_text())
    for name in FILES: shutil.copyfile(SOURCE / name, directory / name)
    # Append a private module/export to a separate generated crate root. The
    # previously captured bounded component and its source remain byte-unchanged.
    entry = directory / 'parallel_waves_root.rs'
    entry.write_text((SOURCE / 'parallel_concurrent.rs').read_text()
        + '\nmod parallel_concurrent_waves;\npub use parallel_concurrent_waves::{Waves, MAX_LEAVES};\n')
    data, count = vectors()
    (directory / 'parallel-waves-vectors.txt').write_text(data)
    commands = []
    for testing, previous in zip((False, True), record['commands'][-2:]):
        command = list(previous)
        command[command.index('--crate-name') + 1] = 'parallel_waves'
        command[command.index(str(directory / 'parallel_concurrent.rs'))] = str(entry)
        artifact = directory / ('parallel-waves-test.exe' if 'windows' in target else 'parallel-waves-test') if testing else directory / 'libparallel_waves.rlib'
        command[command.index('-o') + 1] = str(artifact)
        base.base.run(command)
        commands.append(command)
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-waves.py']
    record['source_sha256'].update({path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sources})
    record.update(status='PRIVATE_MULTI_WAVE_COMPONENT_BUILD_ONLY', production_qualified=False,
                  enclave_execution=False, wave_oracle_cases=count, commands=record['commands'] + commands)
    record['generated_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in directory.iterdir() if path.suffix in ('.rs', '.txt')}
    (directory / 'parallel-waves-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return commands[-1], artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
