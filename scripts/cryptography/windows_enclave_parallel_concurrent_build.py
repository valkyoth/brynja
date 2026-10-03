"""Build private AVX2 concurrent-leaf component; not an enclave image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shutil

import windows_enclave_sha3_accelerated_build as base
import windows_enclave_parallel_stream_build as oracle_builder

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_concurrent.rs', 'parallel_concurrent_slot.rs', 'parallel_concurrent_tests.rs',
         'parallel_accelerated_state.rs', 'parallel_stream_encoding.rs')


def vectors():
    # The existing independent oracle also cross-checks all twelve NIST samples.
    _, _, _, data = oracle_builder.oracle_tests()
    selected = []
    for line in data.splitlines():
        fields = line.split()
        if fields[0] != 'D':
            continue
        block, custom_bits, input_bits = map(int, fields[2:5])
        if block <= 1024 and custom_bits <= 8192 and input_bits <= 4 * block * 8:
            selected.append(line)
    # Explicit four-leaf boundaries and largest admitted leaf/output shapes.
    import importlib.util
    spec = importlib.util.spec_from_file_location('parallel_oracle', ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    for identity in range(1, 5):
        for block in (1, 7, 136, 168, 1024):
            for total in (block * 8 * 3 + 1, block * 8 * 4 - 1, block * 8 * 4):
                for output_bits in (1, 259, 8192):
                    custom_bits = 17
                    custom = oracle.oracle.canonical(78, custom_bits)
                    message = oracle.oracle.canonical(total + identity, total)
                    result = oracle.parallel_hash(168 if identity % 2 else 136,
                        oracle.oracle.byte_bits(message)[:total], block,
                        oracle.oracle.byte_bits(custom)[:custom_bits], output_bits, identity > 2)
                    selected.append(' '.join(map(str, ('D', identity, block, custom_bits, total,
                        (output_bits - 1) % 8 + 1, custom.hex(), message.hex(), result.hex()))))
    if len(selected) < 200:
        raise ValueError('insufficient bounded oracle cases')
    return '\n'.join(selected) + '\n', len(selected)


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory / 'sha3-accelerated-build.json').read_text())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    data, count = vectors()
    (directory / 'parallel-concurrent-vectors.txt').write_text(data)
    dependencies = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                                     'sha3_stream', 'sha3_accelerated_state')
                    for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    library = common + ['--crate-name', 'parallel_concurrent', '--crate-type', 'rlib',
        str(directory / 'parallel_concurrent.rs'), '-o', str(directory / 'libparallel_concurrent.rlib')] + dependencies
    base.run(library)
    binary = directory / ('parallel-concurrent-test.exe' if 'windows' in target else 'parallel-concurrent-test')
    command = common + ['--crate-name', 'parallel_concurrent', '--test', str(directory / 'parallel_concurrent.rs'),
                        '-o', str(binary)] + dependencies
    base.run(command)
    sources = {SOURCE / name for name in FILES}
    sources.update((Path(__file__).resolve(), Path(oracle_builder.__file__).resolve(),
                    ROOT / 'scripts/cryptography/test-windows-enclave-parallel-concurrent.py',
                    ROOT / 'scripts/parallelhash/check-parallelhash-differential.py',
                    ROOT / 'scripts/sha3/check-cshake-differential.py',
                    ROOT / 'scripts/sha3/check-sha3-bit-differential.py',
                    ROOT / 'crates/brynja-hash-parallel/tests/official_vectors.rs'))
    record['source_sha256'].update({path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sources})
    record.update(status='CONCURRENT_PARALLELHASH_COMPONENT_BUILD_ONLY', oracle_cases=count,
                  commands=record['commands'] + [library, command])
    record['generated_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in directory.iterdir() if path.suffix in ('.rs', '.txt')}
    (directory / 'parallel-concurrent-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return command, binary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
