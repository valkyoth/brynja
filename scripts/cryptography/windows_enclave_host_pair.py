"""Build unchanged enclave Rust worker with an isolated safe in-process adapter."""
import hashlib
from pathlib import Path
import shutil
import subprocess

import windows_enclave_wire_build as wire
import windows_enclave_sha256_build as oracle

ROOT = wire.ROOT


def build(directory, target):
    # Reuse the existing first-party dependency build, with all existing variants.
    # No compiled native image is loaded and no Windows API is called here.
    wire.build(directory / 'wire', target, testing=True)
    # rustc's transitive rlib search uses the crate name, not the variant label.
    shutil.copyfile(directory / 'wire/libnormal.rlib', directory / 'libenclave_result.rlib')
    source = ROOT / 'assurance/windows-enclave-probe'
    for name in ('wire_protocol.rs', 'window_wire_tests.rs'):
        shutil.copyfile(source / name, directory / name)
    combined = directory / 'pair_worker.rs'
    combined.write_text((source / 'window_wire.rs').read_text() + '\n' +
                        (source / 'host_pair_transport.rs').read_text())
    deps = directory / 'wire/dependencies'
    library = directory / 'libenclave_pair.rlib'
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
        '--crate-type', 'rlib', '--crate-name', 'enclave_pair', '--cfg', 'test',
        '-L', 'dependency=' + str(deps), '-L', 'dependency=' + str(directory / 'wire'),
        '--extern', 'enclave_result=' + str(directory / 'wire/libnormal.rlib'),
        '--extern', 'brynja_core=' + str(deps / 'libbrynja_core.rlib'),
        '--extern', 'brynja_hash_sha2=' + str(deps / 'libbrynja_hash_sha2.rlib'),
        str(combined), '-o', str(library)]
    subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
    # Recompute public oracle values instead of trusting digest bytes in Rust.
    cases = oracle.vectors()
    generated = ['#[test]', 'fn actual_worker_and_host_match_twenty_independent_vectors() {']
    for message in cases:
        values = ','.join(map(str, message))
        digest = ','.join(map(str, hashlib.sha256(message).digest()))
        generated.append(f'    paired(&[{values}], &[{digest}]);')
    generated.append('}')
    (directory / 'host_pair_tests.rs').write_text((source / 'host_pair_tests.rs').read_text() + '\n' + '\n'.join(generated))
    return ['--extern', 'enclave_pair=' + str(library), '-L', 'dependency=' + str(deps),
            '-L', 'dependency=' + str(directory)]
