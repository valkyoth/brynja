"""Build private copied-ingress tests; not native OS-copy or enclave evidence."""
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_parallel_waves_build as base

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_wave_input.rs', 'parallel_wave_request.rs', 'parallel_wave_input_tests.rs')


def build(directory, target):
    previous, _ = base.build(directory, target)
    record = json.loads((directory / 'parallel-waves-build.json').read_text())
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    common = previous[:previous.index('--crate-name')]
    dependencies = [part for name in ('brynja_core', 'brynja_hash_sha3', 'brynja_crypto_cpu', 'parallel_waves')
                    for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    commands = []
    for testing in (False, True):
        binary = directory / ('parallel-input-test' + ('.exe' if 'windows' in target else '')) if testing else directory / 'libparallel_input.rlib'
        command = common + ['--crate-name', 'parallel_input', str(directory / FILES[0]),
                            '-o', str(binary)] + dependencies + (['--test'] if testing else ['--crate-type=rlib'])
        base.base.base.run(command)
        commands.append(command)
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-input.py']
    record['source_sha256'].update({path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in sources})
    record.update(status='PRIVATE_COPIED_INGRESS_BUILD_ONLY', production_qualified=False,
                  enclave_execution=False, commands=record['commands'] + commands)
    record['generated_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in directory.iterdir() if path.suffix in ('.rs', '.txt')}
    (directory / 'parallel-input-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return commands[-1], binary
