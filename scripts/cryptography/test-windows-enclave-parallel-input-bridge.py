"""Compiled ingress/pointer-lifetime regressions; process-only, not VBS evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_input_image as image
from windows_enclave_parallel_accelerated_worker_build import replace_exact as replace


def run(command, env=None):
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)


def check(directory):
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    image.base.base.build(directory, target)
    record = json.loads((directory / 'parallel-wave-bridge-build.json').read_text())
    for name in image.FILES + ('parallel_input_bridge_tests.rs',): shutil.copyfile(image.SOURCE / name, directory / name)
    previous = record['commands'][-1]
    common = previous[:previous.index('--crate-name')]
    deps = previous[previous.index('--extern'):]
    command = common + ['--crate-name', 'parallel_input', '--crate-type=rlib',
        str(directory / 'parallel_wave_input.rs'), '-o', str(directory / 'libparallel_input.rlib')] + deps
    compiled = run(command)
    if compiled.returncode: raise AssertionError(compiled.stderr)
    record['commands'].append(command)
    entry = directory / 'parallel_input_bridge.rs'
    entry.write_text(image.bridge((image.SOURCE / 'parallel_wave_bridge.rs').read_text()))
    test = directory / 'parallel_wave_bridge_tests.rs'
    test.write_text(replace(test.read_text(), 'assert_eq!(OFFSET.load(Ordering::Acquire), 0);',
        'assert_eq!(OFFSET.load(Ordering::Acquire), 0);\n'
        'assert!(INPUT.load(Ordering::Acquire).is_null());\n'
        'assert_eq!(WIDTH.load(Ordering::Acquire), 0);\nassert_eq!(BLOCK.load(Ordering::Acquire), 0);')
        + '\ninclude!("parallel_input_bridge_tests.rs");\n')
    binary = directory / ('input-bridge-test.exe' if 'windows' in target else 'input-bridge-test')
    command = common + ['--crate-name', 'parallel_input_bridge', '--test', str(entry), '-o', str(binary)]
    command += deps + ['--extern', 'parallel_input=' + str(directory / 'libparallel_input.rlib')]
    compiled = run(command)
    if compiled.returncode: raise AssertionError(compiled.stderr)
    record['commands'].append(command)
    cases = []
    for identity in range(1, 5):
        for mode in ('normal', 'early', 'empty', 'missing', 'cancel', 'unwind'):
            for wave in ((1,) if mode == 'normal' else (1, 2, 3)):
                env = dict(os.environ, BRYNJA_WAVE_ID=str(identity), BRYNJA_WAVE_MODE=mode, BRYNJA_WAVE_FAIL_AT=str(wave))
                result = run([str(binary), '--test-threads=1'], env)
                if result.returncode or '1 passed' not in result.stdout:
                    raise AssertionError(f'{identity}/{mode}/{wave}\n' + result.stdout + result.stderr)
                cases.append(dict(identity=identity, mode=mode, wave=wave, output=result.stdout))
    mutations = []
    original = entry.read_bytes()
    for number, (before, after) in enumerate((
        ('INPUT.store(core::ptr::null_mut(), Ordering::Relaxed);', ''),
        ('WIDTH.store(0, Ordering::Relaxed);', ''),
        ('BLOCK.store(0, Ordering::Relaxed);', ''),
    )):
        try:
            entry.write_bytes(replace(original.decode(), before, after).encode())
            mutant = directory / ('input-bridge-mutant-' + str(number) + ('.exe' if 'windows' in target else ''))
            args = list(command)
            args[args.index('-o') + 1] = str(mutant)
            compiled = run(args)
            if compiled.returncode: raise AssertionError('mutant must compile: ' + compiled.stderr)
            env = dict(os.environ, BRYNJA_WAVE_ID='1', BRYNJA_WAVE_MODE='normal', BRYNJA_WAVE_FAIL_AT='1')
            result = run([str(mutant), '--test-threads=1'], env)
            if result.returncode != 101 or 'test result: FAILED.' not in result.stdout:
                raise AssertionError('mutant escaped/crashed: ' + result.stdout + result.stderr)
            mutations.append(dict(before=before, after=after, output=result.stdout, stderr=result.stderr))
        finally: entry.write_bytes(original)
    paths = [image.SOURCE / name for name in image.FILES + ('parallel_input_bridge_tests.rs',)]
    paths += [Path(__file__).resolve(), Path(image.__file__).resolve()]
    record['source_sha256'].update({p.relative_to(image.ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    for name, digest in record['source_sha256'].items():
        assert hashlib.sha256((image.ROOT / name).read_bytes()).hexdigest() == digest, name
    record.update(status='PRIVATE_COPIED_INPUT_BRIDGE_PROCESS_PASS', enclave_execution=False,
        production_qualified=False, cases=cases, mutations=mutations, binary=binary.name,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                 if p.suffix in ('.rs', '.txt')}
    (directory / 'parallel-input-bridge-results.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Private copied-input bridge: {len(cases)} identity/fault cases; {len(mutations)} compiled mutations rejected; NOT VBS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    check(parser.parse_args().directory.resolve())
