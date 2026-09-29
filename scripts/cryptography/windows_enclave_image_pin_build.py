#!/usr/bin/env python3
"""Build first-party artifact-hash adapter; no production image approval."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha256_build as sha

ROOT = sha.ROOT
FILES = ('image_pin.rs', 'image_pin.h', 'image_pin.c', 'image_pin_main.c')
SOURCES = tuple(sorted(set(sha.source_files()) | {
    'scripts/cryptography/windows_enclave_sha256_build.py',
    'scripts/cryptography/windows_enclave_image_pin_build.py',
    'scripts/cryptography/windows_enclave_image_pin_run.py',
    'scripts/cryptography/test-windows-enclave-image-pin.py',
    *('assurance/windows-enclave-probe/'+p for p in FILES)}))


def dependencies(directory, target, level='2', testing=False):
    sha.check_graph(); directory.mkdir(parents=True, exist_ok=True); commands = []
    for name in sha.CRATES:
        crate = name.replace('-', '_')
        args = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-C', 'opt-level='+level,
                '-C', 'panic='+('unwind' if testing else 'abort'), '--crate-type', 'rlib',
                '--crate-name', crate, str(ROOT/'crates'/name/'src/lib.rs'), '-o', str(directory/('lib'+crate+'.rlib'))]
        if name == 'brynja-hash-sha2':
            for dep in ('brynja_core', 'brynja_hash_core'):
                args += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
        subprocess.run(args, check=True, capture_output=True, timeout=120); commands.append(args)
    return commands


def build(directory):
    directory = directory.resolve(); target = 'x86_64-pc-windows-msvc'
    commands = dependencies(directory, target)
    for name in FILES: shutil.copyfile(ROOT/'assurance/windows-enclave-probe'/name, directory/name)
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '--crate-type', 'staticlib',
        '-D', 'warnings', '-C', 'panic=abort', '-C', 'opt-level=2', '-C', 'overflow-checks=yes',
        '-L', 'dependency='+str(directory), '--extern', 'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
        str(directory/'image_pin.rs'), '-o', str(directory/'image_pin.lib')]
    subprocess.run(command, check=True, capture_output=True, timeout=120); commands.append(command)
    record = {'schema':1, 'native_executed':False, 'strict_qualified':False, 'commands':commands,
        'rustc':subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
        'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'artifact_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.iterdir()) if p.is_file()}}
    (directory/'image-pin-build.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Public image-pin adapter cross-build: PASS; signature verification: NOT IMPLEMENTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
