#!/usr/bin/env python3
"""Build private accelerated KMAC component; no enclave or production claim."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha3_accelerated_build as base
import windows_enclave_kmac_stream_build as scalar

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('kmac_accelerated.rs', 'kmac_accelerated_setup.rs',
         'kmac_accelerated_state.rs', 'kmac_accelerated_key.rs',
         'kmac_accelerated_framing.rs', 'kmac_accelerated_tests.rs',
         'kmac_accelerated_authority_tests.rs', 'kmac_accelerated_wire.rs')


def build(directory, target):
    base.build(directory, target)
    prior = json.loads((directory/'sha3-accelerated-build.json').read_text())
    common = prior['commands'][-1][:prior['commands'][-1].index('--crate-name')]
    def deps(names):
        return [part for name in names for part in
                ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    command = common+['--crate-name', 'brynja_mac_kmac', '--crate-type', 'rlib',
        str(ROOT/'crates/brynja-mac-kmac/src/lib.rs'), '-o', str(directory/'libbrynja_mac_kmac.rlib')]
    command += deps(['brynja_core', 'brynja_hash_sha3'])
    base.run(command)
    prior['commands'].append(command)
    paths = {Path(__file__).resolve(), Path(scalar.__file__).resolve()}
    for name in FILES:
        path = SOURCE/name
        shutil.copyfile(path, directory/name)
        paths.add(path)
    crate = ROOT/'crates/brynja-mac-kmac'
    paths.update((crate/'src').rglob('*.rs'))
    paths.add(crate/'Cargo.toml')
    shutil.copyfile(crate/'src/packer.rs', directory/'kmac_packer.rs')
    # The unmodified packer's own framing tests stay enabled in this product.
    shutil.copyfile(crate/'src/packer/framing_tests.rs', directory/'framing_tests.rs')
    generated, count = scalar.oracle_tests()
    tests = directory/'kmac_accelerated_tests.rs'
    tests.write_text(tests.read_text()+'\n'+generated)
    for name in ('scripts/kmac/check-kmac-differential.py',
                 'scripts/sha3/check-cshake-differential.py',
                 'scripts/sha3/check-sha3-bit-differential.py'):
        paths.add(ROOT/name)
    deps_list = ['brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                 'brynja_mac_kmac', 'sha3_stream', 'sha3_accelerated_state']
    library = common+['--crate-name', 'kmac_accelerated', '--crate-type', 'rlib',
        str(directory/'kmac_accelerated.rs'), '-o', str(directory/'libkmac_accelerated.rlib')]+deps(deps_list)
    base.run(library)
    prior['commands'].append(library)
    artifact = directory/('kmac-accelerated-test.exe' if 'windows' in target else 'kmac-accelerated-test')
    command = common+['--crate-name', 'kmac_accelerated', '--test',
        str(directory/'kmac_accelerated.rs'), '-o', str(artifact)]+deps(deps_list)
    base.run(command)
    prior['commands'].append(command)
    prior['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    prior.update(status='KMAC_COMPONENT_BUILD_ONLY', oracle_cases=count,
                 shared_suffix='crates/brynja-mac-kmac/src/packer.rs')
    prior['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in directory.glob('*.rs')}
    (directory/'kmac-accelerated-build.json').write_text(json.dumps(prior, indent=2)+'\n')
    return command, artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
