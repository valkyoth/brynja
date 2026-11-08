#!/usr/bin/env python3
"""Pinned AESAVS MCT/MMT on package-external portable public operations."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil

spec = importlib.util.spec_from_file_location('aes_packaged_avs', Path(__file__).with_name('check-aes-packaged.py'))
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
ROOT = packaged.ROOT
FIXTURE = ROOT / 'assurance/aes-avs'
HASHES = {
    'ECBMCT128.rsp': '1010757e10a0c7de7ab505e3d935b9e9496d4b4ba5a89dedffb49ce4a4acdc46',
    'ECBMCT192.rsp': 'a1ad99e7848f6162fbd96d343acdb33a7676657776b09fca88fc54704bf1dabd',
    'ECBMCT256.rsp': 'a70992b1d8a902e2ebf8d8233814b422cf5755f9bbccaffa7fcd2b1c5e02998f',
    'ECBMMT128.rsp': 'de5e02b6ca8eaf4c260579c3c8d09d4b57045de359cd5145836dcb7164abb2bb',
    'ECBMMT192.rsp': '284cc490c2c0ae1c0fc5e9935b30ad2e229e4f595b43fb68828b62d42101783c',
    'ECBMMT256.rsp': '14cea8cfcba191b98cb9c8cbf03c57b82edc76164226a2cacd53810dd60115cb',
}
TESTS = {f'aes{bits}::{name}' for bits in (128, 192, 256)
         for name in ('monte_carlo', 'multiblock', 'malformed_vectors_fail')} | {
    'key_updates_use_the_correct_tail', 'iteration_count_and_penultimate_output_are_exact',
    'campaign_rejects_wrong_outputs_keys_inputs_and_directions'}
MARKERS = [
    f'AESAVS_MCT: {bits} 200 records; 1000 iterations; 2 owners; 400000 block operations'
    for bits in (128, 192, 256)
] + [
    f'AESAVS_MMT: {bits} 20 records; 110 blocks; 2 owners; public encryption checked'
    for bits in (128, 192, 256)
]


def prepare(directory):
    for name in ('avs.rs', *(f'fixtures/{name}' for name in HASHES)):
        source = FIXTURE / name
        packaged.require(source.is_file() and not source.is_symlink()
                         and not any(p.is_symlink() for p in source.parents),
                         'missing or symlinked AESAVS fixture: ' + name)
        if source.name in HASHES:
            packaged.require(hashlib.sha256(source.read_bytes()).hexdigest() == HASHES[source.name],
                             'AESAVS fixture hash mismatch: ' + name)
        target = directory / 'tests' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def check_output(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    packaged.require(len(rows) == 12 and {name for name, _ in rows} == TESTS
                     and all(status == 'ok' for _, status in rows),
                     'missing, duplicated, ignored or failed AESAVS test')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    packaged.require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
        'wrong AESAVS test summary')
    for marker in MARKERS:
        packaged.require(output.splitlines().count(marker) == 1, 'missing/duplicate AESAVS population marker')


def marker(compiler, route):
    return f'AESAVS packaged: PASS; {compiler} {route} release; 600 MCT records; 60 MMT records; both owners'


def check(compiler, route):
    packaged.require(compiler in packaged.consumer.TOOLCHAINS and route in packaged.consumer.ROUTES,
                     'unsupported AESAVS configuration')
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        packaged.require(name not in os.environ, 'remove ambient ' + name)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        prepare(directory)
        cargo = ['cargo', '+' + compiler]
        packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
        selection = ['--locked', '--offline', '--no-default-features', '--features', route]
        metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection], directory, env)
        packaged.graph(json.loads(metadata.stdout), route, directory, root / 'unpacked', versions)
        result = packaged.archives.run(cargo + ['test', *selection, '--release', '--test', 'avs',
                                               '--', '--show-output', '--test-threads=1'], directory, env)
        print(result.stdout, end='', flush=True)
        check_output(result.stdout)
    print(marker(compiler, route), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    parser.add_argument('--route', choices=packaged.consumer.ROUTES, required=True)
    args = parser.parse_args()
    check(args.toolchain, args.route)
