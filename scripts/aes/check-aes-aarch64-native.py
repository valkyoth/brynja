#!/usr/bin/env python3
"""Archive-only native ARM AES correctness; retained ELF files are not code review."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_arm_lifecycle', HERE / 'check-aes-linked-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
linked, packaged = lifecycle.linked, lifecycle.packaged
require = packaged.require
TARGET = 'aarch64-unknown-linux-gnu'


def elf_check(data):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01',
            'expected little-endian ELF64 executable')
    kind, machine, version = struct.unpack_from('<HHI', data, 16)
    require(kind in (2, 3) and machine == 183 and version == 1,
            'expected final-linked AArch64 ELF, not object or another architecture')
    require(struct.unpack_from('<Q', data, 24)[0] != 0, 'missing executable entry point')


def marker(compiler, route, panic):
    require(compiler in packaged.consumer.TOOLCHAINS and route in packaged.consumer.ROUTES
            and panic in ('abort', 'unwind'), 'unsupported native ARM configuration')
    count = 48 if panic == 'unwind' else 0
    return (f'AES ARM native: PASS; {compiler}; {route}; {panic}; 18 operations; '
            f'72 normal lifecycle cases; {count} caller unwinds; final-linked artifacts retained; '
            'machine-code qualification not claimed')


def build(root, directory, versions, compiler, route, panic, env):
    marker(compiler, route, panic)
    env = {**env, 'CARGO_PROFILE_RELEASE_PANIC': panic,
           'CARGO_TARGET_DIR': str(root / f'arm-{compiler}-{route}-{panic}')}
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection,
                                             '--filter-platform', TARGET], directory, env)
    packaged.graph(json.loads(metadata.stdout), route, directory, root / 'unpacked', versions)
    packaged.archives.run(cargo + ['build', *selection, '--release', '--bin', 'linked',
                                   '--bin', 'lifecycle', '--target', TARGET], directory, env)
    return Path(env['CARGO_TARGET_DIR']) / TARGET / 'release', env


def observe(binary, directory, env, tools, destination):
    data = binary.read_bytes()
    elf_check(data)
    digest = hashlib.sha256(data).hexdigest()
    reports = {}
    for name, options, suffix in (('llvm-nm', ['--print-size', '--defined-only'], '.nm'),
                                  ('llvm-objdump', ['--disassemble'], '.asm')):
        result = packaged.archives.run([str(tools[name]), *options, str(binary)], directory, env)
        require(not result.stderr and result.stdout.strip(), 'empty/diagnostic ARM inspection output')
        reports[suffix] = result.stdout.encode()
    # Require the expected portable helper population, without applying x86
    # instruction policies to ARM. These are observations, not qualification.
    require(len(linked.symbols(reports['.nm'].decode())) == 11, 'missing portable helper population')
    for suffix, content in {'.elf': data, **reports}.items():
        path = destination / (binary.name + suffix)
        with path.open('xb') as handle:
            handle.write(content)
        print(json.dumps({'artifact': str(path.relative_to(linked.ROOT)),
                          'sha256': hashlib.sha256(content).hexdigest()}), flush=True)
    result = packaged.archives.run([str(binary)], directory, env)
    print(result.stdout, end='', flush=True)
    require(not result.stderr, 'native ARM executable diagnostic')
    require(linked.file_digest(binary) == digest, 'native ARM executable changed during execution')
    return result.stdout


def check(compiler):
    require(compiler in packaged.consumer.TOOLCHAINS, 'unsupported native ARM compiler')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64',
            'requires native Linux AArch64; emulation does not qualify')
    for name in linked.REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    tools = {}
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools[name] = Path(path).resolve(strict=True)
    hashes = {name: linked.file_digest(path) for name, path in tools.items()}
    with packaged.archives.cargo_environment.private_directory(linked.ROOT) as temporary:
        root = Path(temporary)
        # Never replace an earlier attempt's artifacts, including failed runs.
        retained = Path(tempfile.mkdtemp(prefix=f'aes-arm-native-{compiler}-', dir=linked.ROOT / 'target'))
        print(json.dumps({'retained': str(retained.relative_to(linked.ROOT)),
                          'host': platform.platform(), 'machine': platform.machine(),
                          'target': TARGET, 'profile': linked.PROFILE}), flush=True)
        env = packaged.archives.isolated_env(root)
        for name, path in tools.items():
            print(json.dumps({'tool': str(path), 'sha256': hashes[name],
                              'version': packaged.archives.run([str(path), '--version'], root, env).stdout}), flush=True)
        print(packaged.archives.run(['rustc', '+' + compiler, '-vV'], root, env).stdout, flush=True)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        lifecycle.prepare(directory)
        packaged.archives.run(['cargo', '+' + compiler, 'generate-lockfile', '--offline'], directory, env)
        for route in packaged.consumer.ROUTES:
            for panic in ('abort', 'unwind'):
                binaries, build_env = build(root, directory, versions, compiler, route, panic, env)
                destination = retained / f'{route}-{panic}'
                destination.mkdir()
                linked.output_check(observe(binaries / 'linked', directory, build_env, tools, destination))
                lifecycle.output_check(observe(binaries / 'lifecycle', directory, build_env, tools, destination), panic)
                require({name: linked.file_digest(path) for name, path in tools.items()} == hashes,
                        'ARM inspection tool changed during observation')
                print(marker(compiler, route, panic), flush=True)
    print(f'AES ARM native completed: {compiler}; four configurations; correctness only; no timing or machine-code approval', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    check(parser.parse_args().toolchain)
