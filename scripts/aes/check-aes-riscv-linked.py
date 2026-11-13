#!/usr/bin/env python3
"""Packaged RV64 LTO leaf, clearing and block-session machine review."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('rv64_linked_base', HERE / 'check-aes-accelerated-linked.py')
linked = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(linked)
campaigns, packaged = linked.campaigns, linked.packaged
riscv = campaigns.riscv
review = packaged.module('rv64_machine', HERE / 'aes_riscv_machine.py')
cleanup = packaged.module('rv64_cleanup', HERE / 'aes_riscv_cleanup.py')
sessions = packaged.module('rv64_sessions', HERE / 'aes_riscv_sessions.py')
constructors = packaged.module('rv64_constructors', HERE / 'aes_riscv_constructors.py')
public = packaged.module('rv64_public', HERE / 'aes_riscv_public.py')
secret = packaged.module('rv64_secret', HERE / 'aes_riscv_secret.py')
require = packaged.require


def output_check(output):
    expected = []
    for bits in (128, 192, 256):
        expected += ['AES_FORCED_AUTHORITY: RiscVScalarAes',
                     f'AES_ACCELERATED_LINKED_KAT: {bits}; six operations; clearing and quarantine checked']
    require(output.splitlines() == expected, 'wrong RV64 linked execution population')


def check(compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unsupported RV64 linked compiler')
    for name in (*packaged.archives.REJECT_ENV, *riscv.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    qemu, linker, sysroot = riscv.platform_config()
    tools = []
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    hashes = [linked.digest(p) for p in tools]
    base = packaged.ROOT / 'target/aes-riscv-linked'
    base.mkdir(parents=True, exist_ok=True)
    retained = Path(tempfile.mkdtemp(prefix=compiler + '-', dir=base))
    print(f'Artifacts: {retained}', flush=True)
    with packaged.archives.cargo_environment.private_directory(packaged.ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        cargo = ['cargo', '+' + compiler]
        identity = packaged.archives.run(['rustc', '+' + compiler, '-vV'], root, env).stdout
        qemu_version = packaged.archives.run([qemu, '--version'], root, env).stdout
        (retained / 'compiler.txt').write_text(identity)
        (retained / 'qemu-version.txt').write_text(qemu_version)
        for route in ('direct', 'facade'):
            directory = root / 'consumers' / route
            linked.prepare(directory, versions, route, 'static')
            packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
            selection = ['--locked', '--offline', '--no-default-features', '--features', route]
            metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection,
                                                      '--filter-platform', riscv.TARGET], directory, env)
            campaigns.graph(json.loads(metadata.stdout), versions, directory, route, 'static')
            (retained / f'{route}-metadata.json').write_text(metadata.stdout)
            build_env = dict(env)
            build_env['CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER'] = linker
            build_env['RUSTFLAGS'] = shlex.join(riscv.phase_config('candidate')[0])
            for panic in ('abort', 'unwind'):
                label = f'{route}-{panic}'
                build_env['CARGO_PROFILE_RELEASE_PANIC'] = panic
                build_env['CARGO_TARGET_DIR'] = str(root / label)
                command = cargo + ['build', *selection, '--release', '--target', riscv.TARGET]
                print(f'Building RV64 {compiler} {label}', flush=True)
                result = packaged.archives.run(command, directory, build_env)
                (retained / f'{label}-build.log').write_text(result.stdout + result.stderr)
                built = root / label / riscv.TARGET / 'release' / campaigns.NAME
                binary = retained / f'{label}.elf'
                shutil.copyfile(built, binary)
                binary.chmod(0o700)
                digest = linked.digest(binary)
                nm = packaged.archives.run([str(tools[0]), '--print-size', '--defined-only', str(binary)], directory, env)
                asm = packaged.archives.run([str(tools[1]), '--disassemble', str(binary)], directory, env)
                require(not nm.stderr and not asm.stderr, 'inspection tool diagnostic')
                (retained / f'{label}.nm').write_text(nm.stdout)
                (retained / f'{label}.asm').write_text(asm.stdout)
                execution = [*riscv.execution(qemu, sysroot), str(binary)]
                result = packaged.archives.run(execution, directory, env)
                (retained / f'{label}-execution.log').write_text(result.stdout + result.stderr)
                require(not result.stderr, 'RV64 linked executable diagnostic')
                output_check(result.stdout)
                print(result.stdout, end='', flush=True)
                analysis = review.inspect(nm.stdout, binary.read_bytes())
                clearing = cleanup.inspect(nm.stdout, binary.read_bytes(), compiler, panic)
                permits = sessions.inspect(nm.stdout, binary.read_bytes(), compiler, panic)
                owners = constructors.inspect(nm.stdout, binary.read_bytes(), compiler, panic)
                outputs = public.inspect(nm.stdout, binary.read_bytes(), compiler, panic)
                secrets = secret.inspect(nm.stdout, binary.read_bytes(), compiler, panic)
                require(linked.digest(binary) == digest and [linked.digest(p) for p in tools] == hashes,
                        'binary or inspection tool changed')
                report = {'compiler': compiler, 'target': riscv.TARGET, 'route': route,
                          'panic': panic, 'profile': linked.PROFILE, 'binary_sha256': digest,
                          'execution': execution, 'build': command, 'rustflags': build_env['RUSTFLAGS'],
                          'tools': [{'path': str(p), 'sha256': h} for p, h in zip(tools, hashes)],
                          'review': analysis, 'cleanup': clearing, 'sessions': permits,
                          'constructors': owners, 'public': outputs, 'secret': secrets,
                          'native_qualification': False}
                (retained / f'{label}.json').write_text(json.dumps(report, indent=2) + '\n')
                print(f'AES_RISCV_LINKED_CONSUMER_PASS: {compiler} {label}; six leaf bodies; nine public paths', flush=True)
                print(f'AES_RISCV_LINKED_CLEANUP_PASS: {compiler} {label}; three exact bodies', flush=True)
                print(f'AES_RISCV_LINKED_SESSION_PASS: {compiler} {label}; six bound block sessions', flush=True)
                print(f'AES_RISCV_LINKED_CONSTRUCTOR_PASS: {compiler} {label}; six bound key constructors', flush=True)
                print(f'AES_RISCV_LINKED_PUBLIC_PASS: {compiler} {label}; six bound public encryption paths', flush=True)
                print(f'AES_RISCV_LINKED_SECRET_PASS: {compiler} {label}; six bound secret output bodies; both directions', flush=True)
    print(f'AES_RISCV_LINKED_PASS: {compiler}; four QEMU consumers; bounded leaf and clearing review')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    args = parser.parse_args()
    check(args.toolchain)
