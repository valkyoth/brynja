#!/usr/bin/env python3
"""Packaged RV64 startup review and 688 corrupted-answer QEMU controls."""
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
review = packaged.module('rv64_startup', HERE / 'aes_riscv_startup.py')
require = packaged.require


def output_check(output, corrupt=False):
    expected = 'AES_RISCV_STARTUP_QUARANTINED' if corrupt else 'AES_RISCV_STARTUP_PASS'
    require(output.splitlines() == [expected], 'wrong RV64 startup execution population')


def check(compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unsupported RV64 startup compiler')
    for name in (*packaged.archives.REJECT_ENV, *riscv.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    qemu, linker, sysroot = riscv.platform_config()
    source = packaged.ROOT / 'assurance/aes-accelerated-campaigns/startup-riscv.rs'
    require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)),
            'missing or symlinked startup fixture')
    source_hash = linked.digest(source)
    tools = []
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    hashes = [linked.digest(p) for p in tools]
    base = packaged.ROOT / 'target/aes-riscv-startup'
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
            (directory / 'src').mkdir(parents=True)
            shutil.copyfile(source, directory / 'src/main.rs')
            (directory / 'Cargo.toml').write_text(campaigns.manifest(versions, route, 'static') +
                'opt-level=3\nlto="fat"\ncodegen-units=1\nstrip=false\n')
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
                image = binary.read_bytes()
                analysis = review.inspect(nm.stdout, image, compiler, panic)
                rejected = []
                negative = root / (label + '-corrupt.elf')
                for case, changed in review.corruption_cases(image, analysis['references']):
                    negative.write_bytes(changed)
                    negative.chmod(0o700)
                    result = packaged.archives.run([*riscv.execution(qemu, sysroot), str(negative),
                                                   'expect-quarantined'], directory, env)
                    require(not result.stderr, 'corrupted startup diagnostic: ' + case)
                    output_check(result.stdout, corrupt=True)
                    rejected.append(case)
                require(len(rejected) == len(set(rejected)) == 688, 'wrong startup quarantine population')
                require(linked.digest(binary) == digest and linked.digest(source) == source_hash
                        and [linked.digest(p) for p in tools] == hashes,
                        'binary or inspection tool changed')
                report = {'compiler': compiler, 'target': riscv.TARGET, 'route': route,
                          'panic': panic, 'profile': linked.PROFILE, 'binary_sha256': digest,
                          'execution': execution, 'build': command, 'rustflags': build_env['RUSTFLAGS'],
                          'tools': [{'path': str(p), 'sha256': h} for p, h in zip(tools, hashes)],
                          'review': analysis, 'executed_quarantine_cases': rejected,
                          'fixture_sha256': source_hash,
                          'native_qualification': False}
                (retained / f'{label}.json').write_text(json.dumps(report, indent=2) + '\n')
                print(f'AES_RISCV_STARTUP_CONSUMER_PASS: {compiler} {label}; 688 corrupted-answer executions quarantined', flush=True)
    print(f'AES_RISCV_STARTUP_LINKED_PASS: {compiler}; four evidence-only QEMU consumers')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    args = parser.parse_args()
    try:
        check(args.toolchain)
    except (OSError, ValueError) as error:
        raise SystemExit('RV64 startup failed: ' + str(error))
