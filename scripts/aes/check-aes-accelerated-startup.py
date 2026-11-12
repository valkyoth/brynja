#!/usr/bin/env python3
"""Packaged ARM startup: Linux review or explicit Apple capture-only execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('startup_linked', HERE / 'check-aes-accelerated-linked.py')
linked = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linked)
packaged, campaigns = linked.packaged, linked.campaigns
ROOT, require = linked.ROOT, linked.require
TARGET = 'aarch64-unknown-linux-musl'


def native_probe(root, directory, env, compiler, target=TARGET):
    probe = root / 'baseline-probe'
    packaged.archives.run(['rustc', '+' + compiler, '--edition=2024',
        str(ROOT / 'assurance/aes-kernel-candidate/probe.rs'), '--target', target,
        *(['-C', 'linker=rust-lld'] if target == TARGET else []),
        '-o', str(probe)], directory, env)
    result = packaged.archives.run([str(probe)], directory, env)
    require(not result.stderr and result.stdout.splitlines() == ['AES_STATIC_HOST_BUNDLE_PASS'],
            'native ARM baseline ISA probe failed')


def check(compiler, capture_only=False, admission='static', mode='arm-qemu'):
    require(compiler in ('1.90.0', '1.99.1'), 'unsupported startup compiler')
    require(admission in ('static', 'hosted'), 'unsupported startup admission')
    require(mode in ('arm-qemu', 'arm-native', 'apple-native'), 'unsupported ARM startup execution mode')
    target, _, emulated = linked.execution_configuration(mode, platform.system(), platform.machine())
    apple = target == 'aarch64-apple-darwin'
    require(not apple or capture_only,
            'Apple startup requires --capture-only; machine review is not implemented')
    suffix, nm_arguments = linked.inspection_configuration(target)
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    source = ROOT / 'assurance/aes-accelerated-campaigns' / ('startup-hosted.rs' if admission=='hosted' else 'startup.rs')
    marker = 'AES_ARM_HOSTED_STARTUP' if admission=='hosted' else 'AES_ARM_STARTUP'
    require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)),
            'missing or symlinked startup fixture')
    tools = []
    for name in ('llvm-nm', 'llvm-objdump', *(['qemu-aarch64'] if emulated else [])):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    hashes = [linked.digest(p) for p in tools]
    execution_prefix = [str(tools[2]), '-cpu', 'max'] if emulated else []
    consumers = ('native Apple AArch64 consumers' if apple else
                 'emulated consumers' if emulated else 'native AArch64 musl consumers')
    base = ROOT / 'target/aes-accelerated-startup'
    base.mkdir(parents=True, exist_ok=True)
    retained = Path(tempfile.mkdtemp(prefix=compiler+'-'+admission+'-'+mode+'-', dir=base))
    print(f'Artifacts: {retained}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        if not emulated and admission == 'static':
            native_probe(root, root, env, compiler, target)
        cargo = ['cargo', '+'+compiler]
        for route in ('direct', 'facade'):
            directory = root / 'consumers' / route
            (directory / 'src').mkdir(parents=True)
            shutil.copyfile(source, directory / 'src/main.rs')
            (directory / 'Cargo.toml').write_text(campaigns.manifest(versions, route, admission) +
                'opt-level=3\nlto="fat"\ncodegen-units=1\nstrip=false\n')
            packaged.archives.run(cargo+['generate-lockfile', '--offline'], directory, env)
            selection = ['--locked', '--offline', '--no-default-features', '--features', route+(',hosted' if admission=='hosted' else '')]
            metadata = packaged.archives.run(cargo+['metadata', '--format-version=1', *selection,
                '--filter-platform', target], directory, env)
            campaigns.graph(json.loads(metadata.stdout), versions, directory, route, admission)
            (retained / f'{route}-metadata.json').write_text(metadata.stdout)
            for panic in ('abort', 'unwind'):
                label = route+'-'+panic
                build_env = dict(env, RUSTFLAGS='-Ctarget-feature=-aes' if admission=='hosted' else '-Ctarget-feature=+aes,+neon',
                    CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_TARGET_DIR=str(root/label))
                if not apple:
                    build_env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = 'rust-lld'
                print(f'Building startup {compiler} {label}', flush=True)
                build = packaged.archives.run(cargo+['build', *selection, '--release', '--target', target], directory, build_env)
                (retained / f'{label}-build.log').write_text(build.stdout+build.stderr)
                binary = retained / f'{label}{suffix}'
                shutil.copyfile(root/label/target/'release'/campaigns.NAME, binary)
                binary.chmod(0o700)
                digest = linked.digest(binary)
                symbol_command = [str(tools[0]), *nm_arguments, str(binary)]
                nm = packaged.archives.run(symbol_command, directory, env)
                asm = packaged.archives.run([str(tools[1]), '--disassemble', '--no-print-imm-hex', str(binary)], directory, env)
                require(not nm.stderr and not asm.stderr, 'startup inspection diagnostic')
                (retained / f'{label}.nm').write_text(nm.stdout)
                (retained / f'{label}.asm').write_text(asm.stdout)
                execution = packaged.archives.run([*execution_prefix, str(binary)], directory, env)
                require(not execution.stderr and execution.stdout.splitlines() == [marker+'_PASS'],
                        'startup execution population changed')
                (retained / f'{label}-execution.log').write_text(execution.stdout)
                report = dict(compiler=compiler, route=route, panic=panic, target=target, admission=admission,
                    profile=linked.PROFILE, execution='qemu-emulated' if emulated else 'native', binary_sha256=digest,
                    machine_review='not-performed' if capture_only else 'scoped-review',
                    symbol_command=symbol_command, fixture_sha256=linked.digest(source),
                    execution_command=[*execution_prefix, str(binary)],
                    host=dict(system=platform.system(), machine=platform.machine()),
                    tools=[dict(path=str(p), sha256=h) for p,h in zip(tools, hashes)])
                if not capture_only:
                    reviewer = packaged.module('startup_review', HERE/('aes_accelerated_startup_hosted.py' if admission=='hosted' else 'aes_accelerated_startup_arm.py'))
                    report['review'] = reviewer.inspect(nm.stdout, asm.stdout, binary.read_bytes(), compiler, panic)
                    negative = root / (label+'-corrupt.elf')
                    rejected = []
                    for case, changed in reviewer.corruption_cases(binary.read_bytes(), report['review']['references']):
                        negative.write_bytes(changed)
                        negative.chmod(0o700)
                        result = packaged.archives.run([*execution_prefix, str(negative),
                            'expect-quarantined'], directory, env)
                        require(not result.stderr and result.stdout.splitlines() == [marker+'_QUARANTINED'],
                                'corrupted startup answer was not quarantined: '+case)
                        rejected.append(case)
                    require(len(rejected) == 628 and len(set(rejected)) == 628, 'startup quarantine population changed')
                    report['executed_quarantine_cases'] = rejected
                    print(f'{label}: 628 corrupted-answer executions quarantined', flush=True)
                    if admission=='hosted':
                        unavailable=[]
                        for case,changed in reviewer.admission_cases(nm.stdout,asm.stdout,binary.read_bytes(),compiler,panic):
                            negative.write_bytes(changed)
                            result=packaged.archives.run([*execution_prefix,str(negative),
                                'expect-unavailable'],directory,env)
                            require(not result.stderr and result.stdout.splitlines()==[marker+'_UNAVAILABLE'],
                                    'missing AES/PMULL control was admitted: '+case)
                            unavailable.append(case)
                        require(unavailable==['warm-aes-absent','cold-aes-absent',
                                              'warm-pmull-absent','cold-pmull-absent'],
                                'admission control population changed')
                        report['executed_unavailable_controls']=unavailable
                require(linked.digest(binary) == digest and [linked.digest(p) for p in tools] == hashes,
                        'startup binary or inspection tool changed')
                (retained / f'{label}.json').write_text(json.dumps(report, indent=2)+'\n')
    if capture_only:
        print(f'AES startup CAPTURE ONLY: four {consumers}; machine review NOT performed')
    else:
        print(f'{marker}_LINKED_PASS: {compiler}; four {admission} {consumers}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--capture-only', action='store_true')
    parser.add_argument('--admission', choices=('static', 'hosted'), default='static')
    parser.add_argument('--mode', choices=('arm-qemu', 'arm-native', 'apple-native'), default='arm-qemu',
                        help='Apple requires --capture-only; Linux modes support scoped machine review')
    args = parser.parse_args()
    try:
        check(args.toolchain, args.capture_only, args.admission, args.mode)
    except (OSError, ValueError) as error:
        raise SystemExit('AES startup failed: '+str(error))
