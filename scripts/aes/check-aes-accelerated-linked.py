#!/usr/bin/env python3
"""Packaged accelerated final-linked kernels; surrounding callers remain separate review work."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('accelerated_linked_campaigns', HERE / 'check-aes-accelerated-campaigns.py')
campaigns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaigns)
packaged = campaigns.packaged
ROOT = packaged.ROOT
require = packaged.require
PROFILE = 'opt3-fat-lto-cgu1-overflow'


def execution_configuration(mode, system, machine):
    if mode == 'apple-native':
        require(system == 'Darwin' and machine == 'arm64',
                'apple-native requires a real Apple AArch64 host')
        return 'aarch64-apple-darwin', True, False
    require(system == 'Linux', 'linked runner requires Linux')
    if mode == 'arm-native':
        require(machine == 'aarch64', 'arm-native requires a real Linux AArch64 host')
        return 'aarch64-unknown-linux-musl', True, False
    require(mode in ('native', 'arm-qemu') and machine == 'x86_64',
            'native x86 / ARM QEMU modes require a Linux x86 host')
    return ('aarch64-unknown-linux-musl', True, True) if mode == 'arm-qemu' else (
        'x86_64-unknown-linux-gnu', False, False)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspection_configuration(target):
    # Mach-O has no ELF symbol-size field. Capture symbols without invented
    # sizes; the ELF reviewers must never consume these observations.
    if target == 'aarch64-apple-darwin':
        return '.macho', ['--defined-only']
    require(target in ('aarch64-unknown-linux-musl', 'x86_64-unknown-linux-gnu'),
            'unsupported inspection target')
    return '.elf', ['--print-size', '--defined-only']


def output_check(output, arm):
    expected = []
    for bits in (128, 192, 256):
        expected += ['AES_FORCED_AUTHORITY: ' + ('ArmAes' if arm else 'X86AesNi'),
            f'AES_ACCELERATED_LINKED_KAT: {bits}; six operations; clearing and quarantine checked']
    require(output.splitlines() == expected, 'wrong final-linked execution population')


def kernel_reviews(nm, assembly, image, target):
    rounds = packaged.module('accelerated_kernel_review', HERE / 'aes_accelerated_linked_kernels.py')
    expansion = packaged.module('accelerated_expansion_review', HERE / 'aes_accelerated_linked_expansion.py')
    return {'kernel_review': rounds.inspect(nm, assembly, image, target),
            'expansion_review': expansion.inspect(nm, assembly, image, target)}


def prepare(directory, versions, route, admission):
    (directory / 'src').mkdir(parents=True)
    for source, target in (('lib.rs', 'lib.rs'), ('linked.rs', 'main.rs'), ('lifecycle.rs', 'lifecycle.rs')):
        path = ROOT / 'assurance/aes-accelerated-campaigns' / source
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
                'missing or symlinked linked fixture')
        shutil.copyfile(path, directory / 'src' / target)
    text = campaigns.manifest(versions, route, admission)
    (directory / 'Cargo.toml').write_text(text + 'opt-level=3\nlto="fat"\ncodegen-units=1\nstrip=false\n')


def check(compiler, mode, admission, capture_only=False, review_cached_public=False, review_cached_secret=False,
          review_ephemeral_secret=False, review_ephemeral_public=False, review_lifecycle=False,
          review_arm_cleanup=False, review_arm_constructors=False, review_arm_cached=False,
          review_arm_ephemeral=False):
    require(compiler in ('1.90.0', '1.99.1') and mode in ('native', 'arm-qemu', 'arm-native', 'apple-native')
            and admission in ('static', 'hosted'), 'unsupported linked configuration')
    target, arm, emulated = execution_configuration(mode, platform.system(), platform.machine())
    apple = target == 'aarch64-apple-darwin'
    require(not apple or capture_only,
            'Apple Mach-O capture requires --capture-only; machine review is not implemented')
    suffix, nm_arguments = inspection_configuration(target)
    require(not (mode == 'native' and admission == 'hosted'), 'native x86 hosted route is not admitted')
    require(not review_cached_public or (mode == 'native' and admission == 'static' and not capture_only),
            'cached-public review requires native static execution, not capture-only')
    require(not review_cached_secret or (mode == 'native' and admission == 'static' and not capture_only
            and not review_cached_public), 'cached-secret review requires exclusive native static execution')
    require(not review_ephemeral_secret or (mode == 'native' and admission == 'static' and not capture_only
            and not review_cached_public and not review_cached_secret),
            'ephemeral-secret review requires exclusive native static execution')
    require(not review_ephemeral_public or (mode == 'native' and admission == 'static' and not capture_only
            and not review_cached_public and not review_cached_secret and not review_ephemeral_secret),
            'ephemeral-public review requires exclusive native static execution')
    require(not review_lifecycle or (mode == 'native' and admission == 'static' and not capture_only
            and not any((review_cached_public, review_cached_secret, review_ephemeral_secret, review_ephemeral_public))),
            'lifecycle review requires exclusive native static execution')
    require(not review_arm_cleanup or (arm and not capture_only
            and not any((review_cached_public, review_cached_secret, review_ephemeral_secret,
                         review_ephemeral_public, review_lifecycle))),
            'ARM cleanup review requires exclusive ARM execution')
    require(not review_arm_constructors or (arm and not capture_only
            and not any((review_cached_public, review_cached_secret, review_ephemeral_secret,
                         review_ephemeral_public, review_lifecycle, review_arm_cleanup))),
            'ARM constructor review requires exclusive ARM execution')
    require(not review_arm_cached or (arm and not capture_only
            and not any((review_cached_public, review_cached_secret, review_ephemeral_secret,
                         review_ephemeral_public, review_lifecycle, review_arm_cleanup, review_arm_constructors))),
            'ARM cached review requires exclusive ARM execution')
    require(not review_arm_ephemeral or (arm and not capture_only
            and not any((review_cached_public, review_cached_secret, review_ephemeral_secret,
                         review_ephemeral_public, review_lifecycle, review_arm_cleanup,
                         review_arm_constructors, review_arm_cached))),
            'ARM ephemeral review requires exclusive ARM execution')
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    tools = []
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    before = [digest(p) for p in tools]
    base = ROOT / 'target/aes-accelerated-linked'
    base.mkdir(parents=True, exist_ok=True)
    retained = Path(tempfile.mkdtemp(prefix=f'{compiler}-{mode}-{admission}-', dir=base))
    print(f'Artifacts: {retained}', flush=True)
    execution_prefix = ['qemu-aarch64', '-cpu', 'max'] if emulated else []
    arm_consumers = 'emulated consumers' if emulated else 'native AArch64 musl consumers'
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        cargo = ['cargo', '+' + compiler]
        for route in ('direct', 'facade'):
            directory = root / 'consumers' / route
            prepare(directory, versions, route, admission)
            packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
            selection = ['--locked', '--offline', '--no-default-features', '--features',
                         route + (',hosted' if admission == 'hosted' else '')]
            metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection,
                                                      '--filter-platform', target], directory, env)
            campaigns.graph(json.loads(metadata.stdout), versions, directory, route, admission)
            (retained / f'{route}-metadata.json').write_text(metadata.stdout)
            build_env = dict(env)
            if arm and not apple:
                build_env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = 'rust-lld'
            if admission == 'static':
                probe = root / 'probe'
                packaged.archives.run(['rustc', '+' + compiler, '--edition=2024',
                    str(ROOT / 'assurance/aes-kernel-candidate/probe.rs'), '--target', target,
                    '-o', str(probe), *(['-C', 'linker=rust-lld'] if arm and not apple else [])], directory, env)
                observed = packaged.archives.run([*execution_prefix,
                                                  str(probe)], directory, env)
                require(observed.stdout.splitlines() == ['AES_STATIC_HOST_BUNDLE_PASS'], 'ISA probe failed')
            build_env['RUSTFLAGS'] = ('-Ctarget-feature=-aes' if admission == 'hosted' else
                '-Ctarget-feature=+aes,+neon' if arm else '-Ctarget-feature=+aes,+sse2')
            for panic in ('abort', 'unwind'):
                label = f'{route}-{panic}'
                build_env['CARGO_PROFILE_RELEASE_PANIC'] = panic
                build_env['CARGO_TARGET_DIR'] = str(root / label)
                print(f'Building {compiler} {mode} {admission} {label}', flush=True)
                result = packaged.archives.run(cargo + ['build', *selection, '--release', '--target', target], directory, build_env)
                (retained / f'{label}-build.log').write_text(result.stdout + result.stderr)
                built = Path(build_env['CARGO_TARGET_DIR']) / target / 'release' / campaigns.NAME
                binary = retained / f'{label}{suffix}'
                shutil.copyfile(built, binary)
                binary.chmod(0o700)
                binary_hash = digest(binary)
                nm = packaged.archives.run([str(tools[0]), *nm_arguments, str(binary)], directory, env)
                asm = packaged.archives.run([str(tools[1]), '--disassemble', '--no-print-imm-hex', str(binary)], directory, env)
                require(not nm.stderr and not asm.stderr, 'inspection tool diagnostic')
                (retained / f'{label}.nm').write_text(nm.stdout)
                (retained / f'{label}.asm').write_text(asm.stdout)
                result = packaged.archives.run([*execution_prefix,
                                               str(binary)], directory, env)
                (retained / f'{label}-execution.log').write_text(result.stdout + result.stderr)
                require(not result.stderr, 'linked executable diagnostic')
                output_check(result.stdout, arm)
                require(digest(binary) == binary_hash and [digest(p) for p in tools] == before,
                        'binary or inspection tool changed')
                print(result.stdout, end='', flush=True)
                report = {'compiler': compiler, 'target': target, 'route': route, 'admission': admission,
                          'panic': panic, 'profile': PROFILE, 'binary_sha256': binary_hash,
                          'execution': 'qemu-emulated' if emulated else 'native',
                          'execution_command': [*execution_prefix, str(binary)],
                          'machine_review': 'not-performed' if capture_only else 'scoped-review',
                          'symbol_command': [str(tools[0]), *nm_arguments, str(binary)],
                          'host': {'system': platform.system(), 'machine': platform.machine()},
                          'tools': [{'path': str(p), 'sha256': h} for p, h in zip(tools, before)]}
                if not capture_only:
                    report.update(kernel_reviews(nm.stdout, asm.stdout, binary.read_bytes(), target))
                    require(digest(binary) == binary_hash and [digest(p) for p in tools] == before,
                            'binary or inspection tool changed during kernel review')
                if review_arm_cleanup or review_arm_constructors or review_arm_cached or review_arm_ephemeral:
                    arm_kind = ('arm_ephemeral' if review_arm_ephemeral else 'arm_cached' if review_arm_cached
                                else 'arm_constructors' if review_arm_constructors else 'arm_cleanup')
                    cleanup = packaged.module('accelerated_arm_review', HERE / f'aes_accelerated_linked_{arm_kind}.py')
                    report[arm_kind + '_review'] = cleanup.inspect(
                        nm.stdout, asm.stdout, binary.read_bytes(), compiler, panic, admission)
                    require(digest(binary) == binary_hash and [digest(p) for p in tools] == before,
                            'binary or inspection tool changed during ARM review')
                if review_cached_public or review_cached_secret or review_ephemeral_secret or review_ephemeral_public or review_lifecycle:
                    relocations = packaged.archives.run([str(tools[1]), '--dynamic-reloc', str(binary)], directory, env)
                    require(not relocations.stderr, 'relocation tool diagnostic')
                    (retained / f'{label}-relocations.txt').write_text(relocations.stdout)
                    kind = ('lifecycle' if review_lifecycle else 'ephemeral_public' if review_ephemeral_public else 'ephemeral' if review_ephemeral_secret
                            else 'secret' if review_cached_secret else 'public')
                    callers = packaged.module('accelerated_caller_review', HERE / f'aes_accelerated_linked_{kind}.py')
                    key = ('lifecycle_review' if review_lifecycle else 'ephemeral_public_review' if review_ephemeral_public else 'ephemeral_secret_review'
                           if review_ephemeral_secret else f'cached_{kind}_review')
                    report[key] = callers.inspect(
                        nm.stdout, asm.stdout, binary.read_bytes(), compiler, panic, relocations.stdout)
                    require(digest(binary) == binary_hash and [digest(p) for p in tools] == before,
                            'binary or inspection tool changed during caller review')
                (retained / f'{label}.json').write_text(json.dumps(report, indent=2) + '\n')
    if capture_only:
        print('AES accelerated linked CAPTURE ONLY: four executed consumers; machine review NOT performed')
    elif review_cached_public:
        print(f'AES_ACCELERATED_PUBLIC_LINKED_PASS: {compiler}; four consumers; x86 cached public wrappers, kernels and volatile clear')
    elif review_cached_secret:
        print(f'AES_ACCELERATED_SECRET_LINKED_PASS: {compiler}; four consumers; x86 cached secret wrappers, kernels, copy and volatile clear')
    elif review_ephemeral_secret:
        print(f'AES_ACCELERATED_EPHEMERAL_LINKED_PASS: {compiler}; four consumers; x86 cached and ephemeral secret wrappers, expansion closure, kernels, copy and volatile clear')
    elif review_ephemeral_public:
        print(f'AES_ACCELERATED_EPHEMERAL_PUBLIC_LINKED_PASS: {compiler}; four consumers; x86 per-operation public wrappers and replayed operation dependency closure')
    elif review_lifecycle:
        print(f'AES_ACCELERATED_LIFECYCLE_LINKED_PASS: {compiler}; four consumers; x86 constructors, retained destruction bodies and replayed operation closure')
    elif review_arm_cleanup:
        print(f'AES_ACCELERATED_ARM_CLEANUP_LINKED_PASS: {compiler} {admission}; four {arm_consumers}; volatile clear, retained destruction bodies and round kernels')
    elif review_arm_constructors:
        print(f'AES_ACCELERATED_ARM_CONSTRUCTORS_LINKED_PASS: {compiler} {admission}; four {arm_consumers}; six constructors, copy, expansion and cleanup closure')
    elif review_arm_cached:
        print(f'AES_ACCELERATED_ARM_CACHED_LINKED_PASS: {compiler} {admission}; four {arm_consumers}; cached public/secret callers and replayed constructor closure')
    elif review_arm_ephemeral:
        print(f'AES_ACCELERATED_ARM_EPHEMERAL_LINKED_PASS: {compiler} {admission}; four {arm_consumers}; per-operation public/secret callers and replayed cached closure')
    else:
        print(f'AES_ACCELERATED_LINKED_PASS: {compiler} {mode} {admission}; four consumers; kernel bodies only')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--mode', choices=('native', 'arm-qemu', 'arm-native', 'apple-native'), default='native',
                        help='native is Linux x86; arm-native is Linux AArch64 musl; apple-native is Mach-O capture only')
    parser.add_argument('--admission', choices=('static', 'hosted'), default='static')
    parser.add_argument('--capture-only', action='store_true', help='retain artifacts without a machine-review pass')
    review = parser.add_mutually_exclusive_group()
    review.add_argument('--review-cached-public', action='store_true', help='also review x86 cached public-encryption wrappers')
    review.add_argument('--review-cached-secret', action='store_true', help='also review x86 cached secret-output wrappers')
    review.add_argument('--review-ephemeral-secret', action='store_true', help='also review x86 cached and per-operation secret-output wrappers and expansion')
    review.add_argument('--review-ephemeral-public', action='store_true', help='also review x86 per-operation public-output fixture wrappers and replay prior operation reviews')
    review.add_argument('--review-lifecycle', action='store_true', help='also review x86 constructor and retained destruction fixture bodies and replay operation reviews')
    review.add_argument('--review-arm-cleanup', action='store_true', help='also review AArch64 musl volatile clear and retained destruction bodies')
    review.add_argument('--review-arm-constructors', action='store_true', help='also review AArch64 musl constructors, copy, expansion and replay cleanup')
    review.add_argument('--review-arm-cached', action='store_true', help='also review AArch64 musl cached public/secret callers and replay constructor closure')
    review.add_argument('--review-arm-ephemeral', action='store_true', help='also review AArch64 musl per-operation public/secret callers and replay cached closure')
    args = parser.parse_args()
    check(args.toolchain, args.mode, args.admission, args.capture_only, args.review_cached_public,
          args.review_cached_secret, args.review_ephemeral_secret, args.review_ephemeral_public, args.review_lifecycle,
          args.review_arm_cleanup, args.review_arm_constructors, args.review_arm_cached, args.review_arm_ephemeral)
