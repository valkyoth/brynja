"""Replay frozen downstream GHASH suites on forced, archive-only candidate builds."""
import json
import os
from pathlib import Path
import runpy
import shutil

A = runpy.run_path(str(Path(__file__).with_name('check-packaged-api.py')))
pkg = A['pkg']
TARGETS = {'pclmul': 'x86_64-unknown-linux-gnu', 'pmull': 'aarch64-unknown-linux-musl',
           'rv64': 'riscv64gc-unknown-linux-gnu'}


def target_env(base, kernel, denied):
    env = dict(base, RUSTFLAGS='--cfg brynja_ghash_' + kernel + '_evidence')
    prefix = 'CARGO_TARGET_' + TARGETS[kernel].upper().replace('-', '_')
    if kernel == 'pclmul' and denied:
        env[prefix + '_RUNNER'] = 'qemu-x86_64 -cpu max,+aes,-pclmulqdq'
    elif kernel == 'pmull':
        env[prefix + '_LINKER'] = 'rust-lld'
        env[prefix + '_RUNNER'] = 'qemu-aarch64 -cpu max'
        if denied:
            env['RUSTFLAGS'] += ' --cfg brynja_ghash_deny_pmull'
    elif kernel == 'rv64':
        linker = shutil.which('riscv64-linux-gnu-gcc') or shutil.which('riscv64-suse-linux-gcc')
        if not linker:
            raise ValueError('RV64 GNU cross linker required')
        env[prefix + '_LINKER'] = linker
        env['RUSTFLAGS'] += ' -C target-feature=+crt-static'
        cpu = 'zbc=false,zbkc=false,zkne=true,zknd=true' if denied else 'zbc=true,zbkc=false,zkne=false,zknd=false'
        env[prefix + '_RUNNER'] = 'qemu-riscv64 -cpu rv64,' + cpu
    return env


def check_route(root, dependency, versions, base):
    consumer = A['prepare'](root, dependency, versions)
    for name in ('active.rs', 'denied.rs'):
        shutil.copyfile(A['ROOT'] / 'assurance/ghash-candidate-consumer' / name, consumer / 'tests' / name)
    def run(version, env, *args):
        return pkg.run(['cargo', '+' + version, *args], consumer, env).stdout
    run(A['ENDPOINTS'][0], base, 'generate-lockfile', '--offline')
    flags = ['--locked', '--offline', '--features', 'raw,subject/cpu']
    for version in A['ENDPOINTS']:
        graph = json.loads(run(version, base, 'metadata', *flags, '--format-version', '1'))
        A['check_graph'](graph, consumer, root / 'unpacked', versions, dependency, candidate=True)
        for kernel, target in TARGETS.items():
            for denied in (False, True):
                env = target_env(base, kernel, denied)
                suites = [('denied', 1)] if denied else [('active', 1), ('nist', 3), ('ghash_lifecycle', 4),
                                                         ('consumer', 3)]
                for suite, count in suites:
                    result = run(version, env, 'test', *flags, '--target', target, '--release', '--test', suite)
                    if not A['exact_suite'](result, count):
                        raise ValueError(f'incomplete {version} {dependency}/{kernel}/{suite} suite')
            print(f'{version} {dependency} {kernel}: active and denied archive consumers passed', flush=True)


def main():
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError('remove ambient toolchain, target or compiler overrides')
    with pkg.cargo_environment.private_directory(A['ROOT']) as tmp:
        root = Path(tmp)
        base = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, A['ENDPOINTS'][-1], base)
        for dependency in ('brynja-crypto', 'brynja'):
            check_route(root, dependency, versions, base)
    print('GHASH_PACKAGED_CANDIDATES_COMPLETE')


if __name__ == '__main__':
    main()
