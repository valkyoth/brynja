"""Test public hosted runtime dispatch from archives, without forced-candidate cfgs."""
import argparse
from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
import platform
import runpy
import shlex
import shutil

A = runpy.run_path(str(Path(__file__).with_name('check-packaged-api.py')))
pkg = A['pkg']


def published_table(frozen):
    """Reuse the three literal check(H, cases) calls; never derive an answer."""
    # prepare() already verified this exact archive member against FROZEN.
    sections = frozen.split('\n#[test]\n')[1:]
    if len(sections) != 3:
        raise ValueError('expected three frozen NIST vector families')
    calls = []
    for bits, section in zip((128, 192, 256), sections):
        start = f'fn aes{bits}_published_ghash_intermediates() -> Result<(), Error> {{\n    check('
        end = ')\n}'
        section = section.rstrip()
        if not section.startswith(start) or not section.endswith(end):
            raise ValueError('unexpected frozen NIST vector wrapper')
        calls.append('(' + section[len(start):-len(end)] + ')')
    # Rust checks every entry's types and the exact number of cases per family.
    return 'const PUBLISHED: [(u128, &[(&[u128], u128); 5]); 3] = [\n' + ',\n'.join(calls) + '\n];\n'


@contextmanager
def wrong_startup_answer(src):
    """Change only the private archive, for the duration of the negative control."""
    original = src.read_bytes()
    kat = b'0x5e2ec746917062882c85b0685353deb7'
    if original.count(kat) != 1:
        raise ValueError('ambiguous KAT control')
    try:
        src.write_bytes(original.replace(kat, kat[:-1] + b'6'))
        yield
    finally:
        src.write_bytes(original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    arch = parser.add_mutually_exclusive_group()
    arch.add_argument('--rv64', action='store_true')
    arch.add_argument('--pmull', choices=('linux', 'macos'),
                      help='Linux via QEMU or native Apple Silicon')
    parser.add_argument('--save-facade', '--save-rv64-facade', type=Path, metavar='NEW_DIRECTORY',
                        help='retain the tested facade binaries for native replay')
    opts = parser.parse_args()
    if opts.save_facade:
        opts.save_facade.mkdir(mode=0o700, exist_ok=False)
    target = 'riscv64gc-unknown-linux-gnu' if opts.rv64 else 'x86_64-unknown-linux-gnu'
    if opts.rv64:
        rv = runpy.run_path(str(A['ROOT'] / 'scripts/aes/check-aes-riscv.py'))
        qemu, linker, sysroot = rv['platform_config']()
    if opts.pmull == 'linux':
        target = 'aarch64-unknown-linux-musl'
    if opts.pmull == 'macos':
        if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
            raise ValueError('requires native Apple Silicon')
        target = 'aarch64-apple-darwin'
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError('remove ambient build overrides')
    with pkg.cargo_environment.private_directory(A['ROOT']) as temp:
        root = Path(temp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, A['ENDPOINTS'][-1], env)
        consumers = {}
        for dependency in ('brynja-crypto', 'brynja'):
            c = A['prepare'](root, dependency, versions)
            consumers[dependency] = c
            shutil.copyfile(A['ROOT'] / 'assurance/ghash-runtime-consumer/route.rs', c / 'tests/runtime.rs')
            (c / 'tests/vectors.inc').write_text(published_table((c / 'tests/nist.rs').read_text()))
            pkg.run(['cargo', '+' + A['ENDPOINTS'][0], 'generate-lockfile', '--offline'], c, env)
        flags = ['--locked', '--offline', '--features', 'subject/ghash-runtime-execution']
        cases = [('native', 'zbc'), ('absent', 'zbkc'), ('absent', 'aes'), ('quarantine', 'zbc')] if opts.rv64 else [
            ('native', 'host'), ('absent', 'aes'), ('quarantine', 'host')]
        if opts.pmull:
            cases = [('native', 'pmull'), ('absent', 'pmull-masked'), ('quarantine', 'pmull')]
        for scenario, model in cases:
            control = dict(env, BRYNJA_TEST_GHASH_ROUTE=scenario)
            if opts.rv64:
                isa = {'zbc': 'zbc=true,zbkc=true,zkne=false,zknd=false',
                       'zbkc': 'zbc=false,zbkc=true,zkne=false,zknd=false',
                       'aes': 'zbc=false,zbkc=false,zkne=true,zknd=true'}[model]
                control.update(BRYNJA_TEST_GHASH_RV64_MODEL=model,
                               CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=linker,
                               CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-feature=+crt-static',
                               CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER=shlex.join(
                                   rv['execution'](qemu, sysroot, 'rv64,' + isa)))
            elif opts.pmull:
                prefix = 'CARGO_TARGET_' + target.upper().replace('-', '_')
                if opts.pmull == 'linux':
                    control[prefix + '_LINKER'] = 'rust-lld'
                    control[prefix + '_RUNNER'] = 'qemu-aarch64 -cpu max'
                if scenario == 'absent':
                    control[prefix + '_RUSTFLAGS'] = '--cfg brynja_ghash_deny_pmull'
            elif scenario == 'absent':
                control['CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER'] = 'qemu-x86_64 -cpu max,+aes,-pclmulqdq'
            archive_control = nullcontext()
            if scenario == 'quarantine':
                src = root / 'unpacked' / ('brynja-crypto-cpu-' + versions['brynja-crypto-cpu']) / 'src/ghash_admission.rs'
                archive_control = wrong_startup_answer(src)
                control['CARGO_TARGET_DIR'] = str(root / 'bad-kat-build')
            with archive_control:
                for dep, c in consumers.items():
                    for v in A['ENDPOINTS']:
                        cargo = ['cargo', '+' + v]
                        if scenario == 'native':
                            graph = pkg.run(cargo + ['metadata', *flags, '--format-version', '1'], c, env)
                            A['check_graph'](json.loads(graph.stdout), c, root / 'unpacked', versions, dep, runtime=True)
                            if opts.pmull != 'macos':  # already covered by the Linux cross-build
                                pkg.run(cargo + ['check', *flags, '--target', 'thumbv7em-none-eabi', '--lib'], c, env)
                            # Even the legacy broad CPU opt-in must not expose this bridge.
                            probe = c / 'src/bin/probe.rs'
                            probe.parent.mkdir(exist_ok=True)
                            prefix = 'subject::' + ('crypto::' if dep == 'brynja' else '') + 'cpu::'
                            cmd = cargo + ['check', *flags, '--target', target, '--features', 'subject/cpu', '--bin', 'probe', '--message-format=json']
                            probe.write_text('use ' + prefix + 'Sha256Backend; fn main() {}')
                            pkg.run(cmd, c, control)
                            handle = 'RuntimePmull' if opts.pmull else 'RuntimeRv64' if opts.rv64 else 'RuntimePclmul'
                            probe.write_text('use ' + prefix + handle + '; fn main() {}')
                            result = pkg.cargo_result(cmd, c, control, timeout=120)
                            if not pkg.diagnostic_matches(result, 'E0432', filename='src/bin/probe.rs'):
                                raise ValueError('raw GHASH handle not isolated')
                            probe.unlink()
                        cmd = cargo + ['test', *flags, '--release', '--target', target, '--test', 'runtime']
                        result = pkg.run(cmd, c, control)
                        if not A['exact_suite'](result.stdout, 1):
                            raise ValueError('incomplete runtime test')
                        if opts.save_facade and dep == 'brynja' and (opts.pmull or scenario != 'absent'):
                            artifacts = pkg.run(cmd + ['--no-run', '--message-format=json'], c, control)
                            files = [a['executable'] for a in map(json.loads, artifacts.stdout.splitlines())
                                     if a.get('executable') and a['target']['name'] == 'runtime']
                            if len(files) != 1:
                                raise ValueError('expected exactly one runtime executable')
                            shutil.copy2(files[0], opts.save_facade / (scenario + '-' + v))
                        print(v, dep, scenario, model, 'passed', flush=True)
    if opts.pmull:
        print('GHASH_PACKAGED_PMULL_' + opts.pmull.upper() + '_COMPLETE')
    else:
        print('GHASH_PACKAGED_RV64_RUNTIME_COMPLETE' if opts.rv64 else 'GHASH_PACKAGED_RUNTIME_COMPLETE')


if __name__ == '__main__':
    main()
