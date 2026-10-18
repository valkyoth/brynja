"""Compiled production-only domain mutants, independent of conformance copies."""
import importlib.util
import shutil
import subprocess


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rejected(result, expected):
    if result.returncode == 0:
        actual = result.stdout.splitlines()
        # The execution fixture computes output; the independent oracle lives
        # in Python. A successful run producing wrong bytes is the rejection.
        return (len(actual) == len(expected) and actual != expected and
                all(len(a) == len(b) and all(c in '0123456789abcdef' for c in a)
                    for a, b in zip(actual, expected)))
    return result.returncode == 1 and 'mismatch' in result.stderr and not result.stdout


def check(root, consumer, roots, env, native_env=None):
    oracle = load(root / 'scripts/kmac/check-kmac-differential.py', 'production_mutant_oracle')
    adapter = load(root / 'scripts/repository/facade_kmac_sources.py', 'production_mutant_adapter')
    portable = consumer.parent / 'portable-production'
    shutil.copytree(root / 'assurance/kmac-differential', portable,
                    ignore=shutil.ignore_patterns('target'))
    manifest = portable / 'Cargo.toml'
    text = manifest.read_text()
    for name, path in roots.items():
        text = text.replace(f'../../crates/{name}"', str(path) + '"')
    text += '\n[patch.crates-io]\n' + '\n'.join(
        f'{name}={{path="{path.as_posix()}"}}' for name, path in roots.items()) + '\n'
    manifest.write_text(text)
    execution = consumer.parent / 'execution-production'
    shutil.copytree(consumer, execution)
    for name in adapter.COUNTS:
        path = execution / 'src' / name
        path.write_text(adapter.production(name, path.read_text()))
    cases = [c for c in oracle.production_cases(oracle.cases()) if c[7] >= 256]
    request = '\n'.join(f'{a} {kb} {k.hex() or "-"} {cb} {c.hex() or "-"} '
        f'{mb} {m.hex() or "-"} {ob}' for a, k, kb, c, cb, m, mb, ob, _ in cases) + '\n'
    expected = [case[-1].hex() for case in cases]
    if {case[0] for case in cases} != {'kmac128', 'kmac256', 'kmacxof128', 'kmacxof256'}:
        raise ValueError('production mutation corpus lost identities')

    def run(fixture, mode, environment):
        command = ['cargo', 'run', '--offline', '--quiet', '--manifest-path', str(fixture / 'Cargo.toml')]
        if mode:
            command += ['--', mode]
        # Resolve Cargo configuration from the checkout, not /tmp ancestors.
        return subprocess.run(command, cwd=root, env=environment, input=request,
                              text=True, capture_output=True, timeout=240)

    profiles = [(portable, None, env), (execution, 'portable', env)]
    if native_env is not None:
        profiles.append((execution, 'static', native_env))
    for fixture, mode, environment in profiles:
        result = run(fixture, mode, environment)
        if result.returncode or result.stdout.splitlines() != expected:
            raise ValueError('production mutant positive control: ' + result.stderr)
    mutants = []
    for name in ('fixed.rs', 'xof.rs'):
        mutants.append((name, 'KmacCore::new_bits(key, customization, StrengthPolicy::Production)',
                        'KmacCore::new_bits(key, key, StrengthPolicy::Production)', 1, profiles[0]))
        mutants.append(('execution/' + name,
            'Core::new(mode, $wide, key, customization, StrengthPolicy::Production)',
            'Core::new(mode, $wide, key, key, StrengthPolicy::Production)', 1, profiles[1]))
    for prefix, profile in [('hardened_in_place/', profiles[0])] + (
            [('hardened_in_place/accelerated/', profiles[2])] if native_env is not None else []):
        mutants += [
            (prefix + 'fixed.rs', 'self.scope(key, customization, operation)',
             'self.scope(key, key, operation)', 2, profile),
            (prefix + 'xof.rs', 'self.inner.with_bits(key, customization, |state| {',
             'self.inner.with_bits(key, key, |state| {', 1, profile),
        ]
    for name, before, after, count, (fixture, mode, environment) in mutants:
        path = roots['brynja-mac-kmac'] / 'src' / name
        original = path.read_text()
        if original.count(before) != count:
            raise ValueError('production-only mutation anchor: ' + name)
        try:
            path.write_text(original.replace(before, after, 1))
            result = run(fixture, mode, environment)
            if not rejected(result, expected):
                raise ValueError('production-only mutant escaped or failed unrelatedly: ' + name + result.stderr)
        finally:
            path.write_text(original)
    print(f'Production-only KMAC oracle mutants: {len(mutants)} rejected; pristine sources restored', flush=True)
