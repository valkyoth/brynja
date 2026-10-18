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
    cases = [c for c in oracle.production_cases(oracle.cases() + oracle.production_byte_cases())
             if c[7] >= 256]
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
    # These preserve algorithm bytes for valid inputs. Only explicit rejection
    # of weak keys/tags can catch a production-to-conformance policy downgrade.
    for before in (
        'KmacCore::new_bits(key, customization, StrengthPolicy::Production)',
        'self.finish_tag(None, output, StrengthPolicy::Production)',
        'self.verify_inner(None, candidate, StrengthPolicy::Production)',
    ):
        mutants.append(('fixed.rs', before, before.replace('::Production', '::Conformance'),
                        1, profiles[0]))
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
    separation_mutants(root, consumer, roots, env)


def separation_mutants(root, consumer, roots, env):
    """Compile real verifier leaks and a future unclassified policy variant."""
    gate = load(root / 'scripts/kmac/check-kmac-conformance-enabled.py', 'enabled_gate')
    fixture = consumer.parent / 'conformance-negatives'
    shutil.copytree(root / 'assurance/kmac-conformance-rejected', fixture,
                    ignore=shutil.ignore_patterns('target'))
    manifest = fixture / 'Cargo.toml'
    manifest.write_text(manifest.read_text().replace('../../crates/brynja-mac-kmac',
                        roots['brynja-mac-kmac'].as_posix()) +
                        '\n[patch.crates-io]\n' + '\n'.join(
                            f'{name}={{path="{path.as_posix()}"}}' for name, path in roots.items()))
    command = ['cargo', 'check', '--offline', '--manifest-path', str(manifest),
               '--features', 'enabled', '--message-format=json']

    def run():
        result = subprocess.run(command, cwd=root, env=env, text=True,
                                capture_output=True, timeout=240)
        if result.returncode != 101:
            raise ValueError('conformance mutation did not produce compiler diagnostics')
        return result

    source = (fixture / 'src/enabled.rs').read_text()
    gate.validate(run().stdout, source)
    path = roots['brynja-mac-kmac'] / 'src/fixed.rs'
    original = path.read_text()
    for method in ('verify_conformance', 'verify_bits_conformance'):
        start = original.rindex('            conformance_api! { $profile;',
                                0, original.index('pub fn ' + method + '('))
        stop = original.index('\n            }\n            }', start) + len('\n            }')
        mutant = (original[:start] +
                  original[start:stop].replace('            conformance_api! { $profile;\n', '', 1) +
                  original[stop + len('\n            }'):])
        try:
            path.write_text(mutant)
            try:
                gate.validate(run().stdout, source)
            except ValueError as error:
                if str(error) != 'missing or unexpected production conformance rejection':
                    raise
            else:
                raise ValueError('compiled verifier leak escaped the dedicated gate')
        finally:
            path.write_text(original)
    policy = roots['brynja-mac-kmac'] / 'src/policy.rs'
    original = policy.read_text()
    try:
        anchor = 'pub(crate) enum StrengthPolicy {\n'
        if original.count(anchor) != 1:
            raise ValueError('policy variant mutation anchor')
        policy.write_text(original.replace(anchor, anchor + '    Unclassified,\n'))
        result = run()
        if 'E0004' not in result.stdout or 'Unclassified' not in result.stdout:
            raise ValueError('new strength policy variant was not rejected exhaustively')
    finally:
        policy.write_text(original)
    gate.validate(run().stdout, source)
    print('Compiled conformance separation: two verifier leaks and unclassified policy rejected', flush=True)
