"""Exercise production admission independently across every KMAC owner family."""
import subprocess


def verdict(result, test, success):
    summary = ('test result: ok. 1 passed; 0 failed; 0 ignored;' if success else
               'test result: FAILED. 0 passed; 1 failed; 0 ignored;')
    status = 'ok' if success else 'FAILED'
    return (result.returncode == (0 if success else 101) and
            summary in result.stdout and f'test {test} ... {status}' in result.stdout)


def cases(native):
    result = []
    def flip(name, anchor, test):
        result.append((name, anchor, anchor.replace('::Production', '::Conformance'), test))
    for name in ('fixed.rs', 'xof.rs'):
        flip(name, 'KmacCore::new_bits(key, customization, StrengthPolicy::Production)',
             'portable_policy')
        flip('execution/' + name,
             'Core::new(mode, $wide, key, customization, StrengthPolicy::Production)',
             'execution_portable_policy')
    for anchor in ('self.finish_tag(None, output, StrengthPolicy::Production)',
                   'self.verify_inner(None, candidate, StrengthPolicy::Production)'):
        flip('fixed.rs', anchor, 'portable_policy')
    flip('xof.rs', '.finish_xof(None, StrengthPolicy::Production)', 'portable_policy')
    for anchor in (
        '&mut scratch.0, StrengthPolicy::Production,',
        'self.verification(None, crate::execution::bits(candidate)?, StrengthPolicy::Production)',
    ):
        flip('execution/fixed.rs', anchor, 'execution_portable_policy')
    flip('execution/xof.rs', 'self.core.finish(None, 0, true, StrengthPolicy::Production)?;',
         'execution_portable_policy')
    for prefix, test in [('hardened_in_place/', 'portable_policy')] + (
            [('hardened_in_place/accelerated/', 'accelerated_policy')] if native else []):
        # The first occurrence is the ordinary byte setup; XOF delegates to it.
        result.append((prefix + 'fixed.rs', 'if key.bit_len() < $strength {',
                       'if false {', test))
        for anchor in (
            'self.core.tag(None, output, valid, $strength, StrengthPolicy::Production)',
            '.verify(None, bytes(candidate)?, None, $strength, StrengthPolicy::Production)',
        ):
            flip(prefix + 'fixed.rs', anchor, test)
        flip(prefix + 'xof.rs', 'self.finish(None, StrengthPolicy::Production)', test)
    return result


def check(root, consumer, roots, env, native_env=None):
    def run(test):
        environment = native_env if test == 'accelerated_policy' else env
        command = ['cargo', 'test', '--offline', '--manifest-path',
                   str(consumer / 'Cargo.toml'), '--test', 'production_admission',
                   '--', '--exact', test]
        if test == 'accelerated_policy':
            command.append('--ignored')
        return subprocess.run(command, cwd=root, env=environment, text=True,
                              capture_output=True, timeout=240)
    tests = ['portable_policy', 'execution_portable_policy']
    if native_env is not None:
        tests.append('accelerated_policy')
    for test in tests:
        result = run(test)
        if not verdict(result, test, True):
            raise ValueError('admission positive control: ' + result.stdout + result.stderr)
    mutations = cases(native_env is not None)
    for name, before, after, test in mutations:
        path = roots['brynja-mac-kmac'] / 'src' / name
        original = path.read_text()
        count = 2 if name == 'hardened_in_place/accelerated/fixed.rs' and before.startswith('if ') else 1
        if original.count(before) != count:
            raise ValueError('admission mutation anchor changed: ' + name + ': ' + before)
        try:
            path.write_text(original.replace(before, after, 1))
            result = run(test)
            if not verdict(result, test, False):
                raise ValueError('admission mutant escaped or failed unrelatedly: ' +
                                 name + ': ' + before + result.stdout + result.stderr)
        finally:
            path.write_text(original)
    for test in tests:
        result = run(test)
        if not verdict(result, test, True):
            raise ValueError('admission restoration control: ' + result.stdout + result.stderr)
    print(f'Production KMAC admission: {len(mutations)} policy downgrades rejected; '
          f'{len(tests)} pristine profiles restored', flush=True)
