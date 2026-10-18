"""No-compiler regressions for Windows archive and cross-check orchestration."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import strict_windows_consumer as windows
import test_strict_public_consumer as scalar_tests
from test_facade_keccak import rejected


def document(enabled):
    result, roots, consumer = scalar_tests.document()
    result['packages'][0]['name'] = 'strict-facade-consumer'
    expected = windows.accelerated.expected_features() if enabled else windows.scalar.expected_features()
    expected['facade-consumer'] = {'acceleration'} if enabled else set()
    for node in result['resolve']['nodes']:
        node['features'] = sorted(expected[node['id']])
    return result, roots, consumer


def smoke_output():
    empty = 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n'
    return empty + 'test constructors_never_replace_protected_storage_with_ordinary_storage ... ok\n' + \
        empty.replace('0 passed', '1 passed') + empty


def check(api):
    count = 0
    for enabled in (False, True):
        good, roots, consumer = document(enabled)
        saved = copy.deepcopy(good)
        windows.graph(api, good, roots, consumer, enabled)
        assert good == saved
        for i in range(len(good['packages'])):
            for key, value in (('manifest_path', '/checkout/Cargo.toml'), ('source', 'registry+wrong'),
                               ('version', '9.9.9'), ('links', 'unexpected')):
                bad = copy.deepcopy(good)
                bad['packages'][i][key] = value
                rejected(lambda: windows.graph(api, bad, roots, consumer, enabled))
                count += 1
            for feature in ('macos-resident', 'conformance-testing', 'runtime-execution'):
                bad = copy.deepcopy(good)
                bad['resolve']['nodes'][i]['features'].append(feature)
                rejected(lambda: windows.graph(api, bad, roots, consumer, enabled))
                count += 1
        for name in ('facade-consumer', 'brynja-strict', 'wrong-consumer'):
            bad = copy.deepcopy(good)
            bad['packages'][0]['name'] = name
            rejected(lambda: windows.graph(api, bad, roots, consumer, enabled))
        rejected(lambda: windows.graph(api, good, roots, consumer, not enabled))
    populations(api)
    dispatch(api)
    restoration()
    print(f'Windows consumers reject {count} archive/feature drifts, root/opt-in substitution, '
          'skipped host smoke, missing Windows compilation and wrong probe populations')


def populations(api):
    text = smoke_output()
    windows.smoke(SimpleNamespace(returncode=0, stdout=text))
    for bad in ('', text + text, text.replace('1 passed', '0 passed'),
                text.replace('0 ignored', '1 ignored'), text.replace('0 filtered out', '1 filtered out'),
                text.replace('constructors_never_replace_protected_storage_with_ordinary_storage', 'unrelated')):
        rejected(lambda: windows.smoke(SimpleNamespace(returncode=0, stdout=bad)))
    rejected(lambda: windows.smoke(SimpleNamespace(returncode=1, stdout=text)))
    runner = windows.Runner(api, {}, ['cargo', '+example'])
    rejected(runner.finish)
    runner.tests = [(False, False), (False, True), (True, False), (True, True)]
    runner.negatives = {False: 231, True: 266}
    runner.finish()
    for bad in ({False: 230, True: 266}, {False: 231, True: 265}, {False: 497, True: 0}):
        runner.negatives = bad
        rejected(runner.finish)
    runner.negatives = {False: 231, True: 266}
    runner.tests.reverse()
    rejected(runner.finish)


def dispatch(api):
    for enabled in (False, True):
        good, roots, consumer = document(enabled)
        for profile in ([], ['--release']):
            command = ['cargo', '+example', 'test', '--locked', '--offline']
            if enabled:
                command += ['--features', 'acceleration']
            command += profile
            for fail_at in (None, 0, 1, 2):
                runner = windows.Runner(api, roots, command[:2])
                calls = []

                def raw(actual, cwd, env):
                    assert cwd == consumer
                    calls.append(actual)
                    index = len(calls) - 1
                    if index == fail_at:
                        return SimpleNamespace(returncode=1, stdout='', stderr='synthetic failure')
                    if index == 0:
                        assert actual[2] == 'metadata' and '--filter-platform' in actual
                        assert windows.TARGET in actual
                        return SimpleNamespace(returncode=0, stdout=json.dumps(good), stderr='')
                    if index == 1:
                        assert actual[2] == 'check' and '--lib' in actual
                        assert actual[actual.index('--target') + 1] == windows.TARGET
                        assert ('--release' in actual) == bool(profile)
                        assert ('--features' in actual) == enabled
                        return SimpleNamespace(returncode=0, stdout='', stderr='')
                    assert index == 2 and actual == command and '--target' not in actual
                    return SimpleNamespace(returncode=0, stdout=smoke_output(), stderr='')

                with patch.object(runner, 'raw', side_effect=raw):
                    if fail_at is None:
                        runner.run(command, consumer, {})
                        assert runner.tests == [(enabled, bool(profile))] and len(calls) == 3
                    else:
                        rejected(lambda: runner.run(command, consumer, {}))
                        assert runner.tests == [] and len(calls) == fail_at + 1
    runner = windows.Runner(api, {}, ['cargo', '+example'])
    for suffix in (['build'], ['test', '--all-features'], ['check', '--target', 'wrong']):
        rejected(lambda: runner.run(runner.cargo + suffix, consumer, {}))
    for enabled in (False, True):
        command = runner.cargo + ['check', '--locked', '--offline']
        if enabled:
            command += ['--features', 'acceleration']
        for code in (0, 101):
            with patch.object(runner, 'raw', return_value=SimpleNamespace(returncode=code)) as raw:
                runner.run(command, consumer, {})
                assert raw.call_args.args[0] == command + ['--lib', '--target', windows.TARGET]
    assert runner.negatives == {False: 1, True: 1}
    for code in (-9, 1, 2):
        with patch.object(runner, 'raw', return_value=SimpleNamespace(returncode=code)):
            rejected(lambda: runner.run(command, consumer, {}))
    assert runner.negatives == {False: 1, True: 1}


def restoration():
    # Exercise the reused helper itself: an interrupted/surviving/unrelated
    # negative must not leave its rejected Rust source as the positive example.
    for failure in ('exception', 'survived', 'unrelated'):
        with TemporaryDirectory(prefix='windows-surface-regression-') as temporary:
            root = Path(temporary)
            source = root / 'strict-facade-consumer/src/lib.rs'
            positive = None

            def run(command, *args):
                nonlocal positive
                if command[0] == 'check':
                    assert source.read_text() != positive
                    if failure == 'exception':
                        raise ValueError('synthetic interrupted compiler')
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stderr='unrelated compiler failure')
                positive = source.read_text()
                return SimpleNamespace(returncode=0)

            def require(result):
                assert result.returncode == 0

            rejected(lambda: windows.facade.check(windows.scalar.shared.ROOT, {}, root,
                                                  [], {}, run, require))
            assert positive is not None and source.read_text() == positive
