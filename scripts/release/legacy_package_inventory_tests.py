"""Check actual legacy packaging commands before Cargo or cached artifacts run."""
import importlib.util
from pathlib import Path
import sys
import tomllib
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def validate(names):
    assert len(names) == len(set(names)), 'duplicate packaged dependency'
    inherited = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['dependencies']
    for name in names:
        manifest = tomllib.loads((ROOT / 'crates' / name / 'Cargo.toml').read_text())
        for table in (manifest, *manifest.get('target', {}).values()):
            for key in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for alias, dependency in table.get(key, {}).items():
                    if not isinstance(dependency, dict):
                        continue
                    if dependency.get('workspace'):
                        dependency = inherited[alias]
                    if 'path' in dependency:
                        required = dependency.get('package', alias)
                        assert required in names, (name, required)


def command_inventory(family, option):
    source = ROOT / f'scripts/{family}/check-{family}-package.py'
    spec = importlib.util.spec_from_file_location('packaged_legacy_' + family, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []

    class BeforeCargo(Exception):
        pass

    def capture(command, **kwargs):
        assert command[:6] == ['cargo', 'package', '--locked', '--offline',
                              '--allow-dirty', '--no-verify'], command
        assert command[6::2] == ['-p'] * len(command[7::2]), command
        assert kwargs['cwd'] == ROOT and kwargs['check'] is True
        target = Path(kwargs['env']['CARGO_TARGET_DIR'])
        assert target.name == 'target' and target.parent.is_dir()
        assert not target.exists(), 'legacy packaging reused a pre-existing target'
        calls.append((command[7::2], target))
        raise BeforeCargo

    with patch.object(sys, 'argv', [str(source), *([option] if option else [])]), \
            patch.object(module.subprocess, 'run', side_effect=capture), \
            patch.object(module.subprocess, 'check_call', side_effect=AssertionError('unexpected Cargo')):
        try:
            module.main()
        except BeforeCargo:
            pass
        else:
            raise AssertionError('legacy packaging never reached Cargo')
    assert len(calls) == 1
    names, target = calls[0]
    assert not target.parent.exists(), 'legacy temporary directory was not cleaned'
    return names


def check():
    populations = mutations = 0
    for family in ('md5', 'sha1'):
        for option in ('', '--cpu', '--execution', '--hardened', '--strict'):
            names = command_inventory(family, option)
            validate(names)
            populations += 1
            if not option:
                assert set(names) == {'brynja-core', 'brynja-hash-core', f'brynja-legacy-{family}'}
                continue
            assert f'brynja-legacy-{family}-std' in names
            for missing in ('brynja-mac-hmac', 'brynja-mac-kmac', 'brynja-hash-tuple'):
                try:
                    validate([name for name in names if name != missing])
                except AssertionError as error:
                    assert error.args == (('brynja-crypto-cpu-std', missing),), error.args
                    mutations += 1
                else:
                    raise AssertionError('optional packaged dependency omission escaped: ' + missing)
            try:
                validate([*names, 'brynja-mac-hmac'])
            except AssertionError as error:
                assert str(error) == 'duplicate packaged dependency'
                mutations += 1
            else:
                raise AssertionError('duplicate package escaped')
    assert (populations, mutations) == (10, 32)
    print('Legacy package commands: 10 fresh-target inventories; 32 optional/duplicate regressions rejected (no Cargo)')


def facade_check(packaging):
    # The later facade campaign has a separate legacy-only subset. Check that
    # subset too, rather than only the larger enclosing facade inventory.
    source = ROOT / 'scripts/repository/legacy_execution_package.py'
    spec = importlib.util.spec_from_file_location('legacy_facade_inventory', source)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(source.parent), *sys.path]):
        spec.loader.exec_module(module)
    names = [name for name, *_ in packaging.PACKAGING_PACKAGES if name in module.SUPPORT]
    names += [name for name, *_ in module.ARCHIVES]
    validate(names)
    try:
        validate([name for name in names if name != 'brynja-mac-hmac'])
    except AssertionError as error:
        assert error.args == (('brynja-crypto-cpu-std', 'brynja-mac-hmac'),), error.args
    else:
        raise AssertionError('optional HMAC omission escaped the legacy facade subset')
    print('Legacy facade package subset retains optional HMAC and rejects its omission')


if __name__ == '__main__':
    check()
