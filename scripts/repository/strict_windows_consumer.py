"""Windows-target public surface reconciliation; never native enclave execution."""
import copy
import json
import re
import sys
from unittest.mock import patch

import strict_public_consumer as scalar
import strict_accelerated_consumer as accelerated

sys.path.insert(0, str(scalar.shared.ROOT / 'scripts/cryptography'))
import strict_facade_package as facade

TARGET = 'x86_64-pc-windows-msvc'
require = scalar.shared.require


def graph(api, document, roots, consumer, enabled):
    # Adapt only the known downstream name. Archive identities, paths, targets,
    # source IDs and the resolved-root ID are checked by the existing validator.
    mapped = copy.deepcopy(document)
    root = mapped['resolve']['root']
    selected = [p for p in mapped['packages'] if p['id'] == root]
    require(len(selected) == 1 and selected[0]['name'] == 'strict-facade-consumer',
            'unexpected Windows downstream identity')
    selected[0]['name'] = 'facade-consumer'
    expected = accelerated.expected_features() if enabled else scalar.expected_features()
    expected['facade-consumer'] = {'acceleration'} if enabled else set()
    with patch.object(accelerated, 'expected_features', return_value=expected):
        accelerated.graph(api, mapped, roots, consumer)


def smoke(result):
    """Existing host test is Linux protected reuse, not a Windows runtime test."""
    rows = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                      r'(\d+) measured; (\d+) filtered out;', result.stdout, re.M)
    require(result.returncode == 0 and rows == [
        ('ok', '0', '0', '0', '0', '0'),
        ('ok', '1', '0', '0', '0', '0'),
        ('ok', '0', '0', '0', '0', '0')], 'strict Windows harness host smoke population')
    require('test constructors_never_replace_protected_storage_with_ordinary_storage ... ok'
            in result.stdout, 'strict host smoke identity')


class Runner:
    def __init__(self, api, roots, cargo):
        self.api, self.roots, self.cargo = api, roots, cargo
        self.tests = []
        self.negatives = {False: 0, True: 0}

    def raw(self, command, consumer, env):
        self.api.cargo_environment.check(consumer, env)
        return self.api.subprocess.run(command, cwd=consumer, env=env, text=True,
                                       capture_output=True, timeout=240)

    def success(self, result):
        require(result.returncode == 0, 'Windows consumer command failed:\n' +
                result.stdout[-4000:] + result.stderr[-6000:])

    def run(self, command, consumer, env):
        require(command[:2] == self.cargo and len(command) >= 3, 'unexpected consumer command')
        action = command[2]
        enabled = '--features' in command
        feature = ['--features', 'acceleration'] if enabled else []
        profile = ['--release'] if '--release' in command else []
        if action == 'generate-lockfile':
            require(command[3:] == ['--offline'], 'unexpected lock invocation')
            return self.raw(command, consumer, env)
        if action == 'test':
            require(command[3:] == ['--locked', '--offline', *feature, *profile],
                    'unexpected host test invocation')
            metadata = self.raw(self.cargo + ['metadata', '--locked', '--offline',
                '--format-version=1', '--filter-platform', TARGET, *feature], consumer, env)
            self.success(metadata)
            graph(self.api, json.loads(metadata.stdout), self.roots, consumer, enabled)
            checked = self.raw(self.cargo + ['check', '--locked', '--offline', '--lib',
                '--target', TARGET, *feature, *profile], consumer, env)
            self.success(checked)
            result = self.raw(command, consumer, env)
            smoke(result)
            self.tests.append((enabled, bool(profile)))
            print(f'PASS: Windows public examples compiled; acceleration={enabled}; '
                  f'release={bool(profile)}; separate Linux facade smoke passed', flush=True)
            return result
        require(action == 'check' and command[3:] == ['--locked', '--offline', *feature],
                'unexpected ownership probe invocation')
        # Check the Windows implementation, not the non-Windows stub surface.
        result = self.raw(command + ['--lib', '--target', TARGET], consumer, env)
        require(result.returncode in (0, 101), 'Windows probe terminated outside compiler diagnostics')
        if result.returncode:
            self.negatives[enabled] += 1
        return result

    def finish(self):
        require(self.tests == [(False, False), (False, True), (True, False), (True, True)],
                'Windows positive compiler/profile population')
        require(self.negatives == {False: 231, True: 266}, 'Windows ownership/export population')


def execute(api, root, toolchain):
    scalar.legacy_strict_package.require_host(False)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    packages = scalar.specifications(api)
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    runner = Runner(api, roots, ['cargo', '+' + toolchain])
    facade.check(api.ROOT, roots, root, runner.cargo, env, runner.run, runner.success)
    runner.finish()
    print('Windows extracted strict surface: PASS; 497 Windows-target negatives; '
          'native enclave execution NOT performed; historical records unchanged', flush=True)
