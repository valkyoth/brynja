"""Require current stable coverage without relabelling pinned native evidence."""
import os
from pathlib import Path
import re
import shlex
import sys
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
URL = 'https://static.rust-lang.org/dist/channel-rust-stable.toml'
LIMIT = 4 * 1024 * 1024
for directory in ('release', 'zeroization', 'constant-time'):
    sys.path.insert(0, str(ROOT / 'scripts' / directory))
import verification_commands
import zeroization_evidence
import constant_time_evidence


def require(condition, message):
    if not condition:
        raise ValueError('Rust freshness: ' + message)


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value),
            'explicit stable compiler version required')
    return tuple(int(part) for part in value.split('.'))


def latest(raw):
    require(0 < len(raw) <= LIMIT, 'missing or oversized stable manifest')
    manifest = tomllib.loads(raw.decode('utf-8'))
    require(manifest.get('manifest-version') == '2', 'unsupported stable manifest schema')
    release = manifest['pkg']['rust']['version']
    require(isinstance(release, str) and re.fullmatch(
        r'[0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]+ [0-9]{4}-[0-9]{2}-[0-9]{2}\)', release),
        'stable manifest does not identify a stable Rust release')
    result = release.split(' ', 1)[0]
    version(result)
    return result


def fetch(url):
    # Keep the existing manifest URL override for mirrors/testing. Network or
    # parse errors fail closed; never substitute cached "nothing changed".
    with urllib.request.urlopen(url, timeout=30) as response:
        return latest(response.read(LIMIT + 1))


def compiler_list(values):
    require(isinstance(values, list) and bool(values), 'empty compiler coverage')
    numbers = [version(value) for value in values]
    require(numbers == sorted(set(numbers)), 'duplicate or unordered compiler coverage')
    return values


def coverage(root, stable):
    version(stable)
    pinned = tomllib.loads((root / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    require(version(pinned) <= version(stable), 'default compiler is newer than current stable')
    script = (root / 'scripts/ci/check-rust-version-matrix.sh').read_text()
    declarations = re.findall(r'^toolchains=\(([0-9. ]+)\)$', script, re.M)
    require(len(declarations) == 1, 'missing or ambiguous executable compatibility matrix')
    compilers = compiler_list(declarations[0].split())
    require(stable in compilers and pinned in compilers,
            f'compatibility matrix must cover latest {stable} and pinned {pinned}')
    for name in ('zeroization', 'constant-time'):
        matrix = tomllib.loads((root / f'assurance/{name}-matrix.toml').read_text())['coverage']
        require(compiler_list(matrix['compilers']) == compilers,
                name + ' compiler coverage differs from executable matrix')
        require(matrix['target_compiler'] == pinned,
                name + ' native/target compiler differs from the pinned default')
    commands = verification_commands.matrix_commands(root)
    require(any(shlex.split(command) == ['cargo', '+' + stable, 'check', '--workspace', '--all-features']
                and stdin is None for command, stdin in commands),
            'latest stable workspace check is not executable')
    # Reuse the existing checks that bind emitted-code coverage to real CI
    # commands/targets and the pre-tag dynamic-analysis requirements.
    zeroization_evidence.validate(root)
    constant_time_evidence.validate(root)
    gate = (root / 'scripts/tag_gate.sh').read_text().splitlines()
    require(gate.count('scripts/ci/check-rust-version-matrix.sh') == 1 and
            gate.count('scripts/ci/check_latest_tools.sh') == 1,
            'tag gate must execute both compatibility and freshness checks')
    return pinned


def main():
    stable = fetch(os.environ.get('RUST_STABLE_MANIFEST_URL', URL))
    pinned = coverage(ROOT, stable)
    print(f'Rust freshness: latest stable {stable} is required by compatibility/codegen matrices; '
          f'native-evidence compiler remains {pinned}. Matrix execution is still required.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, urllib.error.URLError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
