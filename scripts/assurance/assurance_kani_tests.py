"""Kani inventory checks are byte-ordered, never desktop-locale ordered."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def fixture(root):
    (root / 'assurance').mkdir()
    shutil.copyfile(ROOT / 'assurance/policy.toml', root / 'assurance/policy.toml')
    for source in (ROOT / 'crates').rglob('*.rs'):
        data = source.read_bytes()
        if b'#[kani::proof]' in data:
            target = root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    return root / 'crates/brynja-mac-kmac/src/policy.rs'


def test_kani_inventory_locale_and_confinement():
    if os.name == 'nt':
        return  # This shell runner is POSIX-only; Windows uses its own checks.
    sort = shutil.which('sort')
    assert sort
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = fixture(root)
        binary = root / 'bin'
        binary.mkdir()
        # Deterministically emulate a non-byte collation even on CI hosts
        # without optional locale packages. Exercise the real shell pipeline.
        wrapper = binary / 'sort'
        wrapper.write_text('#!/bin/sh\n'
            'if [ "${LC_ALL-}" = C ]; then\n'
            f'  exec {shlex.quote(sort)} "$@"\n'
            'else\n'
            f'  LC_ALL=C exec {shlex.quote(sort)} -r "$@"\n'
            'fi\n')
        wrapper.chmod(0o700)
        env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
               'LC_ALL': 'POSIX', 'LC_COLLATE': 'POSIX'}
        driver = ROOT / 'scripts/assurance/check-kani.sh'

        def run(path=driver):
            return subprocess.run(['sh', str(path), '--policy-only'], cwd=root,
                                  env=env, capture_output=True, text=True, timeout=15)

        good = run()
        assert good.returncode == 0, good.stderr
        assert 'thirty-two portable' in good.stdout
        # The old implementation must fail this regression.
        mutant = root / 'old-driver.sh'
        text = driver.read_text()
        assert text.count('LC_ALL=C sort') == 1
        mutant.write_text(text.replace('LC_ALL=C sort', 'sort'))
        assert 'harnesses escaped' in run(mutant).stderr
        # Byte ordering must not admit additional or relocated harnesses.
        extra = root / 'crates/unreviewed.rs'
        extra.write_text('#[kani::proof]\nfn unexpected() {}\n')
        bad = run()
        assert bad.returncode != 0 and 'found 33' in bad.stderr
        extra.unlink()
        source.rename(extra)
        bad = run()
        assert bad.returncode != 0 and 'harnesses escaped' in bad.stderr


if __name__ == '__main__':
    test_kani_inventory_locale_and_confinement()
    print('Kani inventory: locale ordering, old-driver mutant, count and confinement PASS')
