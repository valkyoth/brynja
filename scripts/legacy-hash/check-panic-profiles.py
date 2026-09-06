#!/usr/bin/env python3
"""Real downstream release builds own panic strategy, including leaf compilation."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import legacy_acceptance as policy

SOURCE = r'''
fn main() {
    let strategy = if cfg!(panic = "abort") { "abort" } else { "unwind" };
    assert_eq!(std::env::args().nth(1).as_deref(), Some(strategy));
    brynja_legacy_hash_public_api_fixture::acceptance();
    #[cfg(panic = "unwind")]
    {
        let mut destination = [0xa5; 20];
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let secret = brynja_legacy_sha1::HardenedSha1::digest_secret(b"abc", &mut destination);
            assert!(secret.is_ok());
            panic!("application-owned recoverable panic");
        }));
        assert!(caught.is_err());
        assert_eq!(destination, [0; 20]);
    }
    println!("downstream release profile: {strategy}: PASS");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-panic-consumer-') as temporary:
        root = Path(temporary)
        consumer = root / 'consumer'
        shutil.copytree(policy.ROOT / policy.FIXTURE, consumer,
                        ignore=shutil.ignore_patterns('target'))
        manifest = consumer / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates', (policy.ROOT / 'crates').as_posix())
                            + '\n[[bin]]\nname="panic-profile"\npath="src/panic_profile.rs"\n')
        (consumer / 'src/panic_profile.rs').write_text(SOURCE)
        for selected in ('default', 'unwind', 'abort'):
            expected = 'abort' if selected == 'abort' else 'unwind'
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / selected),
                       CARGO_ENCODED_RUSTFLAGS='', CARGO_TERM_COLOR='never')
            env.pop('RUSTFLAGS', None)
            env.pop('CARGO_PROFILE_RELEASE_PANIC', None)
            if selected != 'default':
                env['CARGO_PROFILE_RELEASE_PANIC'] = selected
            result = subprocess.run(['cargo', 'run', '-vv', '--locked', '--offline', '--release',
                                     '--bin', 'panic-profile', '--', expected],
                                    cwd=consumer, env=env, text=True, capture_output=True, timeout=180)
            if result.returncode or f'downstream release profile: {expected}: PASS' not in result.stdout:
                raise ValueError(f'consumer profile {selected} failed: {result.stderr}')
            for leaf in ('brynja_legacy_sha1', 'brynja_legacy_md5'):
                commands = [line for line in result.stderr.splitlines()
                            if 'Running ' in line and f'--crate-name {leaf} ' in line]
                if len(commands) != 1 or ('-C panic=abort' in commands[0]) != (expected == 'abort'):
                    raise ValueError(f'{leaf} did not compile under consumer strategy {selected}')
    print('Downstream default/unwind/abort release builds and unwind-owned cleanup: PASS')


if __name__ == '__main__':
    main()
