#!/usr/bin/env python3
"""Native pre-entry recovery regression; scoped author test, not qualification."""
import importlib.util
from pathlib import Path
import platform
import sys

import hmac_verifiers as verifier
from hmac_faults import accepted, rejected, replace_once, result

ROOT = verifier.ROOT
sys.path.append(str(ROOT / 'scripts/cpu'))
spec = importlib.util.spec_from_file_location('launch_packages', ROOT / 'scripts/cpu/check-hosted-execution.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def check(workspace, env):
    machine = platform.machine()
    if sys.platform == 'darwin' and machine == 'arm64':
        feature, module = 'macos-resident-hmac-acceleration', 'macos_resident/hmac'
        test = 'macos_resident::resource::darwin::tests::hmac_preentry_failures_preserve_session'
        flags = '+neon,+sha2,+aes'
    elif sys.platform == 'linux' and machine in ('x86_64', 'aarch64'):
        feature, module = 'strict-hmac-acceleration', 'strict_hmac'
        test = 'protected_memory::platform::thread::tests::hmac_preentry_failures_preserve_session'
        flags = '+sha,+sse2' if machine == 'x86_64' else '+neon,+sha2,+aes'
    else:
        raise ValueError('requires native Linux x86/Arm or Apple Silicon with matching SHA-256 instructions')
    env = dict(env, RUSTFLAGS='-C target-feature=' + flags)
    command = ['cargo', 'test', '--offline', '-p', host.HOST, '--features', feature, '--lib']
    path = workspace / 'crates' / host.HOST / 'src' / module / 'compiled.rs'
    original = path.read_text()
    before = 'self.quarantined = false;\n            }\n            return Err(error.into());'
    for profile in ([], ['--release']):
        args = [*command, *profile, test, '--', '--exact', '--ignored']
        accepted(result(args, workspace, env), 1)
        try:
            path.write_text(replace_once(original, before,
                '/* wrongly quarantine pre-entry failure */\n            }\n            return Err(error.into());'))
            # A compile failure or ignored test is never mutant rejection.
            rejected(result(args, workspace, env))
        finally:
            path.write_text(original)
        accepted(result(args, workspace, env), 1)
    print('HMAC native worker-start recovery: debug/release PASS; both compiled regressions rejected', flush=True)


def main():
    with verifier.cargo_environment.private_directory(ROOT) as raw:
        root = Path(raw)
        check(host.isolated(root), verifier.environment(root))


if __name__ == '__main__':
    main()
