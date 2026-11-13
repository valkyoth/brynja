#!/usr/bin/env python3
"""Archive-only AES provider consumers; mocks, not device qualification."""
import importlib.util
import json
import os
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_packaged_provider_base', Path(__file__).with_name('check-aes-packaged.py'))
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
ROOT = packaged.ROOT
WIDTHS = (128, 192, 256)
FILES = tuple(f'crates/brynja-crypto/tests/aes{bits}_provider.rs' for bits in WIDTHS) + (
    'crates/brynja-crypto/tests/aes_provider_common/mod.rs',
    'crates/brynja-crypto/tests/aes128_provider_regressions/mod.rs',
)
EXAMPLE = 'assurance/aes-provider-public-api.rs'
TESTS = {
    'reference_adapter_matches_fips_encrypt_decrypt_and_clears_outputs',
    'public_ciphertext_commits_only_complete_success',
    'permissions_are_exact_and_rejection_does_not_dispatch_or_quarantine',
    'every_adapter_failure_clears_or_preserves_output_and_is_terminal',
    'invalid_reported_lengths_never_release_partial_output',
    'adapter_unwind_clears_or_preserves_output_and_is_terminal',
    'separate_bindings_never_substitute_key_or_provider',
    'dropping_borrowed_or_owned_binding_does_not_destroy_device_key',
    'owned_destruction_is_explicit_fallible_and_never_retried',
    'quarantined_owned_binding_can_still_explicitly_destroy',
    'output_owner_can_outlive_provider_binding',
    'neutral_lifecycle_does_not_require_an_aes_backend',
    'regressions::equal_input_output_is_accepted_without_quarantine_in_every_direction',
    'regressions::successful_block_values_are_not_heuristically_validated',
    'regressions::equal_decryption_result_preserves_binding_for_later_encryption',
    'regressions::send_backend_binding_moves_to_worker_and_returns_for_destruction',
}
MARKER = 'AES provider packaged: PASS; 8 host configurations; 384 lifecycle tests; 4 Cortex-M compile checks; mocks only; no upload'


def require(condition, message):
    if not condition:
        raise ValueError('AES provider packaged: ' + message)


def source(name):
    path = ROOT / name
    require(path.is_file() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents),
            'missing or symlinked fixture: ' + name)
    return path.read_text()


def prepare(directory, versions, route):
    require(route in packaged.consumer.ROUTES, 'unknown route')
    # Reuse exact archive pins and the existing isolated-workspace policy.
    packaged.prepare(directory, versions)
    manifest = directory / 'Cargo.toml'
    manifest.write_text(manifest.read_text().replace(
        'features=["hazmat-aes-block"]', 'features=["hazmat-aes-block","external-key-provider"]'))
    (directory / 'src/lib.rs').write_text(source(EXAMPLE))
    for name in FILES:
        target = directory / 'tests' / name.split('/tests/')[1]
        target.parent.mkdir(parents=True, exist_ok=True)
        text = source(name)
        if route == 'facade':
            text = text.replace('brynja_crypto::', 'brynja::crypto::')
        target.write_text(text)


def check_tests(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    require(len(rows) == 16 and {name for name, _ in rows} == {'contracts::' + name for name in TESTS}
            and all(status == 'ok' for _, status in rows), 'missing, duplicate, ignored or failed lifecycle test')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
        'incorrect lifecycle test summary')


def configuration(directory, root, versions, compiler, route, env):
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    for target in (None, packaged.TARGET):
        command = cargo + ['metadata', '--format-version=1', *selection]
        if target:
            command += ['--filter-platform', target]
        metadata = json.loads(packaged.archives.run(command, directory, env).stdout)
        packaged.graph(metadata, route, directory, root / 'unpacked', versions, provider=True)
    for profile in ('debug', 'release'):
        for bits in WIDTHS:
            command = cargo + ['test', *selection, '--test', f'aes{bits}_provider']
            if profile == 'release':
                command.append('--release')
            check_tests(packaged.archives.run(command, directory, env).stdout)
        print(f'AES_PROVIDER_PACKAGED_HOST: {compiler} {route} {profile} 48 exact tests', flush=True)
    packaged.archives.run(cargo + ['check', *selection, '--lib', '--target', packaged.TARGET], directory, env)
    print(f'AES_PROVIDER_PACKAGED_TARGET: {compiler} {route} {packaged.TARGET} compile-only', flush=True)


def check():
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        for route in packaged.consumer.ROUTES:
            directory = root / 'consumers' / route
            prepare(directory, versions, route)
            packaged.archives.run(['cargo', '+' + packaged.consumer.TOOLCHAINS[0],
                                  'generate-lockfile', '--offline'], directory, env)
            for compiler in packaged.consumer.TOOLCHAINS:
                configuration(directory, root, versions, compiler, route, env)
    print(MARKER, flush=True)


if __name__ == '__main__':
    check()
