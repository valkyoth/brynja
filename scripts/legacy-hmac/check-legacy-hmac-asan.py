#!/usr/bin/env python3
"""Portable legacy HMAC and public hosted metadata; not protected-worker execution."""
from pathlib import Path
import platform
import sys

import legacy_hmac_verifiers as verifier


def cases():
    rows = [(['-p', 'brynja-legacy-hmac', '--test', name], count)
            for name, count in (('bounded', 5), ('rfc2202', 2), ('contracts', 6))]
    rows.append((['-p', 'brynja-legacy-hmac', '--features', 'sha1-execution',
                  '--lib', 'execution::retained::tests'], 3))
    rows.extend((['-p', 'brynja-legacy-hmac-std', '--all-features', '--lib', name], count)
                for name, count in (('metadata_and_preselected_tag_policy', 2),
                                    ('batch_metadata_and_public_admission', 2),
                                    ('only_pre_entry_thread_errors_are_reusable', 2), ('missing_native', 4)))
    return rows


def main():
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise ValueError('legacy HMAC sanitizer lane requires Linux x86-64')
    pin = verifier.tool('rust-sanitizers')
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env['RUSTFLAGS'] = '-Zsanitizer=address -C target-cpu=generic'
        env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'
        env['LSAN_OPTIONS'] = 'exitcode=23'
        for args, count in cases():
            output = verifier.run(['cargo', '+' + pin['execution_toolchain'], 'test', '--locked', '--offline',
                                   '--target', 'x86_64-unknown-linux-gnu', *args], env)
            if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in output:
                raise ValueError('legacy HMAC sanitizer population changed: ' + repr(args) + '\n' + output[-6000:])
            print(output)
    print('Legacy HMAC portable/public-metadata ASan/LSan: PASS; no native hardware/residency claim')


if __name__ == '__main__':
    main()
