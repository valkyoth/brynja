#!/usr/bin/env python3
"""Development-only higher-construction vectors and compiled probe regressions."""
import importlib.util
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import check_callers as audit


def golden_vectors():
    expected = {}
    for family in ('kmac', 'tuplehash', 'parallelhash'):
        path = audit.ROOT / f'scripts/{family}/check-{family}-differential.py'
        spec = importlib.util.spec_from_file_location(family, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, 'verify_oracle'):
            module.verify_oracle()
        bits = module.oracle.byte_bits
        for xof in (False, True):
            for strength, rate in ((128, 168), (256, 136)):
                message = bits(bytes(range(135)))
                if family == 'kmac':
                    value = module.kmac(rate, bits(bytes(range(32))), message, [], 256, xof)
                    prefix = 'kmac'
                elif family == 'tuplehash':
                    value = module.tuple_hash(rate, [message], [], 256, xof)
                    prefix = 'tuple'
                else:
                    value = module.parallel_hash(rate, message, 8, [], 256, xof)
                    prefix = 'parallel'
                expected[prefix + ('xof' if xof else '') + str(strength)] = value
    source = (audit.FIXTURE / 'tests/higher_vectors/mod.rs').read_text()
    rows = re.findall(r'\(\s*"(\w+)",\s*\[([\s,0-9a-fx]+)\]', source)
    actual = {name: bytes(int(value, 16) for value in re.findall(r'0x([0-9a-f]{2})', data))
              for name, data in rows}
    if len(rows) != 12 or actual != expected or set(actual) != audit.HIGHER_ALGORITHMS:
        raise ValueError('higher probe independent vector inventory/content drift')
    print('Higher caller golden vectors: 12 independently regenerated', flush=True)


def mutations(accelerated=False):
    with tempfile.TemporaryDirectory(prefix='brynja-higher-callers-') as temporary:
        fixture = Path(temporary) / 'fixture'
        shutil.copytree(audit.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../../crates/', str(audit.ROOT / 'crates') + '/'))
        cases = [('higher.rs', *case) for case in (
            ('$state.update($input)', '$state.update(&[])', 1),
            ('$state.push_item($input)', '$state.push_item(&[])', 1),
            ('drop(secret);', 'core::mem::forget(secret);', 2),
            ('value != secret.expose()', 'value != value', 2),
            ('&mut output[..32]', '&mut output[..31]', 1),
        )]
        if accelerated:
            audit.require_native_avx2(Path('/proc/cpuinfo').read_text())
            cases.extend((
                ('higher.rs', 'owner.quarantine();', '/* missed revocation */', 1),
                ('accelerated.rs', 'report.kernel == kernel()', 'true', 1),
                ('accelerated.rs', 'report.health == Health::Healthy', 'true', 1),
            ))
        env = audit.clean_environment()
        env['CARGO_TARGET_DIR'] = str(Path(temporary) / 'target')
        if accelerated:
            env['RUSTFLAGS'] = '-C target-feature=+avx2'
        for profile in ([], ['--release']):
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path',
                       str(manifest), '--features', 'accelerated' if accelerated else 'higher', '--test', 'audit', *profile]
            control = audit.run(command, env)
            count = 6 if accelerated else 5
            if f'{count} passed; 0 failed; 0 ignored;' not in control:
                raise ValueError('higher caller positive controls did not execute')
            for filename, before, after, count in cases:
                source = fixture / 'src' / filename
                original = source.read_text()
                if original.count(before) != count:
                    raise ValueError('ambiguous higher caller mutation: ' + before)
                try:
                    source.write_text(original.replace(before, after))
                    result = subprocess.run(command, cwd=audit.ROOT, env=env, text=True,
                                            capture_output=True, timeout=180, check=False)
                    if result.returncode == 0 or 'test result: FAILED.' not in result.stdout:
                        raise ValueError('higher caller mutant did not compile and fail: ' + before + result.stderr[-3000:])
                finally:
                    source.write_text(original)
    print(f'Higher caller compiled regressions: {len(cases) * 2} rejected in debug/release; accelerated={accelerated}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accelerated', action='store_true')
    args = parser.parse_args()
    golden_vectors()
    mutations(args.accelerated)
