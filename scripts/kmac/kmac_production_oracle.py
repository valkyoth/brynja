"""Run the execution oracle through production types, not test-only owners."""
import importlib.util
from pathlib import Path
import shutil
import tempfile


def campaign(root, oracle, cases, command, env, execute, route):
    # Reuse the reviewed exact source adapter also exercised by both facades.
    spec = importlib.util.spec_from_file_location('kmac_production_sources',
        root / 'scripts/repository/facade_kmac_sources.py')
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    selected = oracle.production_cases(cases)
    if {case[0] for case in selected} != {'kmac128', 'kmac256', 'kmacxof128', 'kmacxof256'}:
        raise ValueError('production oracle omitted an identity')
    request = '\n'.join(
        f'{name} {kb} {key.hex() or "-"} {cb} {custom.hex() or "-"} '
        f'{mb} {message.hex() or "-"} {ob}'
        for name, key, kb, custom, cb, message, mb, ob, _ in selected) + '\n'
    with tempfile.TemporaryDirectory(prefix='brynja-kmac-production-') as temporary:
        consumer = Path(temporary) / 'consumer'
        shutil.copytree(root / 'assurance/kmac-execution', consumer,
                        ignore=shutil.ignore_patterns('target'))
        manifest = consumer / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(root / 'crates') + '/'))
        for name in adapter.COUNTS:
            path = consumer / 'src' / name
            path.write_text(adapter.production(name, path.read_text()))
        actual_command = list(command)
        actual_command[actual_command.index('--manifest-path') + 1] = str(manifest)
        environment = dict(env, CARGO_TARGET_DIR=str(Path(temporary) / 'target'))
        result = execute(actual_command, environment, request)
        if result.stdout.splitlines() != [case[-1].hex() for case in selected]:
            raise ValueError('production KMAC execution/oracle mismatch')
        if 'KMAC_EXECUTION_ROUTE: ' not in result.stderr or route not in result.stderr:
            raise ValueError('production KMAC execution route absent')
    print(f'Production KMAC execution oracle: PASS; cases={len(selected)}; kernel={route}', flush=True)
