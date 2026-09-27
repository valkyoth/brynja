"""Explicit phase-to-receipt routing; historical locations are local, not rewritten."""
from pathlib import Path
import os
import subprocess
import sys

import detached_catalog as catalog
import detached_history as history
import detached_manifest as records
import verification_carry_forward as carry


def compatible_tools(manifest: dict, root: Path) -> None:
    """Keep compiler/verifier/platform qualification; ignore extra installations.

    Python/rustup inventory text still remains sealed historical provenance.
    It is not evidence that a new compiler or verifier passed these tests.
    """
    tools = manifest['tools']
    if tools['platform'] != sys.platform:
        raise ValueError('phase receipt execution platform differs from collector')
    probes = {'rustc': ['rustc', '-vV'], 'cargo': ['cargo', '-V']}
    probes.update({key: ['rustc', '+' + key.removeprefix('compiler:'), '-vV']
                   for key in tools if key.startswith('compiler:')})
    probes.update(records.verifier_commands(root, manifest['commands']))
    for key, argv in probes.items():
        value = subprocess.check_output(argv, stderr=subprocess.DEVNULL, timeout=30,
                                        env={**os.environ, 'RUSTUP_AUTO_INSTALL': '0'})
        if len(value) > 65536 or value.decode().strip() != tools[key]:
            raise ValueError('phase receipt compiler/verifier identity differs: ' + key)


def load(path: Path) -> dict:
    value = records.read(records.safe_path(path))
    if (set(value) != {'schema', 'phases', 'jobs'} or type(value['schema']) is not int
            or value['schema'] != 1 or not isinstance(value['phases'], dict)
            or not value['phases'] or not set(value['phases']) <= set(catalog.PHASES)
            or not isinstance(value['jobs'], dict) or not 1 <= len(value['jobs']) <= 128):
        raise ValueError('invalid phase receipt registry')
    locations = {}
    for receipt, name in value['jobs'].items():
        if not history.receipt_ok(receipt) or not isinstance(name, str) or not Path(name).is_absolute():
            raise ValueError('invalid phase receipt location')
        locations[receipt] = records.safe_path(Path(name))
        if not locations[receipt].is_dir():
            raise ValueError('missing phase receipt directory')
    if (len(set(locations.values())) != len(locations)
            or any(not history.receipt_ok(r) or r not in locations for r in value['phases'].values())):
        raise ValueError('missing or conflicting phase receipts')
    return {'phases': value['phases'], 'jobs': locations}


def prepare(path: Path, root: Path, plan: dict, phase: str, command: str | None = None) -> tuple[list, list]:
    registry = load(path)
    reader = history.History(registry['jobs'])
    phases = list(catalog.PHASES) if phase == 'plan' else ['repository' if phase == 'command' else phase]
    if any(p not in registry['phases'] for p in phases):
        raise ValueError('requested phase lacks an explicit receipt; no automatic full-run fallback')
    contexts, decisions = {}, []
    for name in phases:
        receipt = registry['phases'][name]
        if receipt not in contexts:
            reader.collect(receipt)
            manifest, _, _ = reader.cache[receipt]
            compatible_tools(manifest, registry['jobs'][receipt] / 'source')
            contexts[receipt] = carry.prepare(registry['jobs'][receipt], receipt, root, plan,
                                              historical_reader=reader)
        context = contexts[receipt]
        if name not in context['manifest']['phases']:
            raise ValueError('receipt does not cover requested phase')
        entries = carry.required(context, 'command' if phase == 'command' else name, command)
        decisions.extend((entry, carry.disposition(entry, context)) for entry in entries)
    return list(contexts.values()), decisions
