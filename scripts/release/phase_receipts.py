"""Explicit phase-to-receipt routing; historical locations are local, not rewritten."""
from pathlib import Path
import os
import subprocess
import sys

import detached_catalog as catalog
import detached_history as history
import detached_manifest as records
import verification_carry_forward as carry
import verification_plan as plans


class ToolDrift(ValueError):
    """Valid historical evidence needs a fresh run with today's selected tools."""


def compiler_keys(manifest: dict, root: Path) -> set[str]:
    """Resolve only understood launchers; opaque scripts keep the full inventory.

    Never infer compiler use from a filename or a substring scan of a script.
    A changed script/feature/policy still goes through the source-delta planner.
    """
    recorded = {key for key in manifest['tools'] if key.startswith('compiler:')}
    selected = set()
    entries = manifest['commands']
    if not entries:
        return recorded
    for entry in entries:
        argv = entry['argv']
        if argv[0] == 'cargo' and len(argv) > 1:
            offset = 2 if argv[1].startswith('+') else 1
            if (len(argv) <= offset or argv[offset] not in
                    {'test', 'check', 'build', 'clippy', 'doc', 'fmt', 'fetch', 'metadata'}):
                # cargo aliases, external subcommands and cargo run may launch
                # other tools; their compiler use is not established here.
                return recorded
            if argv[1].startswith('+'):
                name = argv[1][1:]
            else:
                # The pinned default rustc/cargo are checked separately.
                continue
        elif (argv[:2] == ['python3', 'scripts/zeroization/run-miri-task.py'] or
              argv[0] in {'scripts/zeroization/check-zeroization-miri.sh',
                          'scripts/assurance/check-kani.sh'}):
            probes = records.verifier_commands(root, [entry])
            if not probes:  # A policy-only check does not execute a verifier.
                continue
            name = next(iter(probes.values()))[2]  # rustup run <toolchain>
        else:
            return recorded
        matches = set()
        for key in recorded:
            hosts = [line.removeprefix('host: ') for line in manifest['tools'][key].splitlines()
                     if line.startswith('host: ')]
            if key == 'compiler:' + name or (len(hosts) == 1 and
                    key == 'compiler:' + name + '-' + hosts[0]):
                matches.add(key)
        if len(matches) != 1:
            raise ValueError('missing or ambiguous selected compiler identity: ' + name)
        selected.update(matches)
    return selected


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
                   for key in compiler_keys(manifest, root)})
    probes.update(records.verifier_commands(root, manifest['commands']))
    for key, argv in probes.items():
        value = subprocess.check_output(argv, stderr=subprocess.DEVNULL, timeout=30,
                                        env={**os.environ, 'RUSTUP_AUTO_INSTALL': '0'})
        if len(value) > 65536 or value.decode().strip() != tools[key]:
            raise ToolDrift('phase receipt compiler/verifier identity differs: ' + key)


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
            contexts[receipt] = carry.prepare(registry['jobs'][receipt], receipt, root, plan,
                                              historical_reader=reader)
        context = contexts[receipt]
        context['receipt'] = receipt
        context.setdefault('selected_phases', []).append(name)
        if name not in context['manifest']['phases']:
            raise ValueError('receipt does not cover requested phase')
        manifest = reader.cache[receipt][0]
        selected = [entry for entry in manifest['commands'] if entry['phase'] == name]
        try:
            compatible_tools({**manifest, 'commands': selected}, registry['jobs'][receipt] / 'source')
        except ToolDrift as error:
            # Preserve the historical pass, but never reuse it for this phase.
            # Other phases keep their own compiler/verifier decisions.
            context.setdefault('tool_drift', {})[name] = str(error)
        entries = carry.required(context, 'command' if phase == 'command' else name, command)
        decisions.extend((entry, carry.disposition(entry, context)) for entry in entries)
    return list(contexts.values()), decisions


def authorization_plan(release_plan: dict, contexts: list, decisions: list) -> dict:
    """Bind one approval to actual remaining work across validated receipts.

    An older Miri receipt may see a compiler-matrix change, but is not the
    evidence selected for the matrix. Never authorize that unrelated phase
    through it, and never let it invalidate a newer successful matrix receipt.
    This function grants no approval and changes no reuse decision.
    """
    owners, bindings = {}, []
    for context in contexts:
        selected = context['selected_phases']
        if (not selected or len(set(selected)) != len(selected)
                or any(name not in catalog.PHASES or name in owners for name in selected)):
            raise ValueError('ambiguous phase approval routing')
        owners.update({name: context for name in selected})
        bindings.append({'receipt': context['receipt'], 'phases': sorted(selected),
                         'plan': plans.execution_identity(context['plan']),
                         'tool_drift': context.get('tool_drift', {})})
    remaining = set()
    for entry, reason in decisions:
        if entry['phase'] not in owners or not reason.startswith(('run:', 'reuse:')):
            raise ValueError('unbound phase approval decision')
        if reason.startswith('run:'):
            remaining.add(entry['phase'])
    pending = []
    for name in sorted(remaining):
        context = owners[name]
        delta = context['plan']
        if ((delta['approval_required'] and plans.requires_full(delta, name))
                or name in context.get('tool_drift', {})):
            pending.append(name)
    combined = dict(release_plan)
    combined.update(
        fingerprint=records.digest({'release_plan': plans.execution_identity(release_plan),
                                    'receipts': bindings, 'decisions': decisions}),
        approval_required=bool(pending), full_phases=pending,
        issues=['owner approval required for remaining full phase: ' + name for name in pending],
        phase_receipts=[{'receipt': b['receipt'], 'phases': b['phases']} for b in bindings],
        remaining_commands=sum(reason.startswith('run:') for _, reason in decisions),
    )
    return combined
