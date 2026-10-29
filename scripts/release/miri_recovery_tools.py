"""Sealed, versioned selected-tool comparison for Miri-only recovery.

No live probes here: historical validation must not depend on the collector.
The new runner still seals and checks its complete live tool inventory. This
rule compares recorded identities, not authenticated binary attestations.
"""
import miri_coverage_identity as identity

POLICY = 'selected-miri-v1'
FIELD = 'recovery_tools'


def miri_only(manifest):
    commands = manifest.get('commands', [])
    return bool(commands) and all(e.get('phase') == 'miri' and identity.is_task(e) for e in commands)


def validate(manifest):
    if FIELD in manifest and (manifest.get('schema') != 3 or manifest[FIELD] != POLICY
                             or not manifest.get('recovery') or not miri_only(manifest)):
        raise ValueError('invalid selected-Miri recovery tool policy')


def bind(manifest, parent=None):
    """New recovery opts in explicitly; resume preserves its parent's rule."""
    if parent is not None:
        if FIELD in parent:
            manifest[FIELD] = parent[FIELD]
    elif manifest.get('recovery') and miri_only(manifest):
        manifest[FIELD] = POLICY
    validate(manifest)


def compatible(old, new, old_root, new_root):
    validate(new)
    if FIELD not in new:
        return old['tools'] == new['tools']
    if not miri_only(old):
        return False
    # Share the phase validator's selected compiler resolution. Import locally
    # because phase validation also uses the detached recovery/history reader.
    import phase_receipts as phases
    before, after = old['tools'], new['tools']
    if any(not isinstance(tools, dict) or any(not isinstance(v, str) or not v.strip()
                                             for v in tools.values()) for tools in (before, after)):
        return False
    try:
        old_probes = phases.records.verifier_commands(old_root, old['commands'])
        new_probes = phases.records.verifier_commands(new_root, new['commands'])
        old_compilers = phases.compiler_keys(old, old_root)
        new_compilers = phases.compiler_keys(new, new_root)
        if (set(old_probes) != {'verifier:miri'} or old_probes != new_probes
                or not old_compilers or old_compilers != new_compilers):
            return False
        required = {'platform', 'rustc', 'cargo'} | old_compilers | set(old_probes)
        return all(isinstance(before.get(k), str) and before[k].strip()
                   and before[k] == after.get(k) for k in required)
    except (OSError, KeyError, TypeError, ValueError):
        return False
