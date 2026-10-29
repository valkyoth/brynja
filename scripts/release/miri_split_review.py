"""Source-bound review of KMAC setup / TupleHash output-width decomposition.

This is coverage of the original scenario, NOT a claim that a new process ran.
New selector/accounting regression suites are deliberately not covered here.
The source-delta validator separately checks implementation/dependency changes.
"""
import hashlib

import miri_decomposition_reuse as decomposition
import verification_plan as plans

TESTS = {
    'kmac': ('crates/brynja-mac-kmac/src/setup/tests.rs',
             '036dc52cce7799735231c14490f88bd51056b225c45d340259193990cdd9c68f',
             '61d6e038f6fccede178a0ecf1f4bc03937a771c93b578db811175e479ab0c5e9'),
    'tuplehash': ('crates/brynja-hash-tuple/src/hardened_in_place/tests.rs',
                  '22d550592424950eff033ead263246aff6b83d972db8aa6f06e81b95459f6581',
                  'cda6d794f4326ad31cd894c34ffd5b7f54ec071eb77817785af4e0246c43f5cd'),
}
SUPPORT = {
    'kmac': ('crates/brynja-mac-kmac/tests/verification_errors.rs',
             '5df3042c6fedb7fc2b326da99ec5b9dfde558a574312b7bb952995d10da583fe'),
    'tuplehash': ('crates/brynja-hash-tuple/src/hardened_in_place/xof/tests.rs',
                  'aa71cce7ca0a29ee16da78c3e01b155024f9c3d1bed4f6b46a7385de6daf5234'),
}
SETUP = 'setup::tests::streamed_setup_matches_all_four_contiguous_identities'
VERIFICATION = ('kmac128_mismatch_and_exact_width', 'kmac256_mismatch_and_exact_width',
                'scoped_mismatch_propagates_and_workspace_can_be_reused')
TUPLE = {f'hardened_in_place::{module}::scoped_tuple{kind}{strength}_{suffix}': total
         for module, kind, suffix, total in (
             ('tests', '', 'matches_portable_bits_and_streaming', 56),
             ('xof::tests', 'xof', 'differential', 48)) for strength in (128, 256)}


def pair(before, after, expected):
    return (before is not None and after is not None and
            tuple(hashlib.sha256(raw).hexdigest() for raw in (before, after)) == expected)


def source_groups(root, base, changed):
    """Keep all upstream families unchanged; admit only the exact two test edits."""
    untouched = decomposition.prove(root, base, changed)
    # Conservatively require every other family except independent HMAC and
    # ParallelHash. This is a reviewed checkpoint transition, not a general
    # dependency exemption. The ordinary proof checks all global/build inputs.
    required = set(plans.scope.GROUPS) - {'kmac', 'tuplehash', 'parallelhash', 'hmac'}
    if not required <= untouched:
        return set()
    found = set()
    for group, (test_path, old_hash, new_hash) in TESTS.items():
        if not pair(*plans.inputs.snapshot(root, base, test_path), (old_hash, new_hash)):
            continue
        support, digest = SUPPORT[group]
        if not pair(*plans.inputs.snapshot(root, base, support), (digest, digest)):
            continue
        valid = True
        for path in changed:
            if path == test_path or not path.startswith(plans.scope.GROUP_PREFIXES[group]):
                continue
            before, after = plans.inputs.snapshot(root, base, path)
            pin = f'scripts/{group}/{group}_reviewed_hashes.py'
            if path != pin or not plans.inputs.python_bindings_only(before, after):
                valid = False
                break
        if valid:
            found.add(group)
    return found


def reviewed_roots(old_root, new_root, group):
    if group not in TESTS:
        return False
    path, before, after = TESTS[group]
    support, digest = SUPPORT[group]
    pairs = {**decomposition.REVISIONS, path: (before, after), support: (digest, digest)}
    try:
        for name, expected in pairs.items():
            files = [root / name for root in (old_root, new_root)]
            if any(p.is_symlink() or p.stat().st_size > 1024 * 1024 for p in files):
                return False
            if not pair(*(p.read_bytes() for p in files), expected):
                return False
        return True
    except OSError:
        return False


def predecessor(task, group, profile, old_tasks):
    """Return one exact old definition covering a reviewed split, or None."""
    if profile != 'extended' or set(task) != {'argv', 'environment', 'marker'}:
        return None
    argv, env, marker = task['argv'], task['environment'], task['marker']
    if group == 'tuplehash' and len(argv) == 6 and argv[:3] == ['-p', 'brynja-hash-tuple', '--lib']:
        name = argv[3]
        if name not in TUPLE or argv[-2:] != ['--', '--exact']:
            return None
        if set(env) != {'BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE', 'BRYNJA_MIRI_WIDTH'}:
            return None
        case, width = env['BRYNJA_MIRI_CASE'], env['BRYNJA_MIRI_WIDTH']
        if (case not in {str(i) for i in range(TUPLE[name])} or width not in {'0', '1', '2', '3', '4'}
                or env['BRYNJA_MIRI_PROFILE'] != 'extended'
                or marker != f'MIRI_CASE_PASS: {name.split("::")[-1]}:{case}:width={width}'):
            return None
        old = {**task, 'environment': {k: v for k, v in env.items() if k != 'BRYNJA_MIRI_WIDTH'},
               'marker': marker.rsplit(':width=', 1)[0]}
        return old if old in old_tasks else None
    if group != 'kmac':
        return None
    setup = (argv == ['-p', 'brynja-mac-kmac', '--lib', SETUP, '--', '--exact']
             and set(env) == {'BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE'}
             and env['BRYNJA_MIRI_CASE'] in {str(i) for i in range(100)}
             and env['BRYNJA_MIRI_PROFILE'] == 'extended'
             and marker == 'MIRI_CASE_PASS: kmac-streamed-setup:' + env['BRYNJA_MIRI_CASE'])
    verify = (len(argv) == 7 and argv[:4] == ['-p', 'brynja-mac-kmac', '--test', 'verification_errors']
              and argv[4] in VERIFICATION and argv[-2:] == ['--', '--exact'] and env == {} and marker is None)
    if not (setup or verify):
        return None
    name = SETUP if setup else argv[4]
    for old in old_tasks:
        command = old['argv']
        if (set(old) != {'argv', 'environment', 'marker'} or old['environment'] or old['marker'] is not None
                or command[:4] != ['-p', 'brynja-mac-kmac', '--tests', '--']):
            continue
        options = command[4:]
        if (len(options) % 2 or any(option != '--skip' for option in options[::2])
                or any(skip in name for skip in options[1::2])):
            continue
        return old
    return None
