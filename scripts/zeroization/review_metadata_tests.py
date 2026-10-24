"""Review-only scope regressions; no compiler or verifier is executed here."""
import hashlib
import json
from unittest.mock import patch

import miri_scope as scope
import scope_inputs as inputs
import scope_review_metadata as review


def document(rows, *, active=0):
    text = '[limits]\nactive_backend_count = ' + str(active) + '\n'
    for row in rows:
        text += '\n[[sources]]\n' + '\n'.join(
            key + ' = ' + json.dumps(value) for key, value in row.items()) + '\n'
    return text.encode()


def selected(changes, sources=None):
    values = {**(sources or {}), **changes}
    def git(_root, *args):
        return b'\0'.join(path.encode() for path in changes) if args[0] == 'diff' else b''
    with patch.object(inputs, 'git', side_effect=git), patch.object(
            inputs, 'snapshot', side_effect=lambda r, b, p: values.get(p, (None, None))):
        return scope.select_repository('v0.24.49')


def test_review_metadata():
    test_hmac_review_metadata()
    boundary = 'security/cpu-acceleration-boundary.toml'
    source = 'crates/brynja-crypto-cpu-std/src/lib.rs'
    added = 'crates/brynja-crypto-cpu-std/src/windows_enclave/mod.rs'
    body, window = b'// current library\n', b'// current windows\n'
    old = {'package': 'brynja-crypto-cpu-std', 'path': 'src/lib.rs',
           'status': 'boundary-only', 'sha256': '0' * 64}
    current = {**old, 'sha256': hashlib.sha256(body).hexdigest()}
    extra = {**old, 'path': 'src/windows_enclave/mod.rs',
             'status': 'windows-enclave-host-development',
             'sha256': hashlib.sha256(window).hexdigest()}
    before, after = document([old]), document([current, extra])
    sources = {source: (body, body), added: (window, window)}
    assert selected({boundary: (before, after)}, sources) == (False, ())
    assert selected({boundary: (after, after)}, sources) == (False, ())
    bad = [document([current]), document([current, extra], active=1),
           document([current, extra, extra]), document([extra]),
           document([{**current, 'status': 'approved'}, extra]),
           document([current, {**extra, 'sha256': '1' * 64}]),
           document([current, {**extra, 'sha256': 'z' * 64}]),
           document([current, {**extra, 'path': 'src/../escape.rs'}]),
           document([current, {**extra, 'path': 'src//alias.rs'}]),
           document([current, {**extra, 'package': 'unknown'}]),
           document([current, {**extra, 'unknown': 'field'}]),
           b'invalid TOML =', None]
    # Removing an existing inventory entry is never a metadata-only change.
    for altered in bad:
        assert selected({boundary: (after, altered)}, sources)[1], altered
    for pair in ((None, window), (window, None), (b'old implementation', window)):
        assert selected({boundary: (before, after)}, {**sources, added: pair})[1]
    for field in ('limits', 'active_backend_count'):
        assert selected({boundary: (before, after.replace(field.encode(), b'other'))}, sources)[1]

    # A valid metadata correction cannot conceal a concurrent changed Rust file.
    for path in (source, added, 'crates/brynja-hash-sha3/src/sponge.rs',
                 'crates/brynja-mac-kmac/src/lib.rs'):
        change = {boundary: (before, after), path: (b'old', b'new')}
        assert selected(change, sources)[1]
    for path in ('Cargo.toml', 'rust-toolchain.toml', '.cargo/config.toml',
                 'scripts/zeroization/run-miri-task.py', 'unknown_crypto.rs'):
        assert selected({boundary: (before, after), path: (b'old', b'new')}, sources)[0]

    for path in review.SCRIPT_COMMANDS:
        assert selected({path: (b'# before', b'# after')}) == (False, ())
        assert selected({path: (b'# before', None)})[1]
        assert selected({path: (b'# before', b'')})[1]
    for path in review.NEW_METADATA:
        assert selected({path: (None, b'# inventory')}) == (False, ())
    # Metadata cannot hide a concurrent hash/engine/fixture/compiler edit.
    for parser in review.API_METADATA:
        for source in ('crates/brynja-mac-hmac/src/engine.rs',
                       'crates/brynja-hash-sha2/src/hardened/owner.rs',
                       'scripts/hmac/check-hmac-engine-cleanup.py',
                       'scripts/cryptography/secret_owner_compiler.py',
                       'assurance/hmac-engine-cleanup/src/lib.rs'):
            assert selected({parser: (b'# old', b'# new'), source: (b'old', b'new')})[1]
    for path in ('scripts/cpu/new_checker.py', 'scripts/kmac/new_driver.py',
                 'scripts/kmac/check-kmac-codegen.sh.rs',
                 'scripts/cpu/cpu_boundary_windows.py.rs'):
        assert selected({path: (None, b'# new')})[1]

    hashes = 'scripts/kmac/kmac_reviewed_hashes.py'
    binding = b'REVIEWED_HASHES = {"src/lib.rs": "' + b'a' * 64 + b'"}\n'
    rebound = binding.replace(b'a' * 64, b'b' * 64)
    assert selected({hashes: (binding, rebound)}) == (False, ())
    for altered in (rebound + b'execute()\n', rebound.replace(b'lib.rs', b'other.rs'),
                    rebound.replace(b'b' * 64, b'b' * 63), None):
        assert selected({hashes: (binding, altered)})[1]

    path = 'scripts/hash/final-acceptance-hashes.toml'
    binding = b'[files]\n"src/lib.rs" = "' + b'a' * 63 + b'"\n'
    rebound = binding.replace(b'a' * 63, b'b' * 64)
    assert selected({path: (binding, rebound)}) == (False, ())
    for altered in (binding.replace(b'a' * 63, b'a' * 62), rebound.replace(b'lib.rs', b'other.rs'),
                    rebound + b'[policy]\nwaive=true', None,
                    rebound.replace(b'b' * 64, b'z' * 64)):
        assert selected({path: (binding, altered)})[1]
    assert selected({path: (binding, rebound), 'crates/brynja-hash-sha2/src/lib.rs':
                     (b'old', b'new')}) == (False, ('sha2', 'hmac'))
    print('Review-only scope retains runtime/build/verifier changes and rejects malformed, removed and broadened inventories')


def test_hmac_review_metadata():
    import copy
    base = '8a93f40dcd33b1a4328d107233ead5b5d7933eef'
    completed = '143fc953fbc31a8affb3507dd8273a132c7d9f54'  # v0.25.0

    def historical(path):
        return (inputs.snapshot(scope.ROOT, base, path)[0],
                inputs.snapshot(scope.ROOT, completed, path)[0])

    for path in review.DIAGNOSTIC_PAIRS:
        before, after = historical(path)
        for left, right in ((before, after), (after, before)):
            assert selected({path: (left, right)}) == (False, ())
        for mutant in (None, b'', after + b'\n', after.replace(b'\n', b'\r\n'),
                       after.replace(b'600', b'601'), after.replace(b'detect_leaks=1', b'detect_leaks=0')):
            if mutant != after:
                assert selected({path: (before, mutant)})[1]
        kernel = 'crates/brynja-crypto-cpu/src/x86_sha512/secret.rs'
        assert selected({path: (before, after), kernel: (b'old', b'new')})[1]

    source_names = {'crates/brynja-crypto-cpu-std/' + p for p in review.hmac.HOSTED_SOURCES}
    source_names |= set(review.hmac.SOURCES) | set(review.hmac.TEST_SUFFIXES)
    sources = {p: historical(p) for p in source_names}
    boundary = 'security/cpu-acceleration-boundary.toml'
    before, after = historical(boundary)
    assert selected({boundary: (before, after)}, sources) == (False, ())
    for old, new in ((b'protected-scalar-hmac-session-development', b'admitted'),
                     (b'src/strict_hmac/mod.rs', b'src/strict_hmac/unknown.rs'),
                     (b'active_backend_count = 0', b'active_backend_count = 1')):
        mutant = after.replace(old, new)
        assert mutant != after
        assert selected({boundary: (before, mutant)}, sources)[1]
    for path in source_names:
        if path in review.hmac.TOOL_PAIRS:
            continue
        left, right = sources[path]
        if right is None:
            continue
        changed = {**sources, path: (left, right + b'changed()\n')}
        # A real source edit cannot be hidden behind unchanged metadata.
        assert selected({boundary: (before, after), path: changed[path]}, changed)[1]

    for path, size in review.BATCH_INVENTORIES.items():
        before, after = historical(path)
        a, b = json.loads(before), json.loads(after)
        added = sorted(b['files'].keys() - a['files'].keys())
        assert len(added) == 19
        assert selected({path: (before, after)}, sources) == (False, ())
        def rejects(mutant, overrides=None):
            assert selected({path: (before, json.dumps(mutant).encode())},
                            {**sources, **(overrides or {})})[1]
        for field in ('schema', 'version'):
            mutant = copy.deepcopy(b)
            mutant[field] = 'changed'
            rejects(mutant)
        mutant = copy.deepcopy(b)
        mutant['files'].pop(next(iter(a['files'])))
        rejects(mutant)
        for name, digest in ((added[0], '0' * size), (added[0], 'z' * size),
                             (added[0], '0' * (size // 2)),
                             ('crates/brynja-crypto-cpu-std/src/unrelated.rs', '0' * size)):
            mutant = copy.deepcopy(b)
            mutant['files'][name] = digest
            rejects(mutant)
        for pair in ((None, None), (b'existing source', sources[added[0]][1]),
                     (None, sources[added[0]][1] + b'changed()')):
            rejects(b, {added[0]: pair})
        duplicate = after.replace(b'"files": {', b'"files": {}, "files": {', 1)
        assert selected({path: (before, duplicate)}, sources)[1]
        # A legitimate changed HMAC source is still selected even when the
        # inventory correctly follows its new digest; no old HMAC PASS implied.
        current = sources[added[0]][1] + b'changed()\n'
        mutant = copy.deepcopy(b)
        digest = hashlib.sha256 if size == 64 else hashlib.sha512
        mutant['files'][added[0]] = digest(current).hexdigest()
        pair = (None, current)
        assert selected({path: (before, json.dumps(mutant).encode()), added[0]: pair},
                        {**sources, added[0]: pair}) == (False, ('hmac',))
    print('HMAC review inventories: source-bound additions, parser changes and concurrent implementation mutations PASS')
