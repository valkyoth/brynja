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
    assert selected({'scripts/cpu/cpu_boundary_windows.py': (None, b'# inventory')}) == (False, ())
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
