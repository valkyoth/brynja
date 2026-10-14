"""Read-only comparison with a hash-bound historical verifier observation."""
import hashlib
import json
import subprocess
import sys


def canonical(output, source_root=None):
    payload = json.loads(output)
    actual = payload.get('compared_source_root')
    if not isinstance(actual, str) or not actual:
        raise ValueError('missing compared historical source root')
    if source_root is not None and actual != str(source_root):
        raise ValueError('verifier compared another source root')
    if payload.get('current_checkout_compared') is not False:
        raise ValueError('historical verification cannot qualify the current checkout')
    # Only this explicit display field is transient. No recursive path/string
    # replacement: source hashes, route identities and qualification bits stay exact.
    payload['compared_source_root'] = '<historical-85903ae0>'
    return json.dumps(payload, sort_keys=True, indent=2) + '\n'


def replay(script, source_root, recorded, expected_hash):
    before = recorded.read_bytes()
    if hashlib.sha256(before).hexdigest() != expected_hash:
        raise ValueError('recorded historical replay hash mismatch')
    expected = canonical(before)
    result = subprocess.run([sys.executable, str(script), '--source-root', str(source_root)],
                            text=True, capture_output=True, timeout=300)
    result.check_returncode()
    if result.stderr:
        raise ValueError('unexpected historical verifier diagnostics: ' + result.stderr[-2000:])
    actual = canonical(result.stdout, source_root)
    if actual != expected:
        raise ValueError('historical replay differs from recorded evidence')
    if recorded.read_bytes() != before:
        raise ValueError('historical verifier modified its recorded evidence')
    return json.loads(actual)
