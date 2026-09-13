"""Single owner-approved internal MD5 deferral; never a public-release waiver."""
from pathlib import Path
import hashlib
import json
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/md5'))
import md5_execution_policy

VERSION = 'v0.24.43'
RECORD = 'security/pentest/v0.24.43-deferral.json'
REVIEW_HASH = 'b6606c1f2dbdc4de75d8a4a37832361657ee659309d00c1c9f34d389a0dceb6e'
EXPECTED = {
    'schema': 1,
    'version': VERSION,
    'finding': 'MD5-ORDINARY-SIMD-CLEANUP',
    'severity': 'Medium',
    'status': 'open',
    'deferred_to': 'v0.24.44',
    'profile': 'ordinary-public-only',
    'owner_approval': 'explicit-internal-v0.24.43-only',
    'approved_date': '2026-09-13',
    'reviewed_source_sha256': REVIEW_HASH,
}
FIELDS = {
    'Version': VERSION,
    'Baseline': 'v0.24.42',
    'Status': 'PASS WITH DEFERRAL',
    'Retest': 'PASS WITH DEFERRAL',
    'Open-Findings': '1',
    'Deferred-Finding': EXPECTED['finding'],
    'Deferred-To': EXPECTED['deferred_to'],
}


def require(value, message):
    if not value:
        raise ValueError('internal MD5 deferral: ' + message)


def read(root, name):
    path = root / name
    require(not path.is_symlink() and path.is_file(), 'missing/invalid ' + name)
    with path.open('rb') as stream:
        data = stream.read(2_000_001)
    require(len(data) <= 2_000_000, 'oversized ' + name)
    return data.replace(b'\r\n', b'\n')


def validate(root=ROOT, version=VERSION, publish_tag=''):
    require(version == VERSION, 'only v0.24.43 may use this exception')
    require(not publish_tag, 'publication context cannot use a deferral')
    plan = tomllib.loads(read(root, 'release-crates.toml').decode())
    release = plan['release']
    require(release.get('stage') == 'internal', 'public releases require zero findings')
    require(release.get('version') == '0.24.43' and
            release.get('milestone') == '0.24.43', 'release identity differs')
    require(release.get('exceptional') is True, 'exceptional review remains mandatory')
    crates = plan.get('crates', {})
    require(bool(crates) and all(row.get('publish') is False for row in crates.values()),
            'all crates must remain unpublished')
    record = json.loads(read(root, RECORD))
    require(json.dumps(record, sort_keys=True) == json.dumps(EXPECTED, sort_keys=True),
            'approval, finding or source binding differs')
    lines = read(root, 'security/pentest/' + VERSION + '.md').decode().splitlines()
    for name, value in FIELDS.items():
        matches = [line for line in lines if line.startswith(name + ':')]
        require(matches == [name + ': ' + value], 'report field differs: ' + name)
    require(hashlib.sha256(read(root, md5_execution_policy.REVIEW)).hexdigest() == REVIEW_HASH,
            'approved source review changed; new approval required')
    # A matching review file alone is insufficient: verify every actual source
    # file and the ordinary/hardened/default-off boundaries it binds.
    md5_execution_policy.validate(root)
    require(tomllib.loads(read(root, 'rust-toolchain.toml').decode())['toolchain']['channel']
            == '1.98.1', 'approved compiler changed')


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 3, 'expected version and publication context')
        validate(version=sys.argv[1], publish_tag=sys.argv[2])
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    print('v0.24.43 internal-only deferral accepted; MD5 cleanup finding remains OPEN for v0.24.44')
