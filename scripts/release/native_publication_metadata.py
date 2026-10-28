"""Exact v0.25.2 legacy metadata projection, not native execution approval.

Only the pinned coordinated version/packaging edits below are projected back
to their pre-publication bytes. No Rust, README, fixture source, arbitrary
version, feature, graph edge or third-party identity is normalized. Captured
tools still need the separately owner-approved raw before/after digests.
This never qualifies changed HMAC/KMAC routes or a new public checkpoint.
"""
import native_review_io as io

BASE = '697b5ec2adedda6c92eeb914c7f5baee92e6e655'
REVIEW = '42a98e38673204ca2f91a69327c9580a5a648342'
PROFILES = frozenset(('md5-native-execution', 'sha1-native-hardened'))
PAIRS = {
    'Cargo.toml': (
        '851f5460dbc44b2af73ea7a14486271cb30a953a6bbfcb33a951384209cf90af',
        'b4dfe95ff50491c0e32efcfa03c9ccf7bf95125c98dd8c82c3a128cf4e944712'),
    'Cargo.lock': (
        'b05f41c04614fc7e2a924af50555a6a7633a2f23a35afb8dedd0ce2fec848951',
        'f1da6703b8271d6e6482fc0bcd0b90e15c6de13091ec21d73defafd41574edf0'),
    'crates/brynja-core/Cargo.toml': (
        'e98247de69314a5ce1f6ecde69c081e03237cb663645483e4b9aed3a04929c5d',
        '518008db885478a22d3d93549cf9d6fe26c389c13356e004b567e1b2f8c8c1a4'),
    'crates/brynja-legacy-md5/Cargo.toml': (
        '895e722a3663ef4791d801d8b10324aa9dc9a9da5b5927834a15c978f051e03c',
        '16e339d9ede1be3f38250724fe2e8dde0947b19236eb9ee83a0f5656340f0201'),
    'crates/brynja-legacy-md5-std/Cargo.toml': (
        '8873b69a554f09b392469aa37ac8124895e28b78bc3822eb6483057e6a8e89c5',
        '2fa13574c75626c4b7d080533ad65c76f51181e09e122735c9fd8921de1b3e22'),
    'crates/brynja-legacy-sha1/Cargo.toml': (
        '10d8582f9b077924556e92e809bac3510cb2cd2ebedeb73e70d553cc1e16220b',
        'bdf4ccc654ec3a16b7883614d3091fb915556bc84eed389599035b66915805f5'),
    'crates/brynja-legacy-sha1-std/Cargo.toml': (
        'c876e1d9b2eb3fdfa1241eb3e2ccff5aae5afdec28dcad9e1440480004e98f2d',
        'ae04f64c5d01737c13c9161fd6dabc8e57d5aa99c19271e4cd2b8bac72bd6c23'),
    'assurance/md5-execution/Cargo.lock': (
        '8be70a4104178ebfd12aee1d0221d7fc48e67f79fbf2a50e8f8343fd92f26d11',
        '2f33447bc73783a9f61a6932fec36bc10d8f19ced288c8854c8295524bc2b1a8'),
    'assurance/md5-hardened-execution/Cargo.lock': (
        '3b1a35f983710c8db7976e782587b0bf00ecf54ef8067db86edef8081e185e49',
        '4d6ac520ec82abdf1d9ca6557656244d7380c3d6f595b862688665711633c09a'),
    'scripts/md5/check-md5-package.py': (
        '9c67ddf684c3c5df3afb4c2946363f2bb50d1f002c68714ef8ea6daff62e06e8',
        '51b3a0e467ec65e79bcbb37842088188d26f6048a053b24b51f315b65c839346'),
    'scripts/sha1/check-sha1-package.py': (
        '3223d08e8f55c4549ac3ce2da8e48914990f3de686a09baaa8cb189d44695ec8',
        'bd442e08949fbd0bde86c8f0c805b1fff91aacb1a0922907d32f53d0dfc30ad7'),
}


def normalize(name, raw, profile):
    if profile not in PROFILES or name not in PAIRS or io.sha(raw) != PAIRS[name][1]:
        return raw
    # Read reference bytes as data only. Their raw digest is independently
    # pinned here; neither the current version nor current hashes define it.
    before = io.raw_blob(io.ROOT, BASE, name)
    io.require(io.sha(before) == PAIRS[name][0], 'publication metadata reference drift')
    return before


def raw(root, revision, name, profile):
    return normalize(name, io.raw_blob(root, revision, name), profile)


def equivalent(root, before, after, name, profile):
    if profile not in PROFILES or name not in PAIRS or not name.endswith(('Cargo.toml', 'Cargo.lock')):
        return False
    old, new = (io.raw_blob(root, revision, name) for revision in (before, after))
    return old != new and normalize(name, old, profile) == normalize(name, new, profile)
