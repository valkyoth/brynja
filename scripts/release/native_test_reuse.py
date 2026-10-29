"""Exact v0.25.2 test decomposition, not a general tests-directory exemption.

The four reviewed modules remain behind unchanged cfg(test) parents. Native
matrices retain their original cases; Miri work is split into smaller tasks.
This preserves ORIGINAL native observations, not qualification of changed tests.
Pins detect drift, not authorization: callers must authenticate the historical
artifacts with the external owner approval before using this source proof.
"""
import native_review_io as io

CAPTURE = 'ea97052babc657846851a303962eb1244477f5d6'
# Test path, unchanged declaring parent, parent digest, old/new test digests.
FAMILIES = {
    'kmac-execution': ('scripts/kmac/kmac_reviewed_hashes.py', '"', (
        ('crates/brynja-mac-kmac/src/setup/tests.rs',
         'crates/brynja-mac-kmac/src/setup.rs',
         '2753458ba00729f09991515926061de544a4ab3b21c0f03bf3c9d0f412c18bc5',
         '036dc52cce7799735231c14490f88bd51056b225c45d340259193990cdd9c68f',
         '61d6e038f6fccede178a0ecf1f4bc03937a771c93b578db811175e479ab0c5e9'),)),
    'tuplehash-execution': ('scripts/tuplehash/tuplehash_reviewed_hashes.py', '"', (
        ('crates/brynja-hash-tuple/src/hardened_in_place/tests.rs',
         'crates/brynja-hash-tuple/src/hardened_in_place.rs',
         '5778f14d96fa58b026be95cedf2d7481b8f4dcd9b6eaaa911896229e2415b025',
         '22d550592424950eff033ead263246aff6b83d972db8aa6f06e81b95459f6581',
         'cda6d794f4326ad31cd894c34ffd5b7f54ec071eb77817785af4e0246c43f5cd'),)),
    'parallelhash-execution': ('scripts/parallelhash/parallelhash_reviewed_hashes.py', "'", (
        ('crates/brynja-hash-parallel/src/hardened_in_place/tests.rs',
         'crates/brynja-hash-parallel/src/hardened_in_place.rs',
         'ec68f4ea8807a71091464e0ad501dff30448d4d5c5db09f83194c59ba9157c61',
         '79a3a6ffdc597cfafd54019e9b198f5dca05cf8665aaaa2e37b3f663482e674c',
         '4f342299e9108a20c608e66100845e2e57331fa426eeba472f4beecdb35fe045'),
        ('crates/brynja-hash-parallel/src/hardened_in_place/xof/tests.rs',
         'crates/brynja-hash-parallel/src/hardened_in_place/xof.rs',
         'd0ed2f4a525dad1ea297fd37381a606278e62f8fc050bcfb9a380f24d02a0398',
         'd6615d21a9caa47c6c2409ed263aa56bb276418524e9d95b7e41838f4d29aaa6',
         'd0c5c3ec83a30e9ae0c5eea4ea95dec71654c6fa4a5645b7407f2619a18351a5'))),
}


def changes(root, capture, head, current, captured, family):
    """Return exact reviewed raw-byte pairs, or no exception for other captures.

The caller still checks the entire source/build closure, additions/deletions,
ancestry, artifact identity, original results and approved validation deltas.
"""
    if capture != CAPTURE or family not in FAMILIES:
        return {}
    register, quote, rows = FAMILIES[family]
    if not any(current.get(row[0]) != captured.get(row[0]) for row in rows):
        return {}
    required = {register} | {name for row in rows for name in row[:2]}
    io.require(required <= set(current) & set(captured), 'test review input missing')
    result = {}
    old_register = io.raw_blob(root, capture, register)
    expected_register = old_register
    for name, parent, parent_sha, before, after in rows:
        for revision, expected in ((capture, before), (head, after)):
            raw = io.raw_blob(root, revision, name)
            io.require(io.sha(raw) == expected, 'unreviewed test bytes: ' + name)
            declaration = io.raw_blob(root, revision, parent)
            io.require(io.sha(declaration) == parent_sha and
                       declaration.count(b'#[cfg(test)]\nmod tests;') == 1,
                       'test-only declaration changed: ' + parent)
        old = f'{quote}{name}{quote}: {quote}{before}{quote}'.encode()
        new = f'{quote}{name}{quote}: {quote}{after}{quote}'.encode()
        io.require(expected_register.count(old) == 1, 'test review pin missing/ambiguous')
        expected_register = expected_register.replace(old, new, 1)
        result[name] = {'before': before, 'after': after}
    new_register = io.raw_blob(root, head, register)
    io.require(new_register == expected_register,
               'test review cannot change executable policy or other pins')
    result[register] = {'before': io.sha(old_register), 'after': io.sha(new_register)}
    return result
