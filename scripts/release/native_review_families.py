"""Historical native records still use their original family result validators.

Load exactly one family per process: older policy modules use shared short names.
The index and artifact bytes must equal the reviewed commit, so this adapter does
not grant authority to a rewritten index, a relabelled capture, or new claims.
"""
import importlib.util
import sys

import native_review_io as io

FAMILIES = {
    'sha1-hardened': ('sha1', 'check-sha1-hardened-native'),
    'md5-execution': ('md5', 'md5_execution_native'),
    'md5-hardened': ('md5', 'md5_hardened_native'),
    'keccak-hardened': ('sha3', 'keccak_hardened_native'),
    'kmac-execution': ('kmac', 'kmac_execution_native'),
    'tuplehash-execution': ('tuplehash', 'tuplehash_execution_native'),
    'parallelhash-execution': ('parallelhash', 'parallelhash_execution_native'),
}


class Family:
    def __init__(self, name, root):
        self.name, self.root = name, root
        directory, module = FAMILIES[name]
        sys.path.insert(0, str(root / 'scripts' / directory))
        spec = importlib.util.spec_from_file_location('native_review_family',
            root / 'scripts' / directory / (module + '.py'))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def sources(self):
        if self.name == 'sha1-hardened':
            return self.module.native.policy.hashes(self.root)
        if self.name.startswith('md5'):
            return self.module.policy.snapshot(self.root)
        return self.module.sources(self.root)

    def digest(self, name, raw):
        if self.name == 'sha1-hardened':
            return io.sha(io.normalized(raw).replace(b'\r', b'\n'))
        if self.name.startswith('md5'):
            return io.sha(io.normalized(raw))
        if self.name.startswith('parallelhash'):
            return self.module.digest(name, raw)
        return self.module.shared.source_digest(name, raw)

    def records(self, review, head):
        def unchanged(name):
            raw = io.committed(self.root, name, head)
            io.require(raw == io.historical(self.root, review['reviewed_commit'], name),
                       'original reviewed index/artifact changed: ' + name)
            return raw

        index = io.document(unchanged(self.module.INDEX))
        sha1 = self.name == 'sha1-hardened'
        legacy = sha1 or self.name.startswith('md5')
        rows = index['captures' if sha1 else 'lanes']
        lanes = self.module.native.LANES if sha1 else self.module.LANES
        io.require(set(rows) == set(lanes), 'all reviewed native lanes required')
        if legacy:
            io.require(index['owner_review'] == 'accepted-correctness-with-residuals',
                       'native owner review pending')
        else:
            io.require(index['capture_commit'] == review['capture_commit'], 'index capture mismatch')
        records = []
        for lane, row in rows.items():
            raw = unchanged(row['path' if sha1 else 'artifact'])
            io.require(io.sha(raw) == row['sha256'], 'native artifact checksum')
            record = io.document(raw)
            io.require(record['commit'] == review['capture_commit'], 'record capture mismatch')
            if not legacy:
                io.require(row['reviewed'] is True and row['cpu'] == record['cpu'],
                           'native CPU owner review')
            elif not sha1:
                io.require(row['commit'] == record['commit'], 'MD5 index commit mismatch')
            old = record['source_sha256' if legacy else 'sources']
            for name, value in old.items():
                io.require(self.digest(name, io.historical(self.root, record['commit'], name)) == value,
                           'historical native source mismatch: ' + name)
            if sha1:
                self.module.validate_record(record, lane, old)
            else:
                self.module.record_check(record, lane, record['commit'], old)
            records.append(old)
        io.require(all(value == records[0] for value in records), 'inconsistent capture closures')
        return records[0], len(records)
