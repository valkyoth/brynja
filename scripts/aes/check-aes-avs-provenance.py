#!/usr/bin/env python3
"""Offline re-derivation of the six AESAVS fixtures; never extracts or rewrites files."""
import argparse
import hashlib
import importlib.util
import io
from pathlib import Path, PurePosixPath
import stat
import zipfile

spec = importlib.util.spec_from_file_location('avs_provenance_inputs', Path(__file__).with_name('check-aes-avs.py'))
avs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(avs)

ARCHIVES = {
    'MCT': '6a2a72c00b1daacb9a7d20ab92617d322fa1c5dee493968660990e3f4571426b',
    'MMT': '12d1616f7a713e807714055973f04efc402f46a14e3d81869717c7ace4ecbaf0',
}
MAX_ARCHIVE = 4 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MARKER = 'AESAVS provenance: PASS; two pinned original ZIPs; six normalized fixtures match'
require = avs.packaged.require


def bounded_file(path, limit):
    path = Path(path)
    require(path.is_file() and not path.is_symlink()
            and not any(parent.is_symlink() for parent in path.parents),
            'missing/nonregular/symlinked provenance input: ' + str(path))
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, 'provenance input exceeds size limit')
    return data


def check_archive(path, kind):
    require(kind in ARCHIVES, 'unknown AESAVS archive kind')
    data = bounded_file(path, MAX_ARCHIVE)
    require(hashlib.sha256(data).hexdigest() == ARCHIVES[kind],
            'original AESAVS ZIP hash mismatch: ' + kind)
    expected = {f'ECB{kind}{bits}.rsp' for bits in (128, 192, 256)}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(len(entries) <= 128, 'too many AESAVS archive entries')
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), 'duplicate AESAVS archive entry')
        for name in names:
            parsed = PurePosixPath(name)
            require(not parsed.is_absolute() and '..' not in parsed.parts
                    and '\\' not in name and str(parsed) == name.rstrip('/'),
                    'unsafe AESAVS archive member')
        require(expected <= set(names), 'missing selected AESAVS response file')
        for name in sorted(expected):
            entry = archive.getinfo(name)
            require(not entry.is_dir() and not entry.flag_bits & 1
                    and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                    and 0 < entry.file_size <= MAX_MEMBER,
                    'nonregular/encrypted/oversized AESAVS response file')
            with archive.open(entry) as handle:
                raw = handle.read(MAX_MEMBER + 1)
            require(len(raw) == entry.file_size and len(raw) <= MAX_MEMBER,
                    'AESAVS response size mismatch')
            normalized = raw.replace(b'\r\n', b'\n').rstrip(b'\n') + b'\n'
            require(hashlib.sha256(normalized).hexdigest() == avs.HASHES[name],
                    'normalized original differs from pinned AESAVS fixture: ' + name)
            current = bounded_file(avs.FIXTURE / 'fixtures' / name, MAX_MEMBER)
            require(current == normalized, 'checked-in AESAVS fixture differs from original: ' + name)
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mct', type=Path, required=True, help='Local original aesmct.zip')
    parser.add_argument('--mmt', type=Path, required=True, help='Local original aesmmt.zip')
    args = parser.parse_args()
    try:
        require(check_archive(args.mct, 'MCT') + check_archive(args.mmt, 'MMT') == 6,
                'wrong provenance population')
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.error(str(error))
    print(MARKER)


if __name__ == '__main__':
    main()
