"""Bounded Git/file primitives for explicit native evidence equivalence reviews."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from functools import lru_cache

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError('native reviewed carry-forward: ' + message)


def relative(name):
    require(isinstance(name, str) and bool(name) and '\\' not in name and
            not PurePosixPath(name).is_absolute() and
            all(part not in ('', '.', '..') for part in name.split('/')),
            'invalid repository path')
    return name


def normalized(raw):
    return raw.replace(b'\r\n', b'\n')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=unique)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, timeout=30)


def revision(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{40}', value),
            'full commit identity required')
    return value


def read(root, name):
    path = root / relative(name)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlinked input')
    require(path.is_file() and path.stat().st_size <= LIMIT, 'missing/oversized input: ' + name)
    with path.open('rb') as handle:
        raw = handle.read(LIMIT + 1)
    require(len(raw) <= LIMIT, 'input grew beyond bound')
    return normalized(raw)


@lru_cache(maxsize=8192)
def historical(root, commit, name):
    object_name = revision(commit) + ':' + relative(name)
    require(int(git(root, 'cat-file', '-s', object_name)) <= LIMIT, 'oversized Git object')
    entry = git(root, 'ls-tree', commit, '--', name).split(b' ', 1)[0]
    require(entry in (b'100644', b'100755'), 'nonregular Git input')
    return normalized(git(root, 'show', object_name))


@lru_cache(maxsize=16)
def tree(root, commit):
    entries = {}
    for row in git(root, 'ls-tree', '-r', '-z', revision(commit)).split(b'\0'):
        if row:
            metadata, name = row.split(b'\t', 1)
            entries[name.decode()] = metadata.decode()
    return entries


def names(root, commit):
    return set(tree(root, commit))


def protected(name):
    # Include parent modules, orphan/new source, build scripts and feature/lock
    # inputs, not just the files selected by an individual native validator.
    return (name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rust-toolchain') or
            name.startswith('.cargo/') or
            name.startswith(('crates/', 'assurance/')) and
            name.endswith(('.rs', '/Cargo.toml', '/Cargo.lock')))


def clean(root):
    require(not git(root, 'status', '--porcelain', '--untracked-files=all').strip(),
            'clean committed checkout required')


def committed(root, name, head):
    raw = read(root, name)
    require(raw == historical(root, head, name), 'uncommitted input: ' + name)
    return raw
