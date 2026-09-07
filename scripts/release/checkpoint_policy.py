"""Explicit public checkpoints; later roadmap patches never move them implicitly."""
from functools import lru_cache
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'scripts/release/checkpoints.toml'
ROW = re.compile(r'^\| `(0\.[0-9]+\.[0-9]+|1\.0\.0(?:-rc\.[0-9]+)?)` \|', re.M)
VERSION = re.compile(r'0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')


def validate_catalog(document: dict, versions: list[str]) -> frozenset[str]:
    if set(document) != {'schema', 'checkpoints'} or type(document['schema']) is not int or document['schema'] != 1:
        raise ValueError('invalid public checkpoint schema')
    entries = document['checkpoints']
    if not isinstance(entries, dict) or len(versions) != len(set(versions)):
        raise ValueError('invalid or duplicate checkpoint/roadmap identity')
    expected = {str(int(v.split('.')[1])) for v in versions
                if VERSION.fullmatch(v) and int(v.split('.')[1]) >= 25
                and int(v.split('.')[1]) % 5 == 0}
    if set(entries) != expected:
        raise ValueError('checkpoint register must cover every fifth planned minor exactly')
    for minor, version in entries.items():
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise ValueError('checkpoint must be a stable roadmap version')
        if version.split('.')[1] != minor or version not in versions:
            raise ValueError('checkpoint must name a real row in its own minor series')
    # These published tags predate the closing-patch policy and never move.
    return frozenset({'0.15.0', '0.20.0', *entries.values()})


@lru_cache(maxsize=1)
def checkpoints() -> frozenset[str]:
    if CATALOG.is_symlink() or CATALOG.stat().st_size > 65536:
        raise ValueError('checkpoint register must be a bounded regular file')
    document = tomllib.loads(CATALOG.read_text(encoding='utf-8'))
    versions = ROW.findall((ROOT / 'docs/VERSION_PLAN.md').read_text(encoding='utf-8'))
    return validate_catalog(document, versions)


def is_checkpoint(raw: str) -> bool:
    if raw in ('1.0.0', '1.0.0-rc.1'):
        return True
    match = VERSION.fullmatch(raw)
    if match is None:
        raise ValueError(f'unsupported checkpoint version: {raw}')
    minor = int(match.group(1))
    return minor <= 10 or raw in checkpoints()
