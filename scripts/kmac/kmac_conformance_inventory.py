"""Fail-closed inventory for the reviewed KMAC owner-macro grammar.

This is not a general Rust parser. New declaration/macro shapes require review;
compiled positive/negative controls remain the authority on method resolution.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cryptography'))
from rust_source_contract import scrub, closing_brace

FAMILIES = {
    '': 'brynja_mac_kmac',
    'execution/': 'brynja_mac_kmac::execution',
    'hardened_in_place/': 'brynja_mac_kmac::hardened_in_place',
    'hardened_in_place/accelerated/': 'scoped_execution',
}


def inventory(read):
    result = set()
    for directory, prefix in FAMILIES.items():
        for leaf in ('fixed.rs', 'xof.rs'):
            name = directory + leaf
            code = scrub(read(name))
            macros = []
            for match in re.finditer(r'macro_rules!\s+(\w+)\s*\{\s*\(([^)]*)\)', code):
                start = code.index('{', match.start())
                params = re.findall(r'\$(\w+)\s*:', match[2])
                macros.append((match[1], params, start, closing_brace(code, start)))
            owners = []
            for match in re.finditer(r'\bimpl(?:\s*<[^{}]*?>)?\s+\$(\w+)[^{]*\{', code):
                start = match.end() - 1
                owners.append((match[1], start, closing_brace(code, start)))
            gates = []
            for match in re.finditer(r'\bconformance_api!\s*\{\s*\$profile\s*;', code):
                start = code.index('{', match.start())
                gates.append((start, closing_brace(code, start)))
            # Scan definitions regardless of visibility/qualifiers so a new
            # spelling cannot silently evade the inventory. Private additions
            # also require explicit review instead of being silently skipped.
            for method in re.finditer(r'\bfn\s+(?:r#)?(\w+_conformance)\b', code):
                position = method.start()
                macro = [m for m in macros if m[2] < position < m[3]]
                owner = [o for o in owners if o[1] < position < o[2]]
                if len(macro) != 1 or len(owner) != 1 or not any(a < position < b for a, b in gates):
                    raise ValueError('unclassified or ungated conformance method: ' + name + ':' + method[1])
                macro_name, params, _, _ = macro[0]
                if owner[0][0] not in params or 'profile' not in params:
                    raise ValueError('conformance owner macro shape changed: ' + name)
                count = 0
                for call in re.finditer(r'\b' + re.escape(macro_name) + r'!\s*\(([^()]*)\)', code):
                    args = [arg.strip() for arg in call[1].split(',')]
                    if len(args) == len(params) + 1 and args[-1] == '':
                        args.pop()
                    if len(args) != len(params):
                        raise ValueError('conformance macro arguments changed: ' + name)
                    if args[params.index('profile')] != 'production':
                        continue
                    identity = args[params.index(owner[0][0])]
                    if re.fullmatch(r'Kmac\w+', identity) is None:
                        raise ValueError('unclassified conformance owner: ' + identity)
                    probe = f'let _ = {prefix}::{identity}::{method[1]};'
                    if probe in result:
                        raise ValueError('duplicate conformance method: ' + probe)
                    result.add(probe)
                    count += 1
                if count == 0:
                    raise ValueError('conformance macro has no production owner: ' + name)
    return result


def validate(root, probes):
    source = root / 'crates/brynja-mac-kmac/src'
    expected = inventory(lambda name: (source / name).read_text())
    if expected != set(probes) or len(probes) != len(set(probes)):
        raise ValueError('conformance source/probe inventory differs: missing=' +
                         repr(sorted(expected - set(probes))) + '; extra=' +
                         repr(sorted(set(probes) - expected)))
