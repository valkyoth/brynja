"""Reviewed ARM public-consumer boundaries and constructors in linked KAT ELFs.

Normal/error returns only, not exception dispatch or arbitrary consumer inlining.
"""
import importlib.util
import json
from pathlib import Path

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module('arm_public_image', 'aes_aarch64_linked.py')
# Symbol identities and call edges only; x86 instruction policies are not used.
names = module('arm_public_names', 'aes_linked_public.py')
EDGES = names.EDGES
POLICY = Path(__file__).with_name('aarch64-linked-public-review.json')
require = r.require


def select(table, existing):
    selected = names.candidates(table)
    ordered = sorted([*selected.values(), *existing.values()], key=lambda row: row[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])),
            'overlapping public/constructor/helper bodies')
    return selected


def check(lines, raw, row, image, targets, role, compiler, panic, policy=None):
    policy = json.loads(POLICY.read_text()) if policy is None else policy
    require(set(policy) == {'schema', 'target', 'profile', 'review', 'bodies', 'configurations'}
            and policy['schema'] == 1 and policy['target'] == 'aarch64-unknown-linux-gnu'
            and policy['profile'] == 'opt3-fat-lto-cgu1-overflow'
            and policy['review'] == 'docs/assurance/aes-aarch64-linked-review.md', 'public review scope changed')
    configs = {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')}
    require(set(policy['configurations']) == configs
            and all(set(rows) == set(EDGES) for rows in policy['configurations'].values()),
            'public configuration population changed')
    used = {label for rows in policy['configurations'].values() for label in rows.values()}
    require(used == set(policy['bodies']), 'unused/missing public policy')
    require(compiler + '/' + panic in configs and role in EDGES
            and set(targets) == set(EDGES[role]), 'unreviewed public role/targets')
    actual, _, _ = r.observe(lines, raw, row, image, targets)
    expected = policy['bodies'][policy['configurations'][compiler + '/' + panic][role]]
    require(actual == expected, 'public instruction/encoding policy changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, row, image, targets, role, compiler, panic):
    check(lines, raw, row, image, targets, role, compiler, panic)
    pos = r.mapped(r.segments(image), row[1], row[2], 5)
    cases = [(lines[:-1], raw, image, targets)]
    for key, (name, address, size) in targets.items():
        changed = dict(targets); changed[key] = (name, address + 4, size)
        cases.append((lines, raw, image, changed))
    # Delete every instruction in turn, including success branches, publication
    # stores, length/pointer setup and cleanup. Test text-only tampering and a
    # coherent NOP replacement in both decoded bytes and executable bytes.
    for i, line in enumerate(lines):
        require(line != 'nop', 'unexpected NOP in reviewed public body')
        changed = list(lines); changed[i] = 'nop'
        cases.append((changed, raw, image, targets))
        changed_raw = raw[:4*i] + bytes.fromhex('1f2003d5') + raw[4*i+4:]
        changed_image = image[:pos] + changed_raw + image[pos+len(raw):]
        cases.append((changed, changed_raw, changed_image, targets))
    for changed_lines, changed_raw, changed_image, changed_targets in cases:
        try:
            check(changed_lines, changed_raw, row, changed_image, changed_targets, role, compiler, panic)
        except ValueError:
            pass
        else:
            raise ValueError('AES ARM linked public mutation accepted: ' + role)
    return len(cases)
