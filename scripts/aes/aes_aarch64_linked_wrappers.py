"""Pinned final-linked ARM secret wrappers; not all inlined callers/unwind dispatch."""
import importlib.util
import json
from pathlib import Path
import re


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


image_review = module('arm_wrapper_image', 'aes_aarch64_linked.py')
# Only the architecture-neutral exact symbol-name/population parser is reused.
names = module('arm_wrapper_names', 'aes_linked_wrappers.py')
require = image_review.require
EDGES = {
    'key128': ('zeroize', 'expand128', 'transform128', 'copy'),
    'cached128': ('zeroize', 'transform128', 'copy'),
    'key192': ('zeroize', 'expand192', 'secret192'),
    'key256': ('zeroize', 'expand256', 'secret256'),
    'secret192': ('zeroize', 'transform192', 'copy'),
    'secret256': ('zeroize', 'transform256', 'copy'),
    'copy': (),
}
POLICY = Path(__file__).with_name('aarch64-linked-wrappers-review.json')


def secret_role(lines, symbol, portable):
    matches = [bits for bits in (192, 256) if f'transform{bits}' in portable and sum(
        line == f'bl 0x{portable[f"transform{bits}"][1]:x} <{portable[f"transform{bits}"][0]}>'
        for line in lines) == 1]
    require(len(matches) == 1, 'ambiguous wide secret transform binding')
    bits = matches[0]
    if symbol.startswith('_RI'):
        require(('Kj18_Kjd0_Kjc_' if bits == 192 else 'Kj20_Kjf0_Kje_') in symbol,
                'wide secret generic width mismatch')
    return f'secret{bits}'


def select(table, assembly, portable):
    selected, secrets = names.candidates(table)
    for row in secrets:
        role = secret_role(image_review.decode(assembly, row)[0], row[0], portable)
        require(role not in selected, 'duplicate wide secret role')
        selected[role] = row
    require(set(selected) == set(EDGES), 'wrapper population mismatch')
    ordered = sorted([*selected.values(), *portable.values()], key=lambda row: row[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])),
            'overlapping wrapper/helper bodies')
    return selected


def check(lines, raw, row, image, targets, role, compiler, panic, policy=None):
    policy = json.loads(POLICY.read_text()) if policy is None else policy
    require(set(policy) == {'schema', 'target', 'profile', 'review', 'bodies', 'configurations'}
            and policy['schema'] == 1 and policy['target'] == 'aarch64-unknown-linux-gnu'
            and policy['profile'] == 'opt3-fat-lto-cgu1-overflow'
            and policy['review'] == 'docs/assurance/aes-aarch64-linked-review.md', 'wrapper review scope changed')
    configs = {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')}
    require(set(policy['configurations']) == configs
            and all(set(rows) == set(EDGES) for rows in policy['configurations'].values()), 'wrapper configuration population changed')
    used = {label for rows in policy['configurations'].values() for label in rows.values()}
    require(used == set(policy['bodies']), 'unused/missing wrapper policy')
    require(compiler + '/' + panic in configs and role in EDGES
            and set(targets) == set(EDGES[role]), 'unreviewed wrapper/targets')
    if role.startswith('secret'):
        require(secret_role(lines, row[0], targets) == role, 'wide wrapper role mismatch')
    actual, _, _ = image_review.observe(lines, raw, row, image, targets)
    expected = policy['bodies'][policy['configurations'][compiler + '/' + panic][role]]
    require(actual == expected, 'wrapper instruction/encoding/constant policy changed; explicit re-review required')
    return {'role': role, **actual}


def mutation_cases(lines, raw, row, image, targets, role):
    pos = image_review.mapped(image_review.segments(image), row[1], row[2], 5)
    changed_raw = bytes([raw[0] ^ 1]) + raw[1:]
    changed_image = image[:pos] + changed_raw + image[pos + len(raw):]
    text = list(lines); text[0] = 'nop'
    cases = [(lines[:-1], raw, image, targets), (text, raw, image, targets),
             (lines, changed_raw, image, targets), (lines, raw, changed_image, targets),
             (lines, changed_raw, changed_image, targets)]
    branch = next(i for i, line in enumerate(lines) if re.match(r'(?:b\.|cbn?z |tbn?z |b )', line))
    changed = list(lines); changed[branch] = re.sub(r'0x[0-9a-f]+', '0x0', lines[branch], count=1)
    cases.append((changed, raw, image, targets))
    for key, (name, address, size) in targets.items():
        changed = dict(targets); changed[key] = (name, address + 4, size)
        cases.append((lines, raw, image, changed))
    # Every call site, each immediate clear length and every explicit successful
    # owner tag/metadata store. The full policies also bind argument setup.
    for i, line in enumerate(lines):
        change = (line.startswith('bl ') or re.fullmatch(r'mov w1, #(16|176|208|240)', line)
                  or re.fullmatch(r'str xzr, \[x(?:20|21)\]', line)
                  or re.fullmatch(r'stp x(?:19|20), x(?:21|22|23), \[x(?:20|21), #8\]', line))
        if role == 'copy':
            change = line.startswith(('ldr', 'str', 'add x5,', 'sub x6,', 'mov x4,', 'mov x5,', 'mov x6,'))
        if change:
            changed = list(lines); changed[i] = 'nop'
            cases.append((changed, raw, image, targets))
    _, constants, _ = image_review.observe(lines, raw, row, image, targets)
    for pos, _ in constants:
        changed = image[:pos] + bytes([image[pos] ^ 1]) + image[pos + 1:]
        cases.append((lines, raw, changed, targets))
    return cases


def mutations(lines, raw, row, image, targets, role, compiler, panic):
    check(lines, raw, row, image, targets, role, compiler, panic)
    cases = mutation_cases(lines, raw, row, image, targets, role)
    for changed_lines, changed_raw, changed_image, changed_targets in cases:
        try:
            check(changed_lines, changed_raw, row, changed_image, changed_targets, role, compiler, panic)
        except ValueError:
            pass
        else:
            raise ValueError('AES ARM linked wrapper mutation accepted: ' + role)
    return len(cases)
