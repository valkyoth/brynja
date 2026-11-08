"""Six reviewed public-output boundaries; not final-linked/runtime qualification.

Fingerprints are pinned only after review. Keep call identities, branch targets,
all operands and EH label positions; never infer correctness from call counts.
"""
import hashlib
import json
from pathlib import Path
import re

ROLES = tuple(kind + str(bits) for kind in ('key', 'cached') for bits in (128, 192, 256))
POLICY_PATH = Path(__file__).with_name('aarch64-public-review.json')
LABEL = r'\.LBB[0-9]+_[0-9]+'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
MEMREG = r'(?:' + REG + r'|q0)'
ADDRESS = r'\[(?:x[0-9]+|sp)(?:, #-?[0-9]+)?\]'
OWNER = r'(9Aes(?:128|192|256)Key|17Aes(?:128|192|256)ExpandedKey)20encrypt_block_public'
PATTERNS = (
    r'_ZN13brynja_crypto3aes(?:4wide)?' + OWNER + r'17h[0-9a-f]{16}E',
    r'_RNvM(?:s[0-9a-z]*_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + OWNER,
)


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 public: ' + message)


def relevant(name):
    return '13brynja_crypto3aes' in name and '20encrypt_block_public' in name


def select(definitions, aliases):
    require(not any(relevant(n) for n in aliases), 'public aliases require review')
    result = {}
    for name in definitions:
        if not relevant(name):
            continue
        match = next((m for p in PATTERNS if (m := re.fullmatch(p, name))), None)
        require(match is not None, 'unrecognized public symbol')
        bits = re.search(r'128|192|256', match[1])[0]
        require(('4wide' in name) == (bits != '128'), 'owner namespace mismatch')
        role = ('cached' if 'Expanded' in match[1] else 'key') + bits
        require(role not in result, 'duplicate public role')
        result[role] = name
    require(set(result) == set(ROLES), 'public population changed')
    return result


def edges(role, panic):
    require(role in ROLES and panic in ('abort', 'unwind'), 'unreviewed configuration')
    suffix = '' if role.endswith('128') else role[-3:]
    return (('expand' + suffix,) if role.startswith('key') else ()) + (
        'transform' + suffix, 'clear') + (('resume', 'panic_cleanup') if panic == 'unwind' else ())


def observe(lines, callees, role, panic):
    roles = edges(role, panic)
    require(all(r in callees and re.fullmatch(r'[_A-Za-z0-9.$]+', callees[r]) for r in roles),
            'invalid call identity')
    targets = {callees[r]: r for r in roles}
    require(len(targets) == len(roles), 'ambiguous call identity')
    labels, metadata, code, seen = {}, [], [], set()
    for line in lines:
        if not line.endswith(':'):
            code.append(line)
            continue
        name = line[:-1]
        require(name not in seen, 'duplicate label')
        seen.add(name)
        if re.fullmatch(LABEL, name):
            labels[name] = len(code)
        else:
            require(panic == 'unwind' and re.fullmatch(r'\.L(?:tmp[0-9]+|func_begin[0-9]+)', name),
                    'unreviewed label')
            kind = 'begin' if 'func_begin' in name else 'eh'
            require(kind != 'begin' or (not code and not metadata), 'misplaced function-begin label')
            metadata.append((kind, len(code)))
    require(code and code.count('ret') == 1 and code[-1] == (
        'ret' if panic == 'abort' else 'bl ' + callees['panic_cleanup']), 'unexpected terminal instruction')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction branch label')
    require(all(n < len(code) for _, n in metadata), 'dangling metadata label')
    normalized, branches, calls = [], 0, {}
    for line in code:
        branch = (re.fullmatch(r'(b(?:\.ne)?) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbz x1|tbn?z w0, #0), (' + LABEL + ')', line))
        if branch:
            require(branch[2] in labels, 'unknown branch target')
            normalized.append(branch[1] + ' @+' + str(labels[branch[2]]))
            branches += 1
            continue
        if line.startswith('bl '):
            require(line[3:] in targets, 'unreviewed call target')
            target = targets[line[3:]]
            calls[target] = calls.get(target, 0) + 1
            normalized.append('bl @' + target)
            continue
        allowed = (
            r'ret', r'movi v0.2d, #0000000000000000',
            r'mov ' + REG + ', (?:' + REG + r'|sp|#[0-9]+)',
            r'(?:add|sub) (?:' + REG + r'|sp), (?:' + REG + r'|sp), #[0-9]+',
            r'cmp ' + REG + r', #[0-9]+',
            r'csel x1, xzr, x9, eq', r'csinc x0, x8, xzr, ne',
            r'(?:ldr|ldur|str|stur) ' + MEMREG + ', ' + ADDRESS,
            r'(?:ldp|stp) ' + MEMREG + ', ' + MEMREG + ', ' + ADDRESS,
        )
        require(any(re.fullmatch(p, line) for p in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    normalized += [kind + ' @+' + str(index) for kind, index in metadata]
    return dict(instructions=len(code), branches=branches, calls=calls, metadata_labels=len(metadata),
                sha256=hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest())


def check(lines, callees, role, compiler, panic):
    require(compiler in ('1.90.0', '1.99.1'), 'unreviewed compiler')
    actual = observe(lines, callees, role, panic)
    require(actual == json.loads(POLICY_PATH.read_text())[compiler + '/' + panic][role],
            'instruction stream changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, callees, role, compiler, panic):
    check(lines, callees, role, compiler, panic)
    start = 1 if lines[0].startswith('.Lfunc_begin') else 0
    cases = [(lines[:start] + [line] + lines[start:], 'unreviewed') for line in (
        'blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
        '.inst 0', 'mov sp, x0', 'bl wrong_transform')]
    reason = 'instruction stream changed'
    cases.append((lines[:start] + ['mov w8, #1'] + lines[start:], reason))
    branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
    other = next(line[:-1] for line in lines if re.fullmatch(LABEL + ':', line)
                 and not lines[branch].endswith(line[:-1]))
    for target, why in (('.LBB999999_999999', 'unknown branch target'), (other, reason)):
        changed = lines.copy()
        changed[branch] = re.sub(LABEL + '$', target, changed[branch])
        cases.append((changed, why))
    clear = lines.index('bl ' + callees['clear'])
    cases.append((lines[:clear] + lines[clear + 1:], reason))
    extent = max(i for i in range(clear) if re.fullmatch(r'mov w1, #[0-9]+', lines[i]))
    changed = lines.copy()
    changed[extent] = 'mov w1, #0'
    cases.append((changed, reason))
    cases.append((lines[:clear] + ['mov x0, x3'] + lines[clear:], reason))
    transform = lines.index('bl ' + callees['transform' + ('' if role.endswith('128') else role[-3:])])
    cases.append((lines[:transform] + lines[transform + 1:], reason))
    success = next(i for i in range(transform + 1, len(lines)) if lines[i].startswith('tbnz w0,'))
    changed = lines.copy()
    changed[success] = changed[success].replace('tbnz', 'tbz')
    cases.append((changed, reason))
    release = lines.index('str q0, [x19]')
    changed = lines.copy()
    instruction = changed.pop(release)
    changed.insert(transform, instruction)
    cases.append((changed, reason))
    changed = lines.copy()
    changed[release] = 'str q0, [x20]'
    cases.append((changed, reason))
    changed = lines.copy()
    changed[lines.index('mov w0, w20')] = 'mov w0, wzr'
    cases.append((changed, reason))
    require(len(cases) == 18, 'mutation population changed')
    for changed, why in cases:
        try:
            check(changed, callees, role, compiler, panic)
        except ValueError as error:
            require(why in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 public mutation accepted')
    return len(cases)
