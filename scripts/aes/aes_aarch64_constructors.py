"""Pinned AArch64 AES constructors; no final-link or runtime unwind claim."""
import hashlib
import json
from pathlib import Path
import re

ROLES = tuple(kind + str(bits) for kind in ('key', 'cached') for bits in (128, 192, 256))
POLICY_PATH = Path(__file__).with_name('aarch64-constructors-review.json')
LABEL = r'\.LBB[0-9]+_[0-9]+'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
MEMREG = r'(?:' + REG + r'|q[01])'
ADDRESS = r'\[(?:x[0-9]+|sp)(?:, #-?[0-9]+)?\]'
OWNER = r'(9Aes(?:128|192|256)Key|17Aes(?:128|192|256)ExpandedKey)3new'
PATTERNS = (
    r'_ZN13brynja_crypto3aes(?:4wide)?' + OWNER + r'17h[0-9a-f]{16}E',
    r'_RNvM(?:s[0-9a-z]*_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + OWNER,
)


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 constructors: ' + message)


def relevant(name):
    return '13brynja_crypto3aes' in name and 'Key3new' in name


def select(definitions, aliases):
    require(not any(relevant(n) for n in aliases), 'constructor aliases require review')
    result = {}
    for name in definitions:
        if not relevant(name):
            continue
        match = next((m for p in PATTERNS if (m := re.fullmatch(p, name))), None)
        require(match is not None, 'unrecognized constructor symbol')
        bits = re.search(r'128|192|256', match[1])[0]
        require(('4wide' in name) == (bits != '128'), 'owner namespace mismatch')
        role = ('cached' if 'Expanded' in match[1] else 'key') + bits
        require(role not in result, 'duplicate constructor role')
        result[role] = name
    require(set(result) == set(ROLES), 'constructor population changed')
    return result


def edges(role, panic):
    require(role in ROLES and panic in ('abort', 'unwind'), 'unreviewed configuration')
    suffix = '' if role.endswith('128') else role[-3:]
    return ('begin', 'write', 'finish', 'guard_drop') + (
        ('expand' + suffix, 'clear') if role.startswith('cached') else ()) + (
        ('resume', 'panic_cleanup') if panic == 'unwind' else ())


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
    require(code and 'ret' in code and code[-1] == (
        'ret' if panic == 'abort' else 'bl ' + callees['panic_cleanup']), 'unexpected terminal instruction')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction branch label')
    require(all(n < len(code) for _, n in metadata), 'dangling metadata label')
    normalized, branches, calls = [], 0, {}
    for line in code:
        branch = (re.fullmatch(r'(b(?:\.(?:eq|ne))?) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbn?z w(?:8|20)|tbn?z w(?:0|20|21), #0), (' + LABEL + ')', line))
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
            r'ret', r'movi v1.2d, #0000000000000000',
            r'mov ' + REG + ', (?:' + REG + r'|sp|#[0-9]+)',
            r'(?:add|sub) (?:' + REG + r'|sp), (?:' + REG + r'|sp), #[0-9]+',
            r'cmp ' + REG + r', #[0-9]+',
            r'and w8, w0, #0xff', r'bics wzr, w8, w0',
            r'(?:ldr|ldur|str|stur|ldrb|ldurb) ' + MEMREG + ', ' + ADDRESS,
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
        '.inst 0', 'mov sp, x0', 'bl wrong_guard')]
    reason = 'instruction stream changed'
    cases.append((lines[:start] + ['mov w8, #1'] + lines[start:], reason))
    branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
    other = next(line[:-1] for line in lines if re.fullmatch(LABEL + ':', line)
                 and not lines[branch].endswith(line[:-1]))
    for target, why in (('.LBB999999_999999', 'unknown branch target'), (other, reason)):
        changed = lines.copy()
        changed[branch] = re.sub(LABEL + '$', target, changed[branch])
        cases.append((changed, why))
    indices = {r: lines.index('bl ' + callees[r]) for r in ('begin', 'write', 'finish', 'guard_drop')}
    for index in indices.values():
        cases.append((lines[:index] + lines[index + 1:], reason))
    for call, register in (('begin', 'w1'), ('write', 'w2')):
        index = max(i for i in range(indices[call]) if re.fullmatch('mov ' + register + r', #[0-9]+', lines[i]))
        changed = lines.copy()
        changed[index] = 'mov ' + register + ', #0'
        cases.append((changed, reason))
    for old, new in (('stp x9, x8, [x19, #8]', 'stp x8, x9, [x19, #8]'),
                     ('str x8, [x19]', 'str xzr, [x19]'),
                     ('str xzr, [x19]', 'str x8, [x19]')):
        changed = lines.copy()
        changed[lines.index(old)] = new
        cases.append((changed, reason))
    changed = lines.copy()
    returned = changed.pop(lines.index('stp x9, x8, [x19, #8]'))
    changed.insert(indices['finish'], returned)
    cases.append((changed, reason))
    if role.startswith('cached'):
        expand = lines.index('bl ' + callees['expand' + ('' if role.endswith('128') else role[-3:])])
        clear = lines.index('bl ' + callees['clear'])
        for index in (expand, clear):
            cases.append((lines[:index] + lines[index + 1:], reason))
            extent = max(i for i in range(index) if re.fullmatch(r'mov w1, #[0-9]+', lines[i]))
            changed = lines.copy()
            changed[extent] = 'mov w1, #0'
            cases.append((changed, reason))
        cases.append((lines[:clear] + ['mov x0, x3'] + lines[clear:], reason))
    else:
        changed = lines.copy()
        changed[lines.index('mov x1, x20')] = 'mov x1, x19'
        cases.append((changed, reason))
        changed = lines.copy()
        instruction = changed.pop(indices['write'])
        changed.insert(indices['begin'], instruction)
        cases.append((changed, reason))
        cases.append((lines[:indices['finish']] + ['mov x0, x3'] + lines[indices['finish']:], reason))
        changed = lines.copy()
        changed[branch] = re.sub(r'^(cbz|b.ne)', lambda m: 'cbnz' if m[0] == 'cbz' else 'b.eq', changed[branch])
        require(changed != lines, 'missing admission branch mutation')
        cases.append((changed, reason))
        changed = lines.copy()
        changed[lines.index('str x8, [sp, #16]')] = 'str xzr, [sp, #16]'
        cases.append((changed, reason))
    require(len(cases) == 25, 'mutation population changed')
    for changed, why in cases:
        try:
            check(changed, callees, role, compiler, panic)
        except ValueError as error:
            require(why in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 constructor mutation accepted')
    return len(cases)
