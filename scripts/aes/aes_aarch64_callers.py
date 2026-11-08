"""Twelve exact secret-output entry points; not arbitrary consumer inlining."""
import hashlib
import json
from pathlib import Path
import re

ROLES = tuple(kind + str(bits) + '_' + op for kind in ('key', 'cached')
              for bits in (128, 192, 256) for op in ('encrypt', 'decrypt'))
POLICY_PATH = Path(__file__).with_name('aarch64-callers-review.json')
LABEL = r'\.LBB[0-9]+_[0-9]+'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
MEMREG = r'(?:' + REG + r'|q0)'
ADDRESS = r'\[(?:x[0-9]+|sp)(?:, #-?[0-9]+)?\]'
OWNER = r'(9Aes(?:128|192|256)Key|17Aes(?:128|192|256)ExpandedKey)13(encrypt|decrypt)_block'
PATTERNS = (
    r'_ZN13brynja_crypto3aes(?:4wide)?' + OWNER + r'17h[0-9a-f]{16}E',
    r'_RNvM(?:s[0-9a-z]*_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + OWNER,
)


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 callers: ' + message)


def wide(role):
    require(role in ROLES, 'unreviewed role')
    return role.startswith(('cached192_', 'cached256_'))


def relevant(name):
    return '13brynja_crypto3aes' in name and any(op in name for op in ('13encrypt_block', '13decrypt_block'))


def select(definitions, aliases):
    require(not any(relevant(n) for n in aliases), 'caller aliases require review')
    result = {}
    for name in definitions:
        if not relevant(name):
            continue
        match = next((m for p in PATTERNS if (m := re.fullmatch(p, name))), None)
        require(match is not None, 'unrecognized caller symbol')
        bits = re.search(r'128|192|256', match[1])[0]
        require(('4wide' in name) == (bits != '128'), 'owner namespace mismatch')
        role = ('cached' if 'Expanded' in match[1] else 'key') + bits + '_' + match[2]
        require(role not in result, 'duplicate caller role')
        result[role] = name
    require(set(result) == set(ROLES), 'caller population changed')
    return result


def edges(role):
    return ('begin', 'guard_drop', 'secret' + role[6:9]) if wide(role) else (role.split('_')[0],)


def bindings(callees, role):
    roles = edges(role)
    require(all(r in callees and re.fullmatch(r'[_A-Za-z0-9.$]+', callees[r]) for r in roles),
            'invalid call identity')
    targets = {callees[r]: r for r in roles}
    require(len(targets) == len(roles), 'ambiguous call identity')
    return targets


def forwarding(role, target):
    # All eight streams are identical across compiler/panic profiles except for
    # the public direction constant and exact selected transform destination.
    return ['mov x4, x2', 'mov x3, x1',
            'mov w5, ' + ('#1' if role.endswith('_decrypt') else 'wzr'),
            'ldp x1, x2, [x0]', 'mov x0, x8', 'b ' + target]


def observe(lines, callees, role):
    require(wide(role), 'not a wide caller')
    targets = bindings(callees, role)
    labels, code = {}, []
    for line in lines:
        if line.endswith(':'):
            name = line[:-1]
            require(re.fullmatch(LABEL, name), 'unreviewed label')
            require(name not in labels, 'duplicate label')
            labels[name] = len(code)
        else:
            code.append(line)
    require(code and code[-1] == 'ret' and code.count('ret') == 3, 'unexpected terminal instructions')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction branch label')
    normalized, branches, calls = [], 0, {}
    for line in code:
        branch = (re.fullmatch(r'(b\.(?:eq|ne)) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbn?z (?:w8|x21)), (' + LABEL + ')', line))
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
            r'ret', r'mov ' + REG + ', (?:' + REG + r'|sp|#[0-9]+)',
            r'(?:add|sub) (?:' + REG + r'|sp), (?:' + REG + r'|sp), #[0-9]+',
            r'cmp ' + REG + r', #[0-9]+',
            r'(?:ldr|ldur|str|stur|ldurb) ' + MEMREG + ', ' + ADDRESS,
            r'(?:ldp|stp) ' + MEMREG + ', ' + MEMREG + ', ' + ADDRESS,
        )
        require(any(re.fullmatch(p, line) for p in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    return dict(instructions=len(code), branches=branches, calls=calls,
                sha256=hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest())


def check(lines, callees, role, compiler, panic):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind'), 'unreviewed configuration')
    bindings(callees, role)
    if not wide(role):
        target = edges(role)[0]
        require(lines == forwarding(role, callees[target]), 'forwarding stream changed; explicit re-review required')
        return dict(role=role, instructions=6, tail_call=target, inverse=role.endswith('_decrypt'))
    actual = observe(lines, callees, role)
    require(actual == json.loads(POLICY_PATH.read_text())[compiler + '/' + panic][role],
            'instruction stream changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, callees, role, compiler, panic):
    check(lines, callees, role, compiler, panic)
    if not wide(role):
        replacements = ['mov x4, x1', 'mov x3, x2',
                        'mov w5, ' + ('wzr' if role.endswith('_decrypt') else '#1'),
                        'ldp x2, x1, [x0]', 'mov x0, x9', 'b wrong_owner']
        cases = []
        for i, replacement in enumerate(replacements):
            cases.append((lines[:i] + lines[i + 1:], 'forwarding stream changed'))
            changed = lines.copy()
            changed[i] = replacement
            cases.append((changed, 'forwarding stream changed'))
    else:
        cases = [([line] + lines, 'unreviewed') for line in (
            'blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
            '.inst 0', 'mov sp, x0', 'bl wrong_guard')]
        reason = 'instruction stream changed'
        cases.append((['mov w8, #1'] + lines, reason))
        branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
        other = next(line[:-1] for line in lines if re.fullmatch(LABEL + ':', line)
                     and not lines[branch].endswith(line[:-1]))
        for target, why in (('.LBB999999_999999', 'unknown branch target'), (other, reason)):
            changed = lines.copy()
            changed[branch] = re.sub(LABEL + '$', target, changed[branch])
            cases.append((changed, why))
        for target in edges(role):
            index = lines.index('bl ' + callees[target])
            cases.append((lines[:index] + lines[index + 1:], reason))
        size = '208' if '192' in role else '240'
        direction = '#1' if role.endswith('_decrypt') else 'wzr'
        for old, new in (
            ('mov w4, ' + direction, 'mov w4, ' + ('wzr' if direction == '#1' else '#1')),
            ('mov w1, #16', 'mov w1, #0'), ('cmp x22, #' + size, 'cmp x22, #0'),
            ('str x8, [sp, #16]', 'str xzr, [sp, #16]'),
            ('str x8, [x20]', 'str xzr, [x20]'),
            ('mov x2, x19', 'mov x2, x20'), ('mov x0, x2', 'mov x0, x1')):
            changed = lines.copy()
            changed[lines.index(old)] = new
            cases.append((changed, reason))
    require(len(cases) == (20 if wide(role) else 12), 'mutation population changed')
    for changed, why in cases:
        try:
            check(changed, callees, role, compiler, panic)
        except ValueError as error:
            require(why in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 caller mutation accepted')
    return len(cases)
