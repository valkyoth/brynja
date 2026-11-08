"""Pinned compile-only expansion/transform streams, not a spill-erasure claim.

Operand admission is only a parser boundary. Exact reviewed instruction hashes,
including branch destinations and bound callees, are mandatory for acceptance.
See docs/assurance/aes-aarch64-review.md; policies are never refreshed by a run.
"""
import hashlib
import json
from pathlib import Path
import re

ROLES = ('expand', 'expand192', 'expand256', 'transform', 'transform192', 'transform256')
LABEL = r'\.LBB[0-9]+_[0-9]+'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
WORD = r'w(?:[0-9]|[12][0-9]|30|zr)'
XREG = r'x(?:[0-9]|[12][0-9]|30)'
IMM = r'#-?(?:[0-9]+|0x[0-9a-f]+)'
ADDRESS = r'\[(?:' + XREG + r'|sp)(?:, ' + IMM + r')?\]'


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 rounds: ' + message)


def bind(selected, llvm, clear_pattern):
    # Exactly one external declaration, not any symbol containing "clear".
    declarations = re.findall(r'^declare [^\n@]*@(' + clear_pattern + r')\(', llvm, re.M)
    require(len(declarations) == 1, 'missing/ambiguous external clearing declaration')
    callees = {role: selected[role][0] for role in ('inverse', 'substitute', 'mix', 'add_key', 'wide_add_key')}
    callees['clear'] = declarations[0]
    require(len(set(callees.values())) == len(callees), 'ambiguous call identity')
    return callees


def observe(lines, callees, role):
    require(role in ROLES, 'unreviewed role')
    roles = ('inverse', 'clear') if role.startswith('expand') else (
        'substitute', 'mix', 'add_key' if role == 'transform' else 'wide_add_key', 'clear')
    require(all(r in callees and re.fullmatch(r'[_A-Za-z0-9]+', callees[r]) for r in roles),
            'invalid call identity')
    targets = {callees[r]: r for r in roles}
    require(len(targets) == len(roles), 'ambiguous call identity')
    labels, code = {}, []
    for line in lines:
        if line.endswith(':'):
            name = line[:-1]
            require(re.fullmatch(LABEL, name) and name not in labels, 'invalid/duplicate local label')
            labels[name] = len(code)
        else:
            code.append(line)
    require(code and code[-1] == 'ret', 'missing terminal return')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction local label')
    normalized, branches, calls, clears = [], 0, 0, 0
    for line in code:
        branch = (re.fullmatch(r'(b(?:\.(?:hs|ls|hi|ne|eq))?) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbz w0|cbnz x9|tbz w2, #0|tbnz w0, #0), (' + LABEL + ')', line))
        if branch:
            require(branch[2] in labels, 'unknown branch target')
            normalized.append(branch[1] + ' @+' + str(labels[branch[2]]))
            branches += 1
            continue
        if line.startswith('bl '):
            require(line[3:] in targets, 'unreviewed call target')
            target = targets[line[3:]]
            normalized.append('bl @' + target)
            calls += 1
            clears += target == 'clear'
            continue
        allowed = (
            r'ret', r'cset w0, ne',
            r'(?:and|eor|orr) ' + WORD + ', ' + WORD + ', ' + WORD + r'(?:, (?:lsl|lsr) #[1-7])?',
            r'ands x8, x(?:8|28), #0x1c', r'tst x(?:9|27), #0xc',
            r'ubfx ' + WORD + ', ' + WORD + r', #(?:7, #1|6, #2|5, #3|4, #4)',
            r'sxtb ' + WORD + ', ' + WORD, r'lsr x8, x8, #4',
            r'umulh x8, x(?:22|28), x13', r'msub x9, x8, x12, x24', r'madd x9, x8, x12, x26',
            r'movk x13, #43691',
            r'mov ' + REG + ', (?:' + REG + '|' + IMM + r'|sp)',
            r'(?:add|sub) ' + REG + ', (?:' + REG + '|sp), ' + IMM,
            r'(?:add|sub) sp, sp, #(?:64|112)', r'adds x25, x25, #1',
            r'cmp ' + XREG + ', ' + IMM,
            r'(?:ldrb|ldurb|ldurh|strb|sturb|sturh) ' + WORD + ', ' + ADDRESS,
            r'strb w[89], \[x(?:22|23|24|25)\], #4',
            r'(?:ldr|str) (?:q0|' + REG + '), ' + ADDRESS,
            r'(?:ldp|stp) q0, q1, \[x[02]\]',
            r'(?:ldp|stp) x(?:29, x30|28, x27|26, x25|24, x23|22, x21|20, x19), \[sp, #(?:16|32|48|64|80|96)\]',
        )
        require(any(re.fullmatch(pattern, line) for pattern in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    return dict(instructions=len(code), branches=branches, calls=calls, clears=clears,
                sha256=hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest())


POLICY_PATH = Path(__file__).with_name('aarch64-rounds-review.json')


def check(lines, callees, role, compiler, panic):
    policies = json.loads(POLICY_PATH.read_text())
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind') and role in ROLES,
            'unreviewed configuration')
    actual = observe(lines, callees, role)
    require(actual == policies[compiler + '/' + panic][role],
            'instruction stream changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, callees, role, compiler, panic):
    check(lines, callees, role, compiler, panic)
    cases = [([line] + lines, 'unreviewed') for line in (
        'blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
        '.inst 0', 'mov sp, x0', 'bl wrong_clear')]
    cases.append((['eor w0, w0, w1'] + lines, 'instruction stream changed'))
    load = next(i for i, line in enumerate(lines) if line.startswith(('ldrb ', 'ldurb ')))
    changed = lines.copy()
    changed[load] = re.sub(r'\[x[0-9]+', '[x3', changed[load])
    cases.append((changed, 'instruction stream changed'))
    store = next(i for i, line in enumerate(lines) if line.startswith(('strb ', 'sturb ')))
    cases.append((lines[:store] + lines[store + 1:], 'instruction stream changed'))
    branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
    changed = lines.copy()
    changed[branch] = re.sub(LABEL + '$', '.LBB999999_999999', changed[branch])
    cases.append((changed, 'unknown branch target'))
    clear = lines.index('bl ' + callees['clear'])
    cases.append((lines[:clear] + lines[clear + 1:], 'instruction stream changed'))
    extent = max(i for i in range(clear) if lines[i] in ('mov w1, #4', 'mov w1, #16'))
    changed = lines.copy()
    changed[extent] = 'mov w1, #0'
    cases.append((changed, 'instruction stream changed'))
    pointer = max(i for i in range(clear) if lines[i] in ('mov x0, sp', 'sub x0, x29, #4'))
    changed = lines.copy()
    changed[pointer] = 'mov x0, x3'
    cases.append((changed, 'instruction stream changed'))
    bound = next(i for i, line in enumerate(lines) if line.startswith('cmp '))
    changed = lines.copy()
    changed[bound] = re.sub(r'#[0-9]+$', '#0', changed[bound])
    cases.append((changed, 'instruction stream changed'))
    other = next(line[:-1] for line in lines if line.endswith(':') and not lines[branch].endswith(line[:-1]))
    changed = lines.copy()
    changed[branch] = re.sub(LABEL + '$', other, changed[branch])
    cases.append((changed, 'instruction stream changed'))
    require(len(cases) == 16, 'mutation population changed')
    for changed, reason in cases:
        try:
            check(changed, callees, role, compiler, panic)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 round mutation accepted')
    return len(cases)
