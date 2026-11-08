"""Seven matched core dependency bodies; compile-only, not whole-program erasure."""
import hashlib
import json
from pathlib import Path
import re

ROLES = ('begin', 'write', 'finish', 'clear', 'guard_drop', 'copy', 'zeroize')
EDGES = {'begin': ('zeroize',), 'write': ('copy',), 'finish': ('zeroize',),
         'clear': ('zeroize',), 'guard_drop': ('zeroize',), 'copy': (), 'zeroize': ()}
LABEL = r'\.L(?:BB[0-9]+_[0-9]+|tmp[0-9]+)'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
ADDR = r'\[(?:x[0-9]+|sp)(?:, #-?[0-9]+)?\]'
POLICY_PATH = Path(__file__).with_name('aarch64-core-review.json')


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 core: ' + message)


def select(llvm, definitions, aliases, wrapper_callees):
    require(re.findall(r'^target triple = "([^"]+)"$', llvm, re.M) == ['aarch64-unknown-linux-gnu'], 'wrong target')
    selected = {role: wrapper_callees[role] for role in ROLES[:5]}
    for role, module, function in (('copy', '22secret_memory_transfer', '10copy_bytes'),
                                    ('zeroize', '22secret_memory_volatile', '23zeroize_region_volatile')):
        pattern = r'(?:_ZN11brynja_core' + module + function + r'17h[0-9a-f]+E|_RNvNtC\w+_11brynja_core' + module + function + ')'
        matches = [name for name in definitions if re.fullmatch(pattern, name)]
        require(len(matches) == 1, 'missing/ambiguous helper: ' + role)
        selected[role] = matches[0]
    require(len(set(selected.values())) == len(selected), 'ambiguous core identity')
    for role, name in selected.items():
        require(name in definitions and name not in aliases, 'missing/aliased matched core body: ' + role)
    return selected


def observe(lines, selected, role):
    require(role in ROLES, 'unreviewed role')
    require(all(r in selected and re.fullmatch(r'[_A-Za-z0-9.$]+', selected[r]) for r in EDGES[role]), 'invalid callee identity')
    targets = {selected[r]: r for r in EDGES[role]}
    labels, code = {}, []
    for line in lines:
        if line.endswith(':'):
            name = line[:-1]
            require(re.fullmatch(LABEL, name) and name not in labels, 'invalid/duplicate label')
            labels[name] = len(code)
        else:
            code.append(line)
    require(code and code[-1] in ('ret', 'b ' + selected.get('zeroize', '')), 'unexpected terminal instruction')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction label')
    normalized, branches, calls = [], 0, {}
    for line in code:
        branch = (re.fullmatch(r'(b\.(?:eq|ne|hs|lo|ls)) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbz x(?:0|1|6|8)|cbnz x6), (' + LABEL + ')', line))
        if branch:
            require(branch[2] in labels, 'unknown branch target')
            normalized.append(branch[1] + ' @+' + str(labels[branch[2]]))
            branches += 1
            continue
        if line.startswith(('bl ', 'b ')):
            opcode, target = line.split(' ', 1)
            require(target in targets, 'unreviewed call target')
            key = opcode + ' @' + targets[target]
            calls[key] = calls.get(key, 0) + 1
            normalized.append(key)
            continue
        allowed = (
            r'ret', r'mov ' + REG + ', (?:' + REG + r'|sp|#[0-9]+)',
            r'(?:add|adds) ' + REG + ', ' + REG + ', ' + REG,
            r'(?:cmn|cmp) ' + REG + ', ' + REG,
            r'cmp ' + REG + r', #[0-9]+',
            r'(?:add|sub|subs) ' + REG + ', ' + REG + r', #[0-9]+',
            r'(?:ldr|str|ldrb|strb|strh) ' + REG + ', ' + ADDR,
            r'(?:ldp|stp) ' + REG + ', ' + REG + ', ' + ADDR,
            r'stp x29, x30, \[sp, #-(?:16|32|48)\]!',
            r'ldp x29, x30, \[sp\], #(?:16|32|48)',
            r'(?:ldr|str) x4, \[x[01], x5\]', r'(?:ldrb|strb) (?:w4|wzr), \[x[01], x5\]',
            r'strb (?:wzr|w8), \[x0\], #1',
        )
        require(any(re.fullmatch(p, line) for p in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    return dict(instructions=len(code), branches=branches, calls=calls,
                sha256=hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest())


def llvm_digest(body):
    # Preserve all executable text/SSA names, but not whitespace or predecessor
    # comments. No volatile/fence instruction can be silently dropped.
    lines = [' '.join(line.split(';', 1)[0].split()) for line in body.splitlines()]
    return hashlib.sha256(('\n'.join(line for line in lines if line) + '\n').encode()).hexdigest()


def check_llvm(body, compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unreviewed compiler')
    require(llvm_digest(body) == json.loads(POLICY_PATH.read_text())['zeroize_llvm'][compiler],
            'zeroizer LLVM changed; explicit re-review required')
    return llvm_digest(body)


def check(lines, selected, role, compiler, panic):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind'), 'unreviewed configuration')
    actual = observe(lines, selected, role)
    require(actual == json.loads(POLICY_PATH.read_text())['assembly'][compiler + '/' + panic][role],
            'instruction stream changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, selected, role, compiler, panic):
    check(lines, selected, role, compiler, panic)
    cases = [([line] + lines, 'unreviewed') for line in (
        'blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
        '.inst 0', 'mov sp, x0', 'bl wrong_zeroize')]
    changed_reason = 'instruction stream changed'
    cases.append((['mov w8, #1'] + lines, changed_reason))
    branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
    changed = lines.copy()
    changed[branch] = re.sub(LABEL + '$', '.LBB999999_999999', changed[branch])
    cases.append((changed, 'unknown branch target'))
    # Drop has only one label, so use a new valid local destination at entry.
    changed = ['.LBB999999_999999:'] + lines.copy()
    changed[branch + 1] = re.sub(LABEL + '$', '.LBB999999_999999', changed[branch + 1])
    cases.append((changed, changed_reason))
    replacements = {
        'begin': [('bl ' + selected['zeroize'], 'mov w8, #1'), ('str xzr, [x19, #24]', 'str x20, [x19, #24]'),
                  ('mov w8, #1', 'mov w8, #0'), ('mov x20, x0', 'mov x20, x1'), ('mov x21, x1', 'mov x21, x0')],
        'write': [('cmp x19, x10', 'cmp x19, x9'), ('bl ' + selected['copy'], 'mov w8, #1'),
                  ('str x19, [x20, #16]', 'str xzr, [x20, #16]'), ('add x0, x8, x9', 'add x0, x8, x2')],
        'finish': [('stp x0, x1, [x8, #8]', 'stp xzr, x1, [x8, #8]'), ('b ' + selected['zeroize'], 'ret'),
                   ('mov w9, #769', 'mov w9, #0'), ('strb wzr, [x8]', 'strb w9, [x8]')],
        'clear': [('bl ' + selected['zeroize'], 'mov w8, #1'),
                  ('mov w0, #4' if compiler == '1.90.0' else 'mov w0, #255', 'mov w0, #0'),
                  ('mov w0, wzr', 'mov w0, #1'), ('ldp x29, x30, [sp], #16', 'ldp x29, x30, [sp], #32')],
        'guard_drop': [('b ' + selected['zeroize'], 'ret'), ('ldr x0, [x0]', 'ldr x0, [x8]'),
                       ('ldr x1, [x8, #8]', 'ldr x1, [x8, #16]'), ('mov x8, x0', 'mov x8, x1')],
        'copy': [('mov x4, xzr', 'mov x4, x0'), ('mov x5, xzr', 'mov x5, x0'), ('mov x6, xzr', 'mov x6, x0'),
                 ('strb w4, [x0, x5]', 'strb wzr, [x0, x5]'), ('add x5, x5, #8', 'add x5, x5, #16')],
        'zeroize': [('strb wzr, [x0], #1' if compiler == '1.90.0' else 'strb wzr, [x0]',
                     'strb w8, [x0], #1' if compiler == '1.90.0' else 'strb w8, [x0]'),
                    ('subs x1, x1, #1', 'subs x1, x1, #2'), ('ret', 'mov w8, #1')],
    }[role]
    for old, new in replacements:
        changed = lines.copy()
        # The final copy-register erase is distinct from its entry offset init.
        index = max(i for i, line in enumerate(lines) if line == old)
        if old == 'ret':
            changed.insert(index, new)
        else:
            changed[index] = new
        cases.append((changed, changed_reason))
    if role in ('write', 'finish', 'clear', 'guard_drop', 'zeroize'):
        changed = lines.copy()
        if role == 'write':
            i = next(i for i, line in enumerate(lines) if line.startswith('b.hs '))
            changed[i] = changed[i].replace('b.hs ', 'b.lo ')
        else:
            changed[branch] = re.sub(r'cbz x[01],', 'cbz x8,', changed[branch])
        cases.append((changed, changed_reason))
    if role == 'zeroize':
        changed = lines.copy()
        i = next(i for i, line in enumerate(lines) if line.startswith('b.ne '))
        changed[i] = changed[i].replace('b.ne ', 'b.eq ')
        cases.append((changed, changed_reason))
    require(len(cases) == 15, 'mutation population changed')
    for changed, reason in cases:
        try:
            check(changed, selected, role, compiler, panic)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 core mutation accepted')
    return len(cases)


def llvm_mutations(body, compiler):
    check_llvm(body, compiler)
    for old, new in (('store volatile i8 0', 'store i8 0'), ('fence syncscope("singlethread") seq_cst', '')):
        require(body.count(old) == 1, 'missing zeroizer mutation site')
        try:
            check_llvm(body.replace(old, new), compiler)
        except ValueError as error:
            require('zeroizer LLVM changed' in str(error), 'unrelated LLVM mutation rejection')
        else:
            raise ValueError('AES AArch64 core LLVM mutation accepted')
    return 2
