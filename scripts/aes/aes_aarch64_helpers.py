"""Four bounded AArch64 library assembly streams; not final-linked or timing evidence.

Exact reviewed policies are required in addition to operand admission. Local
labels are resolved to instruction indices; the only call is the separately
reviewed inverse selected from the same compilation. No automatic refresh.
"""
import hashlib
import re

ROLES = ('add_key', 'wide_add_key', 'substitute', 'mix')
REGISTER = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
LABEL = r'\.LBB[0-9]+_[0-9]+'


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 helpers: ' + message)


def observe(lines, inverse):
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
    normalized, branches, calls = [], 0, 0
    for line in code:
        branch = (re.fullmatch(r'(b\.(?:hs|ls|ne|eq)) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbz w1|tbz w1, #0), (' + LABEL + ')', line))
        if branch:
            require(branch[2] in labels, 'unknown branch target')
            normalized.append(branch[1] + ' @+' + str(labels[branch[2]]))
            branches += 1
            continue
        if line.startswith('bl '):
            require(line == 'bl ' + inverse and re.fullmatch(r'[_A-Za-z0-9]+', inverse), 'unreviewed call target')
            normalized.append('bl @inverse')
            calls += 1
            continue
        # This grammar is deliberately only the observed scalar subset. It
        # does not classify operands as public: the exact reviewed stream does.
        allowed = (
            r'ret',
            r'(?:lsl|lsr) ' + REGISTER + ', ' + REGISTER + r', #(?:[0-9]|[12][0-9]|3[01])',
            r'(?:and|eor|orr) ' + REGISTER + ', ' + REGISTER + ', ' + REGISTER
            + r'(?:, (?:lsl|lsr) #(?:[0-9]|[12][0-9]|3[01]))?',
            r'orr x10, x8, #0x[1234678ce]', r'orr x8, x8, #0xf',
            r'(?:add|subs) x[0-9]+, x[0-9]+, (?:x[0-9]+|#[34])',
            r'cmp x[0-9]+, (?:x[0-9]+|#(?:[1-9]|1[0-5]|175|176))',
            r'cset w[0-9]+, (?:hi|hs)', r'csel x9, xzr, x9, lo',
            r'mov ' + REGISTER + ', (?:' + REGISTER + r'|#(?:5|9|10|11|13|16|27|99))',
            r'mov x29, sp', r'sxtb w[0-9]+, w[0-9]+',
            r'ubfx w[0-9]+, w0, #(?:7, #1|6, #2|5, #3|4, #4)',
            r'(?:ldrb|ldrsb|strb) w[0-9]+, \[x[0-9]+(?:, #(?:[1-9]|1[0-5])|, x(?:8|10))?\]',
            r'(?:ldursb|sturb) w[0-9]+, \[x8, #-[123]\]',
            r'strb w11, \[x8\], #4',
            r'stp x(?:29, x30|22, x21|20, x19), \[sp, #-(?:16|32)\]!',
            r'(?:stp|ldp) x20, x19, \[sp, #16\]',
            r'ldp x(?:29, x30|22, x21|20, x19), \[sp\], #(?:16|32)',
        )
        require(any(re.fullmatch(pattern, line) for pattern in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    return dict(instructions=len(code), branches=branches, calls=calls,
                sha256=hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest())


# Complete instruction streams inspected before pinning; see the review doc.
def profiles(substitute, mix, mix_count):
    return {
        'add_key': dict(instructions=73, branches=1, calls=0,
                        sha256='3b72f55284f5f83f70cc6147c4d4a4003d96d8d9468a5f56b0757e780ba40b24'),
        'wide_add_key': dict(instructions=164, branches=16, calls=0,
                             sha256='134bf3fa39a34a9096d2cc869cc1014b1f72abeebed18369ac3c355f2597a5cd'),
        'substitute': dict(instructions=474, branches=1, calls=32, sha256=substitute),
        'mix': dict(instructions=mix_count, branches=2, calls=0, sha256=mix),
    }


POLICY = {
    ('1.90.0', 'abort'): profiles('3bcc990a22e7023d5d8f6d17b0cc87028308c82d9eeebb9798c788a6e8e3d666',
                                 'c22137961effd354645338a6bd126a9df66f25edabc732304cdac1eeff5d652d', 219),
    ('1.90.0', 'unwind'): profiles('632c9282af5ac68849d08a07c064e1b365da21778fa65cfaa6eebe78b2c611af',
                                  'c22137961effd354645338a6bd126a9df66f25edabc732304cdac1eeff5d652d', 219),
    ('1.99.1', 'abort'): profiles('632c9282af5ac68849d08a07c064e1b365da21778fa65cfaa6eebe78b2c611af',
                                 '1ed6990b79ef37b85cf4231c1f2fb2b54b09c99bc7e6d6b6ecdb8b242bbae813', 228),
    ('1.99.1', 'unwind'): profiles('632c9282af5ac68849d08a07c064e1b365da21778fa65cfaa6eebe78b2c611af',
                                  '1ed6990b79ef37b85cf4231c1f2fb2b54b09c99bc7e6d6b6ecdb8b242bbae813', 228),
}


def check(lines, inverse, role, compiler, panic):
    require((compiler, panic) in POLICY and role in ROLES, 'unreviewed configuration')
    actual = observe(lines, inverse)
    require(actual == POLICY[compiler, panic][role], 'instruction stream changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, inverse, role, compiler, panic):
    check(lines, inverse, role, compiler, panic)
    cases = []
    for instruction in ('b.eq .Lmissing', 'blr x0', 'udiv w0, w0, w1',
                        'ldr w0, [x0, x1]', 'lsl w0, w0, w1', '.inst 0',
                        'mov sp, x0', 'bl wrong_inverse'):
        cases.append(([instruction] + lines, 'unreviewed'))
    # Individually admitted changes must still fail the reviewed fingerprint.
    cases.append((['eor w0, w0, w1'] + lines, 'instruction stream changed'))
    load = next(i for i, line in enumerate(lines) if line.startswith(('ldrb ', 'ldrsb ', 'ldursb ')))
    changed = list(lines)
    changed[load] = re.sub(r'\[x[0-9]+', '[x3', changed[load])
    cases.append((changed, 'instruction stream changed' if not lines[load].startswith('ldursb') else 'unreviewed'))
    store = next(i for i, line in enumerate(lines) if line.startswith(('strb ', 'sturb ')))
    changed = list(lines)
    del changed[store]
    cases.append((changed, 'instruction stream changed'))
    branch = next(i for i, line in enumerate(lines) if line.startswith(('b.', 'cbz ', 'tbz ')))
    changed = list(lines)
    changed[branch] = re.sub(LABEL + '$', '.LBB999_999', changed[branch])
    cases.append((changed, 'unknown branch target'))
    for changed, reason in cases:
        try:
            check(changed, inverse, role, compiler, panic)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 helper mutation accepted')
    return len(cases)
