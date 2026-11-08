"""Exact six surviving secret-wrapper assembly policies, not runtime qualification.

Public ciphertext, core bodies and cached-wide callers have separate review
modules. Exception tables, final linking and spill erasure remain outside this
slice.
"""
import hashlib
import json
from pathlib import Path
import re

ROLES = ('key128', 'cached128', 'key192', 'key256', 'secret192', 'secret256')
EDGES = {
    'key128': ('begin', 'expand', 'transform', 'write', 'finish', 'clear', 'guard_drop'),
    'cached128': ('begin', 'transform', 'write', 'finish', 'clear', 'guard_drop'),
    'key192': ('begin', 'expand192', 'secret192', 'clear', 'guard_drop'),
    'key256': ('begin', 'expand256', 'secret256', 'clear', 'guard_drop'),
    'secret192': ('transform192', 'write', 'finish', 'clear', 'guard_drop'),
    'secret256': ('transform256', 'write', 'finish', 'clear', 'guard_drop'),
}
LABEL = r'\.LBB[0-9]+_[0-9]+'
REG = r'[wx](?:[0-9]|[12][0-9]|30|zr)'
MEMREG = r'(?:' + REG + r'|q[01])'
ADDRESS = r'\[(?:x[0-9]+|sp)(?:, #-?[0-9]+)?\]'
POLICY_PATH = Path(__file__).with_name('aarch64-wrappers-review.json')
OWNER = r'(17Aes128ExpandedKey|9Aes128Key|9Aes192Key|9Aes256Key)9transform'
OWNER_PATTERNS = (
    r'_ZN13brynja_crypto3aes(?:4wide)?' + OWNER + r'17h[0-9a-f]{16}E',
    r'_RNvM(?:s[0-9a-z]+_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + OWNER,
)
SECRET = (r'(?:_ZN13brynja_crypto3aes4wide6secret17h[0-9a-f]{16}E|'
          r'_RINvNtNtC\w+_13brynja_crypto3aes4wide6secret(?:Kj18_Kjd0_Kjc_|Kj20_Kjf0_Kje_)EB6_)')


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 wrappers: ' + message)


def relevant(name):
    return '13brynja_crypto3aes' in name and '8portable' not in name and any(
        x in name for x in ('9transform', '6secret'))


def select(definitions, aliases, llvm, portable, panic, clear_pattern):
    require(panic in ('abort', 'unwind'), 'unreviewed panic mode')
    require(not any(relevant(n) for n in aliases), 'wrapper aliases require review')
    wrappers = {}
    for name, (_, body) in definitions.items():
        if not relevant(name):
            continue
        match = next((m for p in OWNER_PATTERNS if (m := re.fullmatch(p, name))), None)
        if match:
            role = {'17Aes128ExpandedKey': 'cached128', '9Aes128Key': 'key128',
                    '9Aes192Key': 'key192', '9Aes256Key': 'key256'}[match[1]]
            require(('4wide' in name) == (role in ('key192', 'key256')), 'owner namespace mismatch')
        else:
            require(re.fullmatch(SECRET, name), 'unrecognized wrapper symbol')
            calls = re.findall(r'\b(?:call|invoke)\b[^\n]*@(\w+)\(', body)
            widths = [bits for bits in (192, 256) if calls.count(portable['transform' + str(bits)][0]) == 1]
            require(len(widths) == 1, 'ambiguous wide transform binding')
            bits = widths[0]
            if name.startswith('_RI'):
                require(('Kj18_Kjd0_Kjc_' if bits == 192 else 'Kj20_Kjf0_Kje_') in name,
                        'generic width mismatch')
            role = 'secret' + str(bits)
        require(role not in wrappers, 'duplicate wrapper role')
        wrappers[role] = name
    require(set(wrappers) == set(ROLES), 'wrapper population changed')
    declarations = [quoted or bare for quoted, bare in re.findall(
        r'^declare [^\n@]*@(?:"([^"\n]+)"|([^" (]+))\(', llvm, re.M)]
    patterns = {'clear': clear_pattern}
    for role in ('begin', 'write', 'finish'):
        suffix = str(len(role)) + role
        patterns[role] = (r'(?:_ZN11brynja_core13secret_memory26SecretRegionInitialization' + suffix
                          + r'17h[0-9a-f]+E|_RNvMNtC\w+_11brynja_core13secret_memoryNtB\w+_26SecretRegionInitialization' + suffix + ')')
    patterns['guard_drop'] = (
        r'(?:_ZN96_\$LT\$brynja_core\.\.secret_memory\.\.SecretRegionInitialization\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E|'
        r'_RNvXs_NtC\w+_11brynja_core13secret_memoryNtB\w+_26SecretRegionInitializationNtNtNtC\w+_4core3ops4drop4Drop4drop)')
    if panic == 'unwind':
        patterns['panic_cleanup'] = r'(?:_ZN4core9panicking16panic_in_cleanup17h[0-9a-f]+E|_RNvNtC\w+_4core9panicking16panic_in_cleanup)'
    callees = {**{r: item[0] for r, item in portable.items()}, **wrappers}
    for role, pattern in patterns.items():
        matches = [n for n in declarations if re.fullmatch(pattern, n)]
        require(len(matches) == 1, 'missing/ambiguous external declaration: ' + role)
        callees[role] = matches[0]
    if panic == 'unwind':
        # LLVM resume lowers to this ABI import, not an LLVM call declaration.
        callees['resume'] = '_Unwind_Resume'
    require(len(set(callees.values())) == len(callees), 'ambiguous call identity')
    return wrappers, callees


def observe(lines, callees, role, panic):
    require(role in ROLES and panic in ('abort', 'unwind'), 'unreviewed configuration')
    roles = EDGES[role] + (('resume', 'panic_cleanup') if panic == 'unwind' else ())
    require(all(r in callees and re.fullmatch(r'[_A-Za-z0-9.$]+', callees[r]) for r in roles), 'invalid call identity')
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
    require(code and 'ret' in code and code[-1] == ('ret' if panic == 'abort' else 'bl ' + callees['panic_cleanup']),
            'unexpected terminal instruction')
    require(len(set(labels.values())) == len(labels) and all(n < len(code) for n in labels.values()),
            'ambiguous/noninstruction branch label')
    require(all(n < len(code) for _, n in metadata), 'dangling metadata label')
    normalized, branches, calls = [], 0, {}
    for line in code:
        branch = (re.fullmatch(r'(b(?:\.(?:eq|ne))?) (' + LABEL + ')', line)
                  or re.fullmatch(r'(cbz (?:w(?:0|8|21|22)|x21)|tb[n]?z w(?:0|20|21|22), #0), (' + LABEL + ')', line))
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
            r'cmp ' + REG + r', #[0-9]+', r'ccmp x21, #0, #4, eq',
            r'csinc x0, x(?:22|23), xzr, ne', r'csel x1, xzr, x(?:22|23), eq',
            r'and w8, w0, #0xff', r'bics wzr, w8, w0',
            r'(?:ldr|ldur|str|stur|ldrb|ldurb) ' + MEMREG + ', ' + ADDRESS,
            r'(?:ldp|stp) ' + MEMREG + ', ' + MEMREG + ', ' + ADDRESS,
        )
        require(any(re.fullmatch(p, line) for p in allowed), 'unreviewed instruction: ' + line)
        normalized.append(line)
    # Positions of EH range labels are retained, but LSDA/CFI dispatch is NOT
    # qualified here. Distinct temporary labels may share a branch-label address.
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
    # Insert after the optional function-begin label, not before EH metadata.
    start = 1 if lines[0].startswith('.Lfunc_begin') else 0
    cases = [(lines[:start] + [line] + lines[start:], 'unreviewed') for line in (
        'blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
        '.inst 0', 'mov sp, x0', 'bl wrong_guard_drop')]
    changed_reason = 'instruction stream changed'
    cases.append((lines[:start] + ['mov w8, #1'] + lines[start:], changed_reason))
    clear = lines.index('bl ' + callees['clear'])
    cases.append((lines[:clear] + lines[clear + 1:], changed_reason))
    extent = max(i for i in range(clear) if re.fullmatch(r'mov w1, #[0-9]+', lines[i]))
    changed = lines.copy()
    changed[extent] = 'mov w1, #0'
    cases.append((changed, changed_reason))
    cases.append((lines[:clear] + ['mov x0, x3'] + lines[clear:], changed_reason))
    drop = lines.index('bl ' + callees['guard_drop'])
    cases.append((lines[:drop] + lines[drop + 1:], changed_reason))
    branch = next(i for i, line in enumerate(lines) if re.search(LABEL + '$', line))
    other = next(line[:-1] for line in lines if re.fullmatch(LABEL + ':', line) and not lines[branch].endswith(line[:-1]))
    changed = lines.copy()
    changed[branch] = re.sub(LABEL + '$', other, changed[branch])
    cases.append((changed, changed_reason))
    status = next(i for i, line in enumerate(lines) if re.fullmatch(r'str x8, \[x(?:19|20)\]', line))
    changed = lines.copy()
    changed[status] = lines[status].replace('x8,', 'xzr,')
    cases.append((changed, changed_reason))
    first_call = next(i for i, line in enumerate(lines) if line.startswith('bl '))
    cases.append((lines[:first_call] + lines[first_call + 1:], changed_reason))
    changed = lines.copy()
    changed[branch] = re.sub(LABEL + '$', '.LBB999999_999999', changed[branch])
    cases.append((changed, 'unknown branch target'))
    require(len(cases) == 16, 'mutation population changed')
    for changed, reason in cases:
        try:
            check(changed, callees, role, compiler, panic)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES AArch64 wrapper mutation accepted')
    return len(cases)
