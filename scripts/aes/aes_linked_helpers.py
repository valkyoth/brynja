"""Exact reviewed x86_64 round-key/volatile-clear streams, not general taint analysis.

Templates preserve all operands. Only same-symbol branch addresses are renamed
to fixed offsets after checking both the numeric destination and annotation.
Encoding hashes additionally bind the actual instruction bytes. No auto-refresh.
"""
import hashlib
import re

COMPILERS = ('1.90.0', '1.99.1')
ROLES = ('add_key', 'wide_add_key', 'zeroize')
ENCODINGS = {
    'add_key': (37, 'd57dc5f71cbc47832231d1c732244335fe9d59b902a9decd30ef0303ae17e48a'),
    'zeroize': (105, '232500bf06905944d87c6f5c5be957a15afda6a98ed10c608fdc95e4c7ea7f7c'),
    'wide_add_key_1.90.0': (372, 'cfd95e135773c54b0cd91e00b790d8d30755a6544e3e7ba0cce11280b3369d80'),
    'wide_add_key_1.99.1': (326, '8b6b342187b51000675ec1b9eceec69529f65e8b722c4b4b2ccc4ac352c1e5e6'),
}


def require(condition, message):
    if not condition:
        raise ValueError('AES linked helpers: ' + message)


def expected(role, compiler):
    require(compiler in COMPILERS and role in ROLES, 'unreviewed configuration')
    if role == 'add_key':
        return ['shlq $4, %rdx', 'cmpq $176, %rdx', 'jae @+1a',
                'movups (%rsi,%rdx), %xmm0', 'movups (%rdi), %xmm1',
                'xorps %xmm0, %xmm1', 'movups %xmm1, (%rdi)',
                'cmpq $176, %rdx', 'setae %al', 'retq']
    if role == 'wide_add_key':
        fail = '173' if compiler == '1.90.0' else '145'
        lines = ['shlq $4, %rcx', 'movb $1, %al']
        for index in range(16):
            register = '%rcx' if index in (0, 15) else '%r8'
            if index == 15:
                lines.append('orq $15, %rcx')
            elif index:
                lines += (['movq %rcx, %r8', f'orq ${index}, %r8'] if compiler == '1.90.0'
                          else [f'leaq {index}(%rcx), %r8'])
            result, byte = ('%eax', '%al') if index == 15 else ('%r8d', '%r8b')
            offset = str(index) if index else ''
            lines += [f'cmpq %rdx, {register}', f'jae @+{fail}',
                      f'movzbl (%rsi,{register}), {result}', f'xorb {byte}, {offset}(%rdi)']
        return lines + ['xorl %eax, %eax', 'retq']
    return ['testq %rsi, %rsi', 'je @+68', 'movq %rsi, %rcx', 'movq %rdi, %rax',
            'andq $7, %rcx', 'je @+2b', 'movq %rdi, %rax', 'nopw %cs:(%rax,%rax)',
            'movb $0, (%rax)', 'incq %rax', 'decq %rcx', 'jne @+20',
            'cmpq $8, %rsi', 'jb @+68', 'addq %rsi, %rdi', 'nopw %cs:(%rax,%rax)',
            'movb $0, (%rax)', *[f'movb $0, {i}(%rax)' for i in range(1, 8)],
            'addq $8, %rax', 'cmpq %rdi, %rax', 'jne @+40', 'retq']


def normalize(lines, symbol, start, size):
    normalized = []
    for line in lines:
        if line.startswith(('je ', 'jne ', 'jae ', 'jb ')):
            branch = re.fullmatch(r'(je|jne|jae|jb) 0x([0-9a-f]+) <'
                                  + re.escape(symbol) + r'\+0x([0-9a-f]+)>', line)
            require(branch is not None, 'unrecognized local branch')
            opcode, target, offset = branch.groups()
            relative = int(offset, 16)
            require(0 <= relative < size and int(target, 16) == start + relative,
                    'branch address/annotation mismatch')
            normalized.append(f'{opcode} @+{relative:x}')
        else:
            normalized.append(line)
    return normalized


def check(lines, raw, symbol, start, role, compiler):
    template = expected(role, compiler)
    require(normalize(lines, symbol, start, len(raw)) == template,
            'instruction template changed: ' + role + '; explicit re-review required')
    key = 'wide_add_key_' + compiler if role == 'wide_add_key' else role
    size, digest = ENCODINGS[key]
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
            'instruction encoding changed: ' + role + '; explicit re-review required')
    return {'role': role, 'instructions': len(lines), 'symbol_bytes': size, 'bytes_sha256': digest}


def mutations(lines, raw, symbol, start, role, compiler):
    # One memory/control substitution, one local-branch misbinding, one encoded
    # byte mutation per actual function. Each must fail for its intended reason.
    changed = list(lines)
    location = next(i for i, line in enumerate(changed) if line.startswith(('movups ', 'movzbl ', 'movb $0,')))
    changed[location] = 'movb (%rax,%rax), %al'
    branch = next(i for i, line in enumerate(lines) if line.startswith(('je ', 'jae ')))
    bad_branch = list(lines)
    bad_branch[branch] = re.sub(r'0x[0-9a-f]+', '0x0', bad_branch[branch], count=1)
    cases = [(changed, raw, 'instruction template changed'),
             (bad_branch, raw, 'branch address/annotation mismatch'),
             (lines, bytes([raw[0] ^ 1]) + raw[1:], 'instruction encoding changed')]
    for changed_lines, changed_raw, reason in cases:
        try:
            check(changed_lines, changed_raw, symbol, start, role, compiler)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES linked helper mutation accepted: ' + role)
    return len(cases)
