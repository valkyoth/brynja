"""Exact retained Apple session checks, directions and width-bound calls.

Instruction templates below are constructed from the inspected sequences, not
learned from an input executable. Only bound external BL displacements vary.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_session_cleanup',
    Path(__file__).with_name('aes_apple_linked_cleanup.py'))
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)
SPEC_IMPORT = importlib.util.spec_from_file_location('apple_session_import',
    Path(__file__).with_name('aes_apple_unwind_import.py'))
imports = importlib.util.module_from_spec(SPEC_IMPORT)
SPEC_IMPORT.loader.exec_module(imports)
mapping, require = cleanup.kernels, cleanup.require


def template(compiler, panic, admission, direction, start, kernel, resume=None):
    cleanup.configuration(compiler, panic, admission)
    require(direction in ('encrypt', 'decrypt'), 'unsupported Apple session direction')
    unwind = compiler == '1.90.0' and panic == 'unwind'
    require((resume is not None) == unwind, 'wrong session runtime target population')
    words, labels, branches = [], {}, []

    def label(value):
        require(value not in labels, 'duplicate session policy label')
        labels[value] = len(words)

    def branch(opcode, target, width=19):
        branches.append((len(words), opcode, target, width))
        words.append(0)

    def call(target):
        delta = target - (start + 4 * len(words))
        require(delta % 4 == 0 and -(2**27) <= delta < 2**27, 'session call out of range')
        words.append(0x94000000 | ((delta // 4) & 0x3ffffff))

    if unwind:
        words += [0xa9be4ff4, 0xa9017bfd, 0x910043fd]  # Save x19/20 and FP/LR.
    words += [0x39402008]  # Health byte at owner+8.
    branch(0x34000008, 'not-ready')
    words += [0x7100051f]
    branch(0x54000001, 'quarantined')
    if unwind:
        words += [0xaa0003f3]  # Preserve owner for landing-pad quarantine.
    words += [0xf9400008, 0xeb08003f]  # Compare generation to permit's x1.
    branch(0x54000001, 'stale')
    words += [0x39402668 if unwind else 0x39402408]
    if compiler == '1.99.1':
        branch(0x34000008, 'architecture')
    elif unwind and admission == 'static':
        branch(0x36000008, 'architecture', 14)
    else:
        words += [0x7100051f]
        branch(0x54000001, 'architecture')
    if admission == 'hosted':
        words += [0x39402a68 if unwind else 0x39402808]
        if compiler == '1.99.1':
            branch(0x34000008, 'target')
        elif unwind:
            branch(0x36000008, 'target', 14)
        else:
            words += [0x7100051f]
            branch(0x54000001, 'target')
    if not unwind:
        words += [0xa9bf7bfd, 0x910003fd]
    words += [0xaa0203e0, 0xaa0303e1, 0x52800002 | (32 if direction == 'decrypt' else 0)]
    call(kernel)
    words += [0x528000c0 if compiler == '1.90.0' else 0x52801fe0]
    if unwind:
        branch(0x14000000, 'epilogue', 26)
    else:
        words += [0xa8c17bfd, 0xd65f03c0]
    errors = [('not-ready', 2), ('quarantined', 3), ('stale', 4), ('architecture', 0)]
    if admission == 'hosted':
        errors.append(('target', 1))
    for i, (name, value) in enumerate(errors):
        label(name)
        words += [0x52800000 | (value << 5)]
        if unwind:
            if i < len(errors) - 1:
                branch(0x14000000, 'epilogue', 26)
        else:
            words += [0xd65f03c0]
    if unwind:
        label('epilogue')
        words += [0xa9417bfd, 0xa8c24ff4, 0xd65f03c0,
                  0x39402268, 0x7100091f]
        branch(0x54000000, 'resume')
        words += [0x52800048, 0x39002268, 0x52800068, 0xf9000268]
        label('resume')
        call(resume)
    for index, opcode, target, width in branches:
        delta = labels[target] - index
        require(-(2**(width - 1)) <= delta < 2**(width - 1), 'local policy branch out of range')
        words[index] = opcode | ((delta & ((1 << width) - 1)) << (0 if width == 26 else 5))
    return b''.join(word.to_bytes(4, 'little') for word in words)


def selected(image):
    def relevant(symbol):
        return b'17brynja_crypto_cpu3aes' in symbol and b'7Session' in symbol and (
            b'encrypt' in symbol or b'decrypt' in symbol)
    code, starts, symbols = mapping.parse(image, symbol_filter=relevant)
    ends, result = dict(zip(starts, starts[1:])), {}
    operation = r'7Session10(encrypt|decrypt)(128|192|256)'
    legacy = r'__ZN17brynja_crypto_cpu3aes' + operation + r'17h[0-9a-f]{16}E'
    current = r'__RNvM(?:s[0-9a-z]*_)?NtC\w+_17brynja_crypto_cpu3aesNtB[0-9a-z]+_' + operation
    for symbol, address in symbols:
        match = re.fullmatch(legacy, symbol) or re.fullmatch(current, symbol)
        require(match is not None and address in ends, 'unknown/incomplete Apple session function')
        role = match[1], int(match[2])
        require(role not in result, 'duplicate session role')
        result[role] = (symbol, address, ends[address] - address, code['offset'] + address - code['address'])
    require(set(result) == {(d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)}
            and len({row[1] for row in result.values()}) == 6, 'session population/alias mismatch')
    return result


def inspect(image, compiler, panic, admission):
    dependency = cleanup.inspect(image, compiler, panic, admission)
    targets = {r['bits']: int(r['address'], 16) for r in dependency['kernel_review']['bodies']
               if r['role'] == 'transform'}
    runtime = imports.inspect(image) if (compiler, panic) == ('1.90.0', 'unwind') else None
    resume = int(runtime['stub_address'], 16) if runtime else None
    reports = []
    for (direction, bits), (symbol, start, size, pos) in sorted(selected(image).items()):
        raw = image[pos:pos + size]
        expected = template(compiler, panic, admission, direction, start, targets[bits], resume)
        require(raw == expected, 'Apple session encoding/extent changed; explicit review required')
        reports.append({'direction': direction, 'bits': bits, 'symbol': symbol, 'address': hex(start),
                        'file_offset': pos, 'size': size, 'instructions': size // 4,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'kernel_address': hex(targets[bits])})
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'sessions': reports, 'unwind_import': runtime, 'cleanup_review': dependency,
            'scope': 'Six retained session admission/direction functions and width-bound kernel calls; MSRV unwind stub statically bound. Not exception-table dispatch, dyld/unwinder, constructors or arbitrary caller qualification.'}
