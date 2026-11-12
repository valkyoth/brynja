"""Exact retained Apple cached public/secret caller instruction policies.

Policies follow whole-body inspection. Dependency calls are bound, not masked;
exception dispatch and the system runtime remain outside this scoped review.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_cached_constructors',
    Path(__file__).with_name('aes_apple_linked_constructors.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
mapping, require, Body, movw = prior.mapping, prior.require, prior.Body, prior.movw


def template(kind, bits, compiler, panic, admission, start, kernel, clear, copy=None, resume=None):
    prior.sessions.cleanup.configuration(compiler, panic, admission)
    require(kind in ('public', 'secret') and bits in (128, 192, 256), 'unsupported Apple cached kind/width')
    public = kind == 'public'
    landing = (compiler, panic) == ('1.90.0', 'unwind')
    require((copy is not None) == (not public) and (resume is not None) == landing,
            'wrong cached dependency population')
    b = Body(start)
    n = {128: 176, 192: 208, 256: 240}[bits]
    owner = (19 if landing else 9) if public else (24 if landing else 8)
    temp = 8 if public or landing else 9

    def byte(offset, reg=temp):
        b.emit(0x39400000 | offset << 10 | owner << 5 | reg)

    def quarantine(reg=8):
        b.emit(movw(reg, 2), 0x39002000 | owner << 5 | reg,
               movw(reg, 3), 0xf9000000 | owner << 5 | reg)

    def epilogue():
        b.emit(*([0xa9427bfd, 0xa9414ff4, 0x9100c3ff] if public else
                 [0xa9447bfd, 0xa9434ff4, 0xa94257f6, 0xa9415ff8, 0x910143ff]))

    def prologue():
        b.emit(*([0xd100c3ff, 0xa9014ff4, 0xa9027bfd, 0x910083fd] if public else
                 [0xd10143ff, 0xa9015ff8, 0xa90257f6, 0xa9034ff4, 0xa9047bfd, 0x910103fd]))

    def clear_region(destination=False):
        b.emit(0xaa1303e0 if destination else 0x910003e0, movw(1, 16))
        b.call(clear)

    def success_secret():
        b.emit(movw(21, 16), 0x910003e1, 0xaa1303e0, movw(2, 16))
        b.call(copy)
        clear_region()
        b.emit(0xa900d693, 0x3900029f)
        if landing:
            b.jump('epilogue')
        else:
            epilogue()
            b.emit(0xd65f03c0)

    if public:
        if landing:
            prologue()
        b.emit(0xf9400000 | owner)
    else:
        prologue()
        b.emit(0xaa0403f5, 0xaa0303f3, 0xaa0203f6, 0xaa0103f7, 0xaa0003f4,
               0xaa0303e0, movw(1, 16))
        b.call(clear)  # Secret destination is cleared before admission.
        b.emit(0xf94002e0 | owner)
    byte(8)
    b.branch(0x34000000 | temp, 'not-ready')
    b.emit(0x7100041f | temp << 5)
    b.branch(0x54000001, 'quarantined')
    other = 9 if landing else 10
    b.emit((0xf9400400 if public else 0xf94006e0) | temp,
           0xf9400000 | owner << 5 | other,
           0xeb00001f | other << 16 | temp << 5)
    b.branch(0x54000001, 'stale')
    byte(9)
    if public:
        if compiler == '1.90.0':
            b.emit(0x7100051f)
            b.branch(0x54000001, 'architecture')
        else:
            b.branch(0x34000008, 'architecture')
    elif admission == 'static':
        b.branch(0x36000000 | temp, 'architecture', 14)
    elif compiler == '1.90.0':
        b.emit(0x7100041f | temp << 5)
        b.branch(0x54000001, 'architecture')
    else:
        b.branch(0x34000009, 'architecture')
    if admission == 'hosted':
        byte(10)
        if public and compiler == '1.90.0':
            b.emit(0x7100051f)
            b.branch(0x54000001, 'target')
        else:
            b.branch((0x34000000 if public else 0x36000000) | temp, 'target', 19 if public else 14)
    pointer = 8 if public else 1
    length = other if public else temp
    b.emit((0xf9400800 if public else 0xf9400ae0) | pointer)
    b.branch(0xb4000000 | pointer, 'invalid-schedule')
    b.emit((0xf9400c00 if public else 0xf9400ee0) | length,
           0xf100001f | n << 10 | length << 5)
    b.branch(0x54000001, 'invalid-schedule')
    if public:
        if landing:
            b.emit(0xaa0203f4)
        else:
            prologue()
        b.emit(0x3dc00020, 0x3d8003e0, 0x910003e0, 0xaa0803e1)
        if not landing:
            b.emit(0xaa0203f3)
        b.emit(movw(2, 0))  # Public path is encryption only.
        b.call(kernel)
        b.emit(0x3dc003e0, 0x3d800280 if landing else 0x3d800260)
        clear_region()
        b.emit(movw(0, 7 if compiler == '1.90.0' else 254))
        if landing:
            b.jump('epilogue')
        else:
            epilogue()
            b.emit(0xd65f03c0)
    else:
        b.emit(0x3dc002c0, 0x3d8003e0)
        if landing:
            b.branch(0x36000015, 'encrypt', 14)
            b.emit(0x910003e0, movw(2, 1))
            b.call(kernel)
            b.jump('publish-secret')
        else:
            b.emit(0x910003e0, 0xaa1503e2)
            b.call(kernel)
            success_secret()
    errors = [('not-ready', 2), ('quarantined', 3), ('stale', 4), ('architecture', 0)]
    if admission == 'hosted':
        errors.append(('target', 1))
    for i, (name, code) in enumerate(errors):
        b.label(name)
        # The current static layout negates a known-zero admission field.
        if name == 'architecture' and compiler == '1.99.1' and admission == 'static':
            b.emit(0x4b0803e0 if public else 0x4b0903e8)
        else:
            b.emit(movw(0 if public else 8, code))
        if public:
            b.jump('epilogue') if landing else b.emit(0xd65f03c0)
        elif i < len(errors) - 1:
            b.jump('failure')
    if not public:
        b.label('failure')
        b.emit(0x39000688, movw(8, 1), 0x39000288)
        b.label('clear-destination')
        if landing:
            clear_region(destination=True)
            b.label('epilogue')
            epilogue()
            b.emit(0xd65f03c0)
        else:
            b.emit(0xaa1303e0, movw(1, 16))
            epilogue()
            b.call(clear, tail=True)
    b.label('invalid-schedule')
    if public:
        quarantine()
        b.emit(movw(0, 6 if compiler == '1.90.0' else 255))
        if landing:
            b.label('epilogue')
            epilogue()
        b.emit(0xd65f03c0)
    else:
        err = 0x601 if compiler == '1.90.0' else 0xff01
        reg = 8 if landing else 9
        b.emit(movw(reg, err), 0x79000280 | reg)
        quarantine(reg)
        b.jump('clear-destination')
        if landing:
            b.label('encrypt')
            b.emit(0x910003e0, movw(2, 0))
            b.call(kernel)
            b.label('publish-secret')
            success_secret()
    if landing:
        if public:
            b.emit(0xaa0003f4)
            byte(8)
            b.emit(0x7100091f)
            b.branch(0x54000001, 'unwind-first-quarantine')
            clear_region()
            byte(8)
            b.emit(0x7100091f)
            b.branch(0x54000001, 'unwind-second-quarantine')
            b.label('resume')
            b.emit(0xaa1403e0)
            b.call(resume)
            b.label('unwind-first-quarantine')
            quarantine()
            clear_region()
            byte(8)
            b.emit(0x7100091f)
            b.branch(0x54000000, 'resume')
            b.label('unwind-second-quarantine')
            quarantine()
            b.emit(0xaa1403e0)
            b.call(resume)
        else:
            # Both retained landing-pad entries, including the branch-to-next.
            b.jump('landing')
            b.label('landing')
            b.emit(0xaa0003f4)
            byte(8)
            b.emit(0x7100091f)
            b.branch(0x54000000, 'unwind-clear')
            quarantine()
            b.label('unwind-clear')
            clear_region()
            clear_region(destination=True)
            byte(8)
            b.emit(0x7100091f)
            b.branch(0x54000000, 'resume')
            quarantine()
            b.label('resume')
            b.emit(0xaa1403e0)
            b.call(resume)
    return b.finish()


def selected(image):
    def relevant(symbol):
        return b'3aes9execution' in symbol and b'ExpandedKey' in symbol and (
            b'encrypt_block_public' in symbol or b'6secret' in symbol)
    code, starts, symbols = mapping.parse(image, symbol_filter=relevant)
    ends, result = dict(zip(starts, starts[1:])), {}
    owner = r'17Aes(128|192|256)ExpandedKey(20encrypt_block_public|6secret)'
    for symbol, start in symbols:
        match = (re.fullmatch(r'__ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E', symbol) or
                 re.fullmatch(r'__RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_' + owner, symbol))
        require(match is not None and start in ends, 'unknown/incomplete Apple cached caller')
        role = ('public' if match[2] == '20encrypt_block_public' else 'secret', int(match[1]))
        require(role not in result, 'duplicate Apple cached caller')
        result[role] = (symbol, start, ends[start] - start, code['offset'] + start - code['address'])
    require(set(result) == {(k, b) for k in ('public', 'secret') for b in (128, 192, 256)}
            and len({row[1] for row in result.values()}) == 6, 'Apple cached population/alias mismatch')
    return result


def inspect(image, compiler, panic, admission):
    dependency = prior.inspect(image, compiler, panic, admission)
    session = dependency['session_review']
    cleanup = session['cleanup_review']
    clear = next(int(r['address'], 16) for r in cleanup['cleanup_bodies'] if r['role'] == 'zeroize')
    kernels = {r['bits']: int(r['address'], 16) for r in cleanup['kernel_review']['bodies'] if r['role'] == 'transform'}
    copy = next(int(r['address'], 16) for r in dependency['constructors_and_copy'] if r['role'] == 'copy')
    resume = int(session['unwind_import']['stub_address'], 16) if session['unwind_import'] else None
    reports = []
    for (kind, bits), (symbol, start, size, pos) in sorted(selected(image).items()):
        expected = template(kind, bits, compiler, panic, admission, start, kernels[bits], clear,
                            copy if kind == 'secret' else None, resume)
        raw = image[pos:pos + size]
        require(raw == expected, 'Apple cached caller encoding/extent changed; explicit review required')
        reports.append({'kind': kind, 'bits': bits, 'symbol': symbol, 'address': hex(start),
                        'file_offset': pos, 'size': size, 'instructions': size // 4,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'kernel_address': hex(kernels[bits])})
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'cached_callers': reports, 'constructor_review': dependency,
            'scope': 'Six retained cached public/secret callers and bound dependencies; not ephemeral callers, '
                     'all call sites, exception dispatch, loader/unwinder, startup/lifetime admission or spill erasure.'}
