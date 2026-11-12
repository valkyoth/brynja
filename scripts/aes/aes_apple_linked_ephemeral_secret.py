"""Exact retained Apple per-operation secret-output caller policies.

Full bodies are inspected, including direction, result handling and cleanup.
Runtime exception dispatch and arbitrary call sites are outside this scope.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_secret_public',
    Path(__file__).with_name('aes_apple_linked_ephemeral_public.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
mapping, require, Body, movw = prior.mapping, prior.require, prior.Body, prior.movw


def template(bits, compiler, panic, admission, start, expand, encrypt, decrypt, clear, copy, resume=None):
    prior.prior.prior.sessions.cleanup.configuration(compiler, panic, admission)
    require(bits in (128, 192, 256), 'unsupported Apple ephemeral secret width')
    unwind = panic == 'unwind'
    landing = compiler == '1.90.0' and unwind
    require((resume is not None) == landing, 'wrong ephemeral secret unwind dependency')
    modern = compiler == '1.99.1'
    modern_hosted = modern and admission == 'hosted'
    n = {128: 176, 192: 208, 256: 240}[bits]
    frame, scratch = (n + 112, 96) if unwind else (n + 96, 80)
    owner, result, generation, inverse = (20, 21, 22, 23) if landing else (21, 20, 23, 22)
    key = 26 if modern and unwind else 25
    temp = 8 if not unwind and admission == 'static' else 9
    qreg = 17 - temp
    error = (27 if landing else 25) if unwind else temp
    flag, needs_clear = (26, 25) if landing else (27, 26)
    session_error = error if unwind else 22
    pairs = ([(28, 27, n + 16)] if unwind else []) + [
        (26, 25, frame - 80), (24, 23, frame - 64), (22, 21, frame - 48),
        (20, 19, frame - 32), (29, 30, frame - 16)]
    b = Body(start)

    def byte(offset, reg=8):
        b.emit(0x39400000 | offset << 10 | owner << 5 | reg)

    def quarantine():
        b.emit(movw(8, 2), 0x39002008 | owner << 5, movw(8, 3), 0xf9000008 | owner << 5)

    def health():
        byte(8)
        b.emit(0x7100091f)

    def clear_region(region):
        address = {'destination': 0xaa1303e0, 'schedule': 0x910003e0,
                   'block': 0xd10003a0 | scratch << 10}[region]
        b.emit(address, movw(1, n if region == 'schedule' else 16))
        b.call(clear)

    def store_error(reg):
        b.emit(0x39000400 | result << 5 | reg, movw(8, 1), 0x39000008 | result << 5)

    def session_arguments():
        b.emit(0xd10003a2 | scratch << 10, 0x910003e3,
               0xaa0003e0 | owner << 16, 0xaa0003e1 | generation << 16)

    def success():
        b.label('success')
        b.emit(movw(owner, 16), 0xd10003a1 | scratch << 10, 0xaa1303e0, movw(2, 16))
        b.call(copy)
        clear_region('block')
        clear_region('schedule')
        b.emit(0xa9008013 | owner << 10 | result << 5, 0x3900001f | result << 5)
        b.jump('epilogue')

    def session_failure():
        b.label('session-failure')
        if modern:
            b.emit(0xaa0003e0 | session_error)
        clear_region('block')
        clear_region('destination')
        if unwind:
            b.emit(movw(needs_clear, 0))
            b.jump('clear-schedule')
        else:
            store_error(session_error)
            clear_region('schedule')
            health()
            b.branch(0x54000000, 'epilogue')
            quarantine()
            b.jump('epilogue')

    b.emit(0xd10003ff | frame << 10)
    for first, second, offset in pairs:
        b.emit(0xa9000000 | (offset // 8) << 15 | second << 10 | 31 << 5 | first)
    b.emit(0x910003fd | (frame - 16) << 10, 0xaa0403e0 | inverse,
           0xaa0303f3, 0xaa0203f8, 0xaa0103e0 | key, 0xaa0003e0 | result,
           0xaa0303e0, movw(1, 16))
    b.call(clear)  # Clear caller destination before admission.
    b.emit(0xf9400000 | key << 5 | owner)
    byte(8)
    b.branch(0x34000008, 'not-ready')
    b.emit(0x7100051f)
    b.branch(0x54000001, 'quarantined')
    b.emit(0xf9400400 | key << 5 | generation, 0xf9400008 | owner << 5,
           0xeb08001f | generation << 5)
    b.branch(0x54000001, 'stale')
    byte(9)
    if admission == 'static':
        b.branch(0x36000008, 'architecture', 14)
    elif modern:
        b.branch(0x34000008, 'failure')
    else:
        b.emit(0x7100051f)
        b.branch(0x54000001, 'architecture')
    if admission == 'hosted':
        byte(10)
        b.branch(0x36000008, 'target', 14)
    b.emit(0x6f00e400)
    for offset in range(n - 32, 0, -32):
        b.emit(0xad0003e0 | (offset // 16) << 15)
    b.emit(0x3d8003e0)
    if unwind:
        b.emit(movw(flag, 1))
    b.emit(movw(error, 255 if modern else 6), 0xf9400800 | key << 5)
    b.branch(0xb4000000, 'missing-key' if unwind else 'clear-schedule')
    b.emit(0xf9400c00 | key << 5 | qreg)
    if unwind:
        b.emit(movw(needs_clear, 1))
    b.emit(0xf100001f | (bits // 8) << 10 | qreg << 5)
    b.branch(0x54000001, 'clear-schedule')
    b.emit(0x910003e1)
    b.call(expand)
    byte(8, temp)
    b.emit(movw(qreg, 2))
    b.branch(0x34000000 | temp, 'post-not-ready')
    b.emit(0x7100081f | temp << 5)
    b.branch(0x54000001, 'post-generation')
    b.emit(movw(error, 3))
    b.jump('clear-schedule')
    errors = [('not-ready', 2), ('quarantined', 3), ('stale', 4)]
    if not modern_hosted:
        errors.append(('architecture', 0))
        if admission == 'hosted':
            errors.append(('target', 1))
    for i, (label, code) in enumerate(errors):
        b.label(label)
        b.emit(0x4b0803e8 if label == 'architecture' and modern else movw(8, code))
        if i < len(errors) - 1:
            b.jump('failure')
    b.label('failure')
    store_error(8)
    b.label('clear-destination')
    clear_region('destination')
    b.label('epilogue')
    for first, second, offset in reversed(pairs):
        b.emit(0xa9400000 | (offset // 8) << 15 | second << 10 | 31 << 5 | first)
    b.emit(0x910003ff | frame << 10, 0xd65f03c0)
    if modern_hosted:
        b.label('target')
        b.emit(movw(8, 1))
        b.jump('failure')
    if unwind:
        b.label('missing-key')
        b.emit(movw(needs_clear, 1))
        b.jump('clear-schedule')
    b.label('post-not-ready')
    b.emit(movw(error, 2))
    b.jump('post-failure')
    b.label('post-generation')
    b.emit(0xf9400000 | owner << 5 | temp, 0xeb00001f | temp << 16 | generation << 5)
    b.branch(0x54000001, 'post-stale')
    byte(9, temp)
    if admission == 'static':
        b.branch(0x36000000 | temp, 'post-architecture', 14)
    elif modern:
        b.branch(0x34000000 | temp, 'post-architecture' if unwind else 'post-failure')
    else:
        b.emit(0x7100041f | temp << 5)
        b.branch(0x54000001, 'post-architecture')
    if admission == 'hosted':
        byte(10, temp)
        b.branch(0x36000000 | temp, 'post-target', 14)
    b.emit(0x3dc00300, 0x3c8003a0 | ((-scratch) & 511) << 12)
    if landing:
        b.branch(0x36000000 | inverse, 'encrypt', 14)
        session_arguments()
    else:
        session_arguments()
        b.branch(0x36000000 | inverse, 'encrypt', 14)
    b.call(decrypt)
    b.jump('session-result')
    b.label('post-stale')
    b.emit(movw(error, 4))
    if not modern_hosted or unwind:
        b.jump('post-failure')
        b.label('post-architecture')
        b.emit(movw(error, 0))
        if admission == 'hosted':
            b.jump('post-failure')
            b.label('post-target')
            b.emit(movw(error, 1))
    b.label('post-failure')
    b.emit(0x39002000 | owner << 5 | qreg, movw(qreg, 3), 0xf9000000 | owner << 5 | qreg)
    b.label('clear-schedule')
    if unwind:
        b.emit(0x39000400 | result << 5 | error, 0x39000000 | result << 5 | flag)
    else:
        store_error(error)
    clear_region('schedule')
    health()
    b.branch(0x54000000, 'after-quarantine' if unwind else 'clear-destination')
    quarantine()
    if unwind:
        b.label('after-quarantine')
        b.branch(0x35000000 | needs_clear, 'clear-destination')
        b.jump('epilogue')
    else:
        b.jump('clear-destination')
    if modern_hosted and not unwind:
        b.label('post-target')
        b.emit(movw(error, 1))
        b.jump('post-failure')
    b.label('encrypt')
    if landing:
        session_arguments()
    b.call(encrypt)
    b.label('session-result')
    if modern:
        b.emit(movw(8, 255), 0x6a20011f)
        b.branch(0x54000000, 'success')
        session_failure()
        success()
    else:
        b.emit(0x12001c00 | session_error, 0x7100181f | session_error << 5)
        b.branch(0x54000001, 'session-failure')
        success()
        session_failure()
    if landing:
        # Session failure pad clears block/destination; expansion pad has no
        # initialized block. Both paths clear schedule and quarantine authority.
        b.emit(0xaa0003f5)
        clear_region('block')
        clear_region('destination')
        b.emit(movw(22, 0))
        b.jump('unwind-schedule')
        b.emit(0xaa0003f5)
        health()
        b.branch(0x54000000, 'unwind-needs-destination')
        quarantine()
        b.label('unwind-needs-destination')
        b.emit(movw(22, 1))
        b.label('unwind-schedule')
        clear_region('schedule')
        health()
        b.branch(0x54000000, 'unwind-destination')
        quarantine()
        b.label('unwind-destination')
        b.branch(0x36000016, 'resume', 14)
        clear_region('destination')
        b.label('resume')
        b.emit(0xaa1503e0)
        b.call(resume)
    return b.finish()


def selected(image):
    code, starts, symbols = mapping.parse(image, symbol_filter=lambda s:
        b'3aes9execution' in s and b'Key6secret' in s and b'ExpandedKey' not in s)
    ends, result = dict(zip(starts, starts[1:])), {}
    for symbol, start in symbols:
        match = (re.fullmatch(r'__ZN13brynja_crypto3aes9execution9Aes(128|192|256)Key6secret17h[0-9a-f]{16}E', symbol) or
                 re.fullmatch(r'__RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_9Aes(128|192|256)Key6secret', symbol))
        require(match is not None and start in ends, 'unknown/incomplete Apple ephemeral secret caller')
        bits = int(match[1])
        require(bits not in result, 'duplicate Apple ephemeral secret caller')
        result[bits] = (symbol, start, ends[start] - start, code['offset'] + start - code['address'])
    require(set(result) == {128, 192, 256} and len({r[1] for r in result.values()}) == 3,
            'Apple ephemeral secret population/alias mismatch')
    return result


def inspect(image, compiler, panic, admission):
    dependency = prior.inspect(image, compiler, panic, admission)
    constructors = dependency['cached_review']['constructor_review']
    session = constructors['session_review']
    cleanup = session['cleanup_review']
    clear = next(int(r['address'], 16) for r in cleanup['cleanup_bodies'] if r['role'] == 'zeroize')
    expansions = {r['bits']: int(r['address'], 16) for r in cleanup['kernel_review']['bodies'] if r['role'] == 'expand'}
    copy = next(int(r['address'], 16) for r in constructors['constructors_and_copy'] if r['role'] == 'copy')
    sessions = prior.prior.prior.sessions.selected(image)
    resume = int(session['unwind_import']['stub_address'], 16) if session['unwind_import'] else None
    reports = []
    for bits, (symbol, start, size, pos) in sorted(selected(image).items()):
        encrypt, decrypt = sessions['encrypt', bits][1], sessions['decrypt', bits][1]
        expected = template(bits, compiler, panic, admission, start, expansions[bits], encrypt, decrypt, clear, copy, resume)
        raw = image[pos:pos + size]
        require(raw == expected, 'Apple ephemeral secret encoding/extent changed; explicit review required')
        reports.append({'bits': bits, 'symbol': symbol, 'address': hex(start), 'file_offset': pos,
                        'size': size, 'instructions': size // 4, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'expansion_address': hex(expansions[bits]), 'encrypt_address': hex(encrypt),
                        'decrypt_address': hex(decrypt)})
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'ephemeral_secret_callers': reports, 'ephemeral_public_review': dependency,
            'scope': 'Three retained shared ephemeral secret encrypt/decrypt callers and bound dependencies; '
                     'not all call sites, exception dispatch, loader/unwinder, startup/lifetime admission or spill erasure.'}
