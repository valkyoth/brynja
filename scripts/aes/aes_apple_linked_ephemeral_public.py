"""Exact retained Apple per-operation public-encryption instruction policies.

Templates encode inspected bodies, including expansion and repeated admission.
They are not learned from the executable supplied to the checker.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_ephemeral_cached',
    Path(__file__).with_name('aes_apple_linked_cached.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
mapping, require, Body, movw = prior.mapping, prior.require, prior.Body, prior.movw


def template(bits, compiler, panic, admission, start, expand, kernel, clear, resume=None):
    prior.prior.sessions.cleanup.configuration(compiler, panic, admission)
    require(bits in (128, 192, 256), 'unsupported Apple ephemeral public width')
    landing = (compiler, panic) == ('1.90.0', 'unwind')
    require((resume is not None) == landing, 'wrong ephemeral public unwind dependency')
    n = {128: 176, 192: 208, 256: 240}[bits]
    frame = n + (64 if bits == 128 else 80)
    scratch = 48 if bits == 128 else 64
    owner, generation, source, destination = (21, 22, 20, 19) if landing else (19, 20, 22, 21)
    error = 19 if landing else 20
    modern_hosted = compiler == '1.99.1' and admission == 'hosted'
    split_return = compiler == '1.99.1' and panic == 'abort' and bits == 128
    b = Body(start)
    pairs = ([] if bits == 128 else [(28, 27, n + 16)]) + [
        (22, 21, frame - 48), (20, 19, frame - 32), (29, 30, frame - 16)]

    def epilogue():
        for first, second, offset in reversed(pairs):
            b.emit(0xa9400000 | (offset // 8) << 15 | second << 10 | 31 << 5 | first)
        b.emit(0x910003ff | frame << 10, 0xd65f03c0)

    def return_value():
        b.jump('epilogue') if panic == 'unwind' else epilogue()

    def byte(offset, reg=8):
        b.emit(0x39400000 | offset << 10 | owner << 5 | reg)

    def quarantine():
        b.emit(movw(8, 2), 0x39002008 | owner << 5, movw(8, 3), 0xf9000008 | owner << 5)

    def clear_region(block=False):
        b.emit((0xd10003a0 | scratch << 10) if block else 0x910003e0,
               movw(1, 16 if block else n))
        b.call(clear)

    def health():
        byte(8)
        b.emit(0x7100091f)

    b.emit(0xd10003ff | frame << 10)
    for first, second, offset in pairs:
        b.emit(0xa9000000 | (offset // 8) << 15 | second << 10 | 31 << 5 | first)
    b.emit(0x910003fd | (frame - 16) << 10, 0xf9400000 | owner)
    byte(8)
    b.branch(0x34000008, 'not-ready')
    b.emit(0x7100051f)
    b.branch(0x54000001, 'quarantined')
    b.emit(0xf9400400 | generation, 0xf9400008 | owner << 5,
           0xeb08001f | generation << 5)
    b.branch(0x54000001, 'stale')
    for offset, label in [(9, 'architecture')] + ([(10, 'target')] if admission == 'hosted' else []):
        byte(offset)
        if compiler == '1.90.0':
            b.emit(0x7100051f)
            b.branch(0x54000001, label)
        else:
            b.branch(0x34000008, label)
    # Initialize the complete temporary schedule before checking raw storage.
    b.emit(0x6f00e400)
    for offset in range(n - 32, 0, -32):
        b.emit(0xad0003e0 | (offset // 16) << 15)
    b.emit(0x3d8003e0, movw(9, 6 if compiler == '1.90.0' else 255), 0xf9400808)
    b.branch(0xb4000008, 'clear-schedule')
    b.emit(0xf9400c0a, 0xf100015f | (bits // 8) << 10)
    b.branch(0x54000001, 'clear-schedule')
    b.emit(*([0xaa0203f3, 0xaa0103f4] if landing else [0xaa0103f6, 0xaa0203f5]))
    b.emit(0x910003e1, 0xaa0803e0)
    b.call(expand)
    byte(8, 9)
    b.emit(movw(8, 2))
    b.branch(0x34000009, 'post-not-ready')
    b.emit(0x7100093f)
    b.branch(0x54000001, 'post-generation')
    b.emit(movw(9, 3))
    b.jump('clear-schedule')
    errors = [('not-ready', 2), ('quarantined', 3), ('stale', 4), ('architecture', 0)]
    if admission == 'hosted':
        errors.append(('target', 1))
    for label, value in errors:
        b.label(label)
        b.emit(0x4b0803e0 if label == 'architecture' and compiler == '1.99.1'
               and admission == 'static' else movw(0, value))
        return_value()
    b.label('post-not-ready')
    b.emit(movw(9, 2))
    b.jump('post-failure')
    b.label('post-generation')
    b.emit(0xf9400009 | owner << 5, 0xeb09001f | generation << 5)
    b.branch(0x54000001, 'post-stale')
    byte(9, 9)
    if admission == 'static':
        b.branch(0x36000009, 'post-architecture', 14)
    elif modern_hosted:
        b.branch(0x34000009, 'post-failure')
    else:
        b.emit(0x7100053f)
        b.branch(0x54000001, 'post-architecture')
    if admission == 'hosted':
        byte(10, 9)
        b.branch(0x36000009, 'post-target', 14)
    # Stage exactly one input block; public publication follows the transform.
    b.emit(0x3dc00000 | source << 5, 0x3c8003a0 | ((-scratch) & 511) << 12,
           0xd10003a0 | scratch << 10, 0x910003e1, movw(2, 0))
    b.call(kernel)
    b.emit(0x3cc003a0 | ((-scratch) & 511) << 12, 0x3d800000 | destination << 5)
    clear_region(block=True)
    clear_region()
    b.emit(movw(0, 7 if compiler == '1.90.0' else 254))
    return_value()
    b.label('post-stale')
    b.emit(movw(9, 4))
    if not modern_hosted:
        b.jump('post-failure')
        b.label('post-architecture')
        b.emit(movw(9, 0))
        if admission == 'hosted':
            b.jump('post-failure')
            b.label('post-target')
            b.emit(movw(9, 1))
    b.label('post-failure')
    b.emit(0x39002008 | owner << 5, movw(8, 3), 0xf9000008 | owner << 5)
    b.label('clear-schedule')
    b.emit(0xaa0903e0 | error)
    clear_region()
    health()
    if split_return:
        b.branch(0x54000001, 'final-quarantine')
        b.emit(0xaa0003e0 | error << 16)
        epilogue()
        b.label('final-quarantine')
    else:
        b.branch(0x54000000, 'error-return')
    quarantine()
    b.label('error-return')
    b.emit(0xaa0003e0 | error << 16)
    b.label('epilogue')
    epilogue()
    if modern_hosted:
        b.label('post-target')
        b.emit(movw(9, 1))
        b.jump('post-failure')
    if landing:
        # Separate retained transform and expansion landing-pad entries.
        b.emit(0xaa0003f3)
        health()
        b.branch(0x54000000, 'unwind-block')
        quarantine()
        b.label('unwind-block')
        clear_region(block=True)
        clear_region()
        health()
        b.branch(0x54000000, 'resume')
        b.jump('unwind-last-quarantine')
        b.emit(0xaa0003f3)
        health()
        b.branch(0x54000001, 'unwind-first-quarantine')
        clear_region()
        health()
        b.branch(0x54000001, 'unwind-last-quarantine')
        b.label('resume')
        b.emit(0xaa1303e0)
        b.call(resume)
        b.label('unwind-first-quarantine')
        quarantine()
        clear_region()
        health()
        b.branch(0x54000000, 'resume')
        b.label('unwind-last-quarantine')
        quarantine()
        b.emit(0xaa1303e0)
        b.call(resume)
    return b.finish()


def selected(image):
    code, starts, symbols = mapping.parse(image,
        symbol_filter=lambda s: b'brynja_aes_accelerated_fixture9public' in s)
    ends, result = dict(zip(starts, starts[1:])), {}
    for symbol, start in symbols:
        match = (re.fullmatch(r'__ZN30brynja_aes_accelerated_fixture9public(128|192|256)17h[0-9a-f]{16}E', symbol) or
                 re.fullmatch(r'__RNvC\w+_30brynja_aes_accelerated_fixture9public(128|192|256)', symbol))
        require(match is not None and start in ends, 'unknown/incomplete Apple ephemeral public caller')
        bits = int(match[1])
        require(bits not in result, 'duplicate Apple ephemeral public caller')
        result[bits] = (symbol, start, ends[start] - start, code['offset'] + start - code['address'])
    require(set(result) == {128, 192, 256} and len({r[1] for r in result.values()}) == 3,
            'Apple ephemeral public population/alias mismatch')
    return result


def inspect(image, compiler, panic, admission):
    dependency = prior.inspect(image, compiler, panic, admission)
    session = dependency['constructor_review']['session_review']
    cleanup = session['cleanup_review']
    clear = next(int(r['address'], 16) for r in cleanup['cleanup_bodies'] if r['role'] == 'zeroize')
    kernels = {(r['role'], r['bits']): int(r['address'], 16) for r in cleanup['kernel_review']['bodies']}
    resume = int(session['unwind_import']['stub_address'], 16) if session['unwind_import'] else None
    reports = []
    for bits, (symbol, start, size, pos) in sorted(selected(image).items()):
        expected = template(bits, compiler, panic, admission, start, kernels['expand', bits],
                            kernels['transform', bits], clear, resume)
        raw = image[pos:pos + size]
        require(raw == expected, 'Apple ephemeral public encoding/extent changed; explicit review required')
        reports.append({'bits': bits, 'symbol': symbol, 'address': hex(start), 'file_offset': pos,
                        'size': size, 'instructions': size // 4, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'expansion_address': hex(kernels['expand', bits]),
                        'kernel_address': hex(kernels['transform', bits])})
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'ephemeral_public_callers': reports, 'cached_review': dependency,
            'scope': 'Three retained fixture-inlined ephemeral public callers and bound dependencies; '
                     'not ephemeral secret callers, all call sites, exception dispatch, loader/unwinder, '
                     'startup/lifetime admission or spill erasure.'}
