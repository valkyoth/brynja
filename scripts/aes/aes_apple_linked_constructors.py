"""Explicit retained Apple raw/cached constructor and copy instruction policies.

Templates are built from inspected instruction sequences, never learned from
an input binary. Calls bind to independently checked dependencies in that image.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_constructor_sessions',
    Path(__file__).with_name('aes_apple_linked_sessions.py'))
sessions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sessions)
mapping, require = sessions.mapping, sessions.require


class Body:
    def __init__(self, start):
        require(type(start) is int and start >= 0 and start % 4 == 0, 'invalid constructor start')
        self.start, self.words, self.labels, self.branches = start, [], {}, []

    def emit(self, *words):
        self.words.extend(words)

    def label(self, name):
        require(name not in self.labels, 'duplicate constructor label')
        self.labels[name] = len(self.words)

    def branch(self, opcode, label, width=19):
        self.branches.append((len(self.words), opcode, label, width))
        self.words.append(0)

    def jump(self, label):
        self.branch(0x14000000, label, 26)

    def call(self, target, tail=False):
        require(type(target) is int and target >= 0, 'missing constructor call target')
        delta = target - (self.start + len(self.words) * 4)
        require(delta % 4 == 0 and -(2**27) <= delta < 2**27, 'constructor call out of range')
        self.emit((0x14000000 if tail else 0x94000000) | ((delta // 4) & 0x3ffffff))

    def finish(self):
        for index, opcode, label, width in self.branches:
            require(label in self.labels, 'missing constructor label')
            delta = self.labels[label] - index
            require(-(2**(width - 1)) <= delta < 2**(width - 1), 'constructor branch out of range')
            self.words[index] = opcode | ((delta & ((1 << width) - 1)) << (0 if width == 26 else 5))
        return b''.join(w.to_bytes(4, 'little') for w in self.words)


def movw(register, value):
    return 0x52800000 | value << 5 | register


def copy_template():
    # Length-only 8-byte loop and byte remainder, followed by clearing x4/x5/x6
    # and NZCV. This is not a claim about copies elsewhere in the program.
    return bytes.fromhex('e5031faa e60302aa df2000f1 e3000054 246865f8 046825f8 '
                         'a5200091 c62000d1 df2000f1 62ffff54 c60000b4 24686538 '
                         '04682538 a5040091 c60400d1 86ffffb5 e4031faa e5031faa '
                         'e6031faa ff031feb c0035fd6')


def template(role, bits, compiler, panic, admission, start, clear, copy, expand=None, resume=None):
    sessions.cleanup.configuration(compiler, panic, admission)
    require(role in ('raw', 'cached') and bits in (128, 192, 256), 'unsupported Apple constructor role/width')
    cached = role == 'cached'
    landing = cached and (compiler, panic) == ('1.90.0', 'unwind')
    require((expand is not None) == cached and (resume is not None) == landing,
            'wrong constructor dependency population')
    n = {128: 176, 192: 208, 256: 240}[bits] if cached else bits // 8
    b = Body(start)
    # The MSRV cached unwind layout swaps owner and return-slot registers.
    owner, result = (20, 21) if landing else (21, 20)
    modern_hosted = compiler == '1.99.1' and admission == 'hosted'

    def load_byte(reg, offset):
        b.emit(0x39400000 | offset << 10 | owner << 5 | reg)

    def quarantine():
        b.emit(movw(8, 2), 0x39002008 | owner << 5, movw(8, 3), 0xf9000008 | owner << 5)

    def epilogue():
        if cached:
            for word in (0xa94e7bfd, 0xa94d4ff4, 0xa94c57f6, 0xa94b5ff8):
                b.emit(word + ((n - 176) // 8 << 15))
            b.emit(0x910003ff | (n + 64) << 10)
        else:
            b.emit(0xa9437bfd, 0xa9424ff4, 0xa94157f6, 0xa8c45ff8)

    def clear_region(scratch=False):
        b.emit(0x910003e0 if scratch else 0xaa1303e0, movw(1, n))
        b.call(clear)

    def authority(reg, prefix):
        load_byte(reg, 9)
        if admission == 'static':
            b.branch(0x36000000 | reg, prefix + 'architecture', 14)
        elif modern_hosted:
            # Zero already is the error code; no separate MOV-zero block.
            b.branch(0x34000000 | reg, prefix + 'failure')
        else:
            b.emit(0x7100041f | reg << 5)
            b.branch(0x54000001, prefix + 'architecture')
        if admission == 'hosted':
            load_byte(reg, 10)
            b.branch(0x36000000 | reg, prefix + 'target', 14)

    if cached:
        b.emit(0xd10003ff | (n + 64) << 10)
        for word in (0xa90b5ff8, 0xa90c57f6, 0xa90d4ff4, 0xa90e7bfd):
            b.emit(word + ((n - 176) // 8 << 15))
        b.emit(0x910003fd | (n + 48) << 10)
    else:
        b.emit(0xa9bc5ff8, 0xa90157f6, 0xa9024ff4, 0xa9037bfd, 0x9100c3fd)
    b.emit(0xaa0303f3, 0xaa0203f6, 0xaa0103e0 | owner, 0xaa0003e0 | result,
           0xaa0303e0, movw(1, n))
    b.call(clear)  # Clear admitted destination before any admission decision.
    load_byte(8, 8)
    b.branch(0x34000008, 'not-ready')
    b.emit(0x7100051f)
    b.branch(0x54000001, 'quarantined')
    authority(8, '')
    b.emit(0xf9400017 | owner << 5)  # Capture generation.
    if cached:
        b.emit(0x6f00e400)
        for offset in range(n - 32, 0, -32):
            b.emit(0xad0003e0 | (offset // 16) << 15)
        b.emit(0x3d8003e0, 0x910003e1, 0xaa1603e0)
        b.call(expand)
        load_byte(9, 8)
        b.emit(movw(8, 2))
        b.branch(0x34000009, 'post-not-ready')
        b.emit(0x7100093f)
        b.branch(0x54000001, 'post-generation')
        b.emit(movw(9, 3))
        b.jump('post-result')
    else:
        b.emit(movw(24, n), 0xaa1303e0, 0xaa1603e1, movw(2, n))
        b.call(copy)
        b.emit(0xa9005e95, 0xa9016293)
        epilogue()
        b.emit(0xd65f03c0)
    errors = [('not-ready', 2), ('quarantined', 3)]
    if not modern_hosted:
        errors.append(('architecture', 0))
    if admission == 'hosted':
        errors.append(('target', 1))
    for i, (label, value) in enumerate(errors):
        b.label(label)
        b.emit(movw(8, value))
        if i < len(errors) - 1:
            b.jump('failure')
    b.label('failure')
    b.emit(0x39002008 | result << 5, 0xf900001f | result << 5)
    b.label('clear-destination')
    if not cached:
        b.emit(0xaa1303e0, movw(1, n))
        epilogue()
        b.call(clear, tail=True)
        return b.finish()
    clear_region()
    b.label('epilogue')
    epilogue()
    b.emit(0xd65f03c0)
    b.label('post-not-ready')
    b.emit(movw(9, 2))
    b.jump('post-failure')
    b.label('post-generation')
    b.emit(0xf9400009 | owner << 5, 0xeb0902ff)
    b.branch(0x54000001, 'post-stale')
    authority(9, 'post-')
    b.emit(movw(22, n), 0x910003e1, 0xaa1303e0, movw(2, n))
    b.call(copy)
    clear_region(scratch=True)
    b.emit(0xa9005c00 | result << 5 | owner, 0xa9015813 | result << 5)
    if panic == 'unwind':
        b.jump('epilogue')
    else:
        epilogue()
        b.emit(0xd65f03c0)
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
    b.label('post-result')
    b.emit(0x39002009 | result << 5, 0xf900001f | result << 5)
    clear_region(scratch=True)
    load_byte(8, 8)
    b.emit(0x7100091f)
    b.branch(0x54000000, 'clear-destination')
    quarantine()
    b.jump('clear-destination')
    if modern_hosted:
        b.label('post-target')
        b.emit(movw(9, 1))
        b.jump('post-failure')
    if landing:
        # Complete retained landing pad after the ordinary return paths.
        b.emit(0xaa0003f5)
        load_byte(8, 8)
        b.emit(0x7100091f)
        b.branch(0x54000001, 'unwind-first-quarantine')
        clear_region(scratch=True)
        load_byte(8, 8)
        b.emit(0x7100091f)
        b.branch(0x54000001, 'unwind-second-quarantine')
        b.label('unwind-destination')
        clear_region()
        b.emit(0xaa1503e0)
        b.call(resume)
        b.label('unwind-first-quarantine')
        quarantine()
        clear_region(scratch=True)
        load_byte(8, 8)
        b.emit(0x7100091f)
        b.branch(0x54000000, 'unwind-destination')
        b.label('unwind-second-quarantine')
        quarantine()
        clear_region()
        b.emit(0xaa1503e0)
        b.call(resume)
    return b.finish()


def selected(image):
    def relevant(symbol):
        return b'secret_memory_transfer10copy_bytes' in symbol or (
            b'30brynja_aes_accelerated_fixture9lifecycle' in symbol and b'new_' in symbol)
    code, starts, symbols = mapping.parse(image, symbol_filter=relevant)
    ends, result = dict(zip(starts, starts[1:])), {}
    for symbol, start in symbols:
        stem = r'30brynja_aes_accelerated_fixture9lifecycle6aes(128|192|256)(7new_key|10new_cached)'
        match = (re.fullmatch(r'__ZN' + stem + r'17h[0-9a-f]{16}E', symbol) or
                 re.fullmatch(r'__RNvNtNtC\w+_' + stem, symbol))
        if match:
            role = ('raw' if match[2] == '7new_key' else 'cached', int(match[1]))
        else:
            require(re.fullmatch(r'__(?:ZN11brynja_core22secret_memory_transfer10copy_bytes17h[0-9a-f]{16}E|'
                                 r'RNvNtC\w+_11brynja_core22secret_memory_transfer10copy_bytes)', symbol),
                    'unknown Apple constructor/copy symbol')
            role = ('copy', 0)
        require(role not in result and start in ends, 'duplicate/incomplete Apple constructor role')
        result[role] = (symbol, start, ends[start] - start, code['offset'] + start - code['address'])
    require(set(result) == {('copy', 0), *((r, b) for r in ('raw', 'cached') for b in (128, 192, 256))}
            and len({r[1] for r in result.values()}) == 7, 'Apple constructor population/alias mismatch')
    return result


def inspect(image, compiler, panic, admission):
    dependency = sessions.inspect(image, compiler, panic, admission)
    cleanup = dependency['cleanup_review']
    clear = next(int(r['address'], 16) for r in cleanup['cleanup_bodies'] if r['role'] == 'zeroize')
    expansions = {r['bits']: int(r['address'], 16) for r in cleanup['kernel_review']['bodies'] if r['role'] == 'expand'}
    resume = int(dependency['unwind_import']['stub_address'], 16) if dependency['unwind_import'] else None
    rows, reports = selected(image), []
    for (role, bits), (symbol, start, size, pos) in sorted(rows.items(), key=lambda item: item[0][0] != 'copy'):
        expected = (copy_template() if role == 'copy' else
                    template(role, bits, compiler, panic, admission, start, clear, rows['copy', 0][1],
                             expansions[bits] if role == 'cached' else None,
                             resume if role == 'cached' else None))
        raw = image[pos:pos + size]
        require(raw == expected, 'Apple constructor/copy encoding/extent changed; explicit review required')
        reports.append({'role': role, 'bits': bits, 'symbol': symbol, 'address': hex(start),
                        'file_offset': pos, 'size': size, 'instructions': size // 4,
                        'sha256': hashlib.sha256(raw).hexdigest()})
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'constructors_and_copy': reports, 'session_review': dependency,
            'scope': 'Six retained raw/cached constructors and copy helper with exact dependency calls; '
                     'not higher-level operation callers, exception dispatch, loader/unwinder or platform startup qualification.'}
