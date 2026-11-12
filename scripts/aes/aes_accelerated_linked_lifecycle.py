"""Exact x86 package-external constructors and retained destruction bodies.

Constructor policies cover both panic profiles. LTO merges the six owner
destructors; execution checks all source routes, without claiming a review of
every call site in the fixture main functions. No automatic policy refresh.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('lifecycle_operation_review',
        Path(__file__).with_name('aes_accelerated_linked_ephemeral_public.py'))
operations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operations)
secret = operations.secret
kernels, image_review = operations.kernels, operations.image_review
require, TARGET = operations.require, operations.TARGET


def policies(rows):
    return {(role, bits): dict(instructions=count, symbol_bytes=size, calls=calls,
            tail_calls=tails, constant_loads=0, text_sha256=text, encoding_sha256=encoding)
            for role, bits, count, size, calls, tails, text, encoding in rows}


# Full bodies inspected: destination admission/clearing, authority binding,
# full-width copying/expansion, temporary cleanup, success/error representation.
POLICY = {
    ('1.90.0', 'abort'): policies([
        ('new_cached', 128, 92, 349, 6, 0, '926f3368e499677cd571b7598218ac2986413cfba253ff45f374f362dc36f5f4', '3f767bdeea6c7c4aceb7eb4c6a0f70596fe7bb8b7d7ead180a9b7899f338071d'),
        ('new_cached', 192, 94, 365, 6, 0, '68cf91f48cd123ad0fdfb1ff22223d43c667255e461dc5a38ac6dfdf102a399e', '601129b05cf095e54db33840d0595befbb4b27bfb0e66f748f93fd8c18a31b63'),
        ('new_cached', 256, 96, 381, 6, 0, '2485d00ac780e42f12485dd7d738568798e1957d8bed99c246db7ceb990c579a', '2bba2191981934b2ea01bc576f0249f72797a8a53a10c6cf08fb632adc93a90d'),
        ('new_key', 128, 49, 146, 2, 1, '3bc2cd531db5a0fbcc421af355de823aecb3d27ac52bdc0ba078160edc0e1429', '3cccfee8f3d6de3cbd862414024c591e807d77d6120399e85ac7755773685e31'),
        ('new_key', 192, 49, 146, 2, 1, '4d3de6f21a7d9560b85c713b3c45e1390357dccd9755df7631a00ae4942a228f', 'e6f83c9df054aef77501fc75fd7b8e816314557ce85109810108da95529d9d96'),
        ('new_key', 256, 49, 146, 2, 1, 'decfc7ab94a43e3a3b5e3c87474aee686899b52946925632237bdb744360c4b4', 'd56ebec0de47963983e57a0ecee2d05967c738998f14e0bb6f679866f063d795'),
    ]),
    ('1.90.0', 'unwind'): policies([
        ('new_cached', 128, 109, 424, 9, 0, 'af42e1b5b4566c35f5148f1c62b11e84bd47ccbf4415bf81a6ce5aaa10ade63b', '697b0f1abca03eba14be1eac80c6cc9a42a3d0d9989ac55d575ee466ad2c04ef'),
        ('new_cached', 192, 111, 440, 9, 0, 'fe1cf658ceba0cb65bbe70df52aa198e7cf80001f9ce236e33c61e134734287f', 'd364ffd7e241a1ee1a20aaec33e04fb7c309ebf8cad539513d667e876bc6fe3a'),
        ('new_cached', 256, 113, 456, 9, 0, 'dd252c16407a2a46d58a937a5ce8737925582ba31ce21634ffa9a476225e9406', '678dcfcc474efda76e518ddd14ecbccfdef9088725de88ac90f0e6b1515cf420'),
        ('new_key', 128, 49, 146, 2, 1, '3bc2cd531db5a0fbcc421af355de823aecb3d27ac52bdc0ba078160edc0e1429', '3cccfee8f3d6de3cbd862414024c591e807d77d6120399e85ac7755773685e31'),
        ('new_key', 192, 49, 146, 2, 1, '4d3de6f21a7d9560b85c713b3c45e1390357dccd9755df7631a00ae4942a228f', 'e6f83c9df054aef77501fc75fd7b8e816314557ce85109810108da95529d9d96'),
        ('new_key', 256, 49, 146, 2, 1, 'decfc7ab94a43e3a3b5e3c87474aee686899b52946925632237bdb744360c4b4', 'd56ebec0de47963983e57a0ecee2d05967c738998f14e0bb6f679866f063d795'),
    ]),
    ('1.99.1', 'abort'): policies([
        ('new_cached', 128, 92, 349, 6, 0, '188a8d90d49d5d044c9d406e9d1b33b129ef6c23f1f2d3e8bd8acf747e209cbf', '48996c9b8ef4341bed8cbbfccc9f6f4a0c66b766d973b5de7bafea3fd67a4abf'),
        ('new_cached', 192, 94, 365, 6, 0, '3458f3fe47c509ff9980813e3b8fee5bb8d8f6e336c1adb31f573cfe32857c0a', '4d4e0d848153831c61fc4e8ac30f321c4bd1ab93bc6f9b0b8d4219cfc138dd6e'),
        ('new_cached', 256, 96, 381, 6, 0, '6516db7c83f3ef975780054288b6d469b3290f777d7166cad54f0e5008d80d13', 'cb5d9bfcf35351793861683a83c9192ee349c9af161578710d2fa9c4466fa253'),
        ('new_key', 128, 49, 146, 2, 1, 'a776c1adab22bf3e34634aff6dec5f0870d076351454f1d15f5dd5001b9fcb56', '03f64698a7dcf53d3af891eec084fc7319dc912cb3af13eebae24f6fd6ed414a'),
        ('new_key', 192, 49, 146, 2, 1, '9605e5d4ba3720afc83345a6b722b42e4187e540feeb55fdd98d6bee4d9c1b3a', '0bd1c7deaa393e63e976a0e2e89d5df7b9b0b918f24041ae8b9b0dba6425bbe0'),
        ('new_key', 256, 49, 146, 2, 1, '6027a895cf74db2c90ecd4a909c74ba31a44d19c80a778f223ffaf5baf1d08c0', '17db4570f60347ceeeae25312dde53bd43a0d35a01a314fa6c3400002697630d'),
    ]),
    ('1.99.1', 'unwind'): policies([
        ('new_cached', 128, 92, 349, 6, 0, '188a8d90d49d5d044c9d406e9d1b33b129ef6c23f1f2d3e8bd8acf747e209cbf', '48996c9b8ef4341bed8cbbfccc9f6f4a0c66b766d973b5de7bafea3fd67a4abf'),
        ('new_cached', 192, 94, 365, 6, 0, '3458f3fe47c509ff9980813e3b8fee5bb8d8f6e336c1adb31f573cfe32857c0a', '4d4e0d848153831c61fc4e8ac30f321c4bd1ab93bc6f9b0b8d4219cfc138dd6e'),
        ('new_cached', 256, 96, 381, 6, 0, '6516db7c83f3ef975780054288b6d469b3290f777d7166cad54f0e5008d80d13', 'cb5d9bfcf35351793861683a83c9192ee349c9af161578710d2fa9c4466fa253'),
        ('new_key', 128, 49, 146, 2, 1, 'a776c1adab22bf3e34634aff6dec5f0870d076351454f1d15f5dd5001b9fcb56', '03f64698a7dcf53d3af891eec084fc7319dc912cb3af13eebae24f6fd6ed414a'),
        ('new_key', 192, 49, 146, 2, 1, '9605e5d4ba3720afc83345a6b722b42e4187e540feeb55fdd98d6bee4d9c1b3a', '0bd1c7deaa393e63e976a0e2e89d5df7b9b0b918f24041ae8b9b0dba6425bbe0'),
        ('new_key', 256, 49, 146, 2, 1, '6027a895cf74db2c90ecd4a909c74ba31a44d19c80a778f223ffaf5baf1d08c0', '17db4570f60347ceeeae25312dde53bd43a0d35a01a314fa6c3400002697630d'),
    ]),
}
ROLES = {(role, bits): f'6aes{bits}{len(role)}{role}'
         for role in ('new_key', 'new_cached') for bits in (128, 192, 256)}
ROLES.update({('destroy_key', 128): '6aes12811destroy_key', ('destroy_block', 0): '13destroy_block'})


def candidates(table):
    selected = {}
    for line in table.splitlines():
        if '30brynja_aes_accelerated_fixture9lifecycle' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized lifecycle symbol row')
        address, size, name = match.groups()
        roles = [role for role, suffix in ROLES.items() if re.fullmatch(
            r'(?:_ZN30brynja_aes_accelerated_fixture9lifecycle' + suffix + r'17h[0-9a-f]{16}E|'
            r'_RNvNt' + ('' if role[0] == 'destroy_block' else 'Nt') +
            r'C\w+_30brynja_aes_accelerated_fixture9lifecycle' + suffix + ')', name)]
        require(len(roles) == 1, 'unrecognized lifecycle symbol')
        role = roles[0]
        require(role not in selected and int(size, 16) > 0, 'duplicate/empty lifecycle symbol')
        selected[role] = (name, int(address, 16), int(size, 16))
    require(set(selected) == set(ROLES), 'lifecycle symbol population changed')
    ordered = sorted(selected.values(), key=lambda row: row[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping lifecycle symbols')
    return selected


def constructor(lines, raw, sizes, row, image, targets, role, compiler, panic):
    require((compiler, panic) in POLICY and role in POLICY[compiler, panic], 'unreviewed constructor configuration')
    edges = {'zeroize', 'copy'}
    if role[0] == 'new_cached':
        edges.add('expand')
        if (compiler, panic) == ('1.90.0', 'unwind'):
            edges.add('resume')
    require(set(targets) == edges,
            'constructor call target population changed')
    require(len(raw) == row[2], 'constructor symbol extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets, tail_calls=('zeroize',))
    require(actual == POLICY[compiler, panic][role], 'constructor stream changed; explicit re-review required')
    return {'role': role[0], 'bits': role[1], **actual}


def destruction_template(row, clear, compiler, panic):
    require((compiler, panic) in POLICY, 'unreviewed destruction configuration')
    symbol, start, _ = row
    name, target, _ = clear
    def rel(end):
        delta = target - start - end
        require(-(2**31) <= delta < 2**31, 'destruction target out of rel32 range')
        return delta.to_bytes(4, 'little', signed=True)
    edge = f'jne 0x{target:x} <{name}>'
    if (compiler, panic) != ('1.99.1', 'unwind'):
        return (['testq %rdi, %rdi', edge, 'retq'],
                b'\x48\x85\xff\x0f\x85' + rel(9) + b'\xc3', [3, 6, 1])
    # The public explicit-clear selector remains in this compiler/profile.
    # Both branches preserve RSI (owned length) and RDI (owned pointer).
    return (['testl %edx, %edx', f'je 0x{start + 14:x} <{symbol}+0xe>',
             'testq %rdi, %rdi', edge, 'retq', 'testq %rdi, %rdi',
             f'je 0x{start + 13:x} <{symbol}+0xd>', f'jmp 0x{target:x} <{name}>'],
            b'\x85\xd2\x74\x0a\x48\x85\xff\x0f\x85' + rel(13) +
            b'\xc3\x48\x85\xff\x74\xfa\xe9' + rel(24), [2, 2, 3, 6, 1, 3, 2, 5])


def destruction(lines, raw, sizes, row, image, clear, compiler, panic):
    require(len(raw) == row[2], 'destruction symbol extent changed')
    loads = image_review.segments(image)
    pos = image_review.file_offset(loads, row[1], row[2], 5)
    image_review.file_offset(loads, clear[1], clear[2], 5)
    require(clear[1] + clear[2] <= row[1] or row[1] + row[2] <= clear[1], 'overlapping destruction target')
    require(image[pos:pos + len(raw)] == raw, 'destruction decoded bytes differ from executable')
    expected = destruction_template(row, clear, compiler, panic)
    require((lines, raw, sizes) == expected, 'destruction stream changed; explicit re-review required')
    return {'instructions': len(lines), 'symbol_bytes': len(raw), 'clear_edges': 2 if len(lines) == 8 else 1}


def mutations(check, lines, raw, sizes, row, image, *args):
    check(lines, raw, sizes, row, image, *args)
    rejected = 0
    for index in range(len(lines)):
        changed = list(lines)
        changed[index] = 'unreviewed-instruction'
        try:
            check(changed, raw, sizes, row, image, *args)
        except ValueError as error:
            require('stream changed' in str(error), 'text mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('lifecycle textual mutation accepted')
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    for index in range(len(raw)):
        altered = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        replaced = image[:pos] + altered + image[pos + len(raw):]
        try:
            check(lines, altered, sizes, row, replaced, *args)
        except ValueError as error:
            require(any(s in str(error) for s in ('stream changed', 'branch destination mismatch',
                    'call destination mismatch', 'unsupported call encoding', 'tail-call destination mismatch',
                    'unsupported tail-call encoding')), 'byte mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('lifecycle encoded mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed lifecycle configuration')
    dependencies = operations.inspect(table, assembly, image, compiler, panic, relocations)
    selected = candidates(table)
    helpers = secret.cached.candidates(table)
    expansions = secret.expansion_candidates(table, assembly, image)
    resume = (secret.cached.public.cleanup.resume_target(assembly, relocations, image)
              if (compiler, panic) == ('1.90.0', 'unwind') else None)
    constructors, destructors, rejected = [], [], 0
    for role, row in sorted(selected.items()):
        args = (*kernels.decode(assembly, row, TARGET), row, image)
        if role[0].startswith('new_'):
            targets = {r: helpers[r] for r in ('zeroize', 'copy')}
            if role[0] == 'new_cached':
                targets['expand'] = expansions['expand' + str(role[1])]
                if resume is not None:
                    targets['resume'] = resume
            args += (targets, role, compiler, panic)
            constructors.append(constructor(*args))
            rejected += mutations(constructor, *args)
        else:
            args += (helpers['zeroize'], compiler, panic)
            destructors.append({'role': role[0], **destruction(*args)})
            rejected += mutations(destruction, *args)
    expected = {('1.90.0', 'abort'): 1988, ('1.90.0', 'unwind'): 2264,
                ('1.99.1', 'abort'): 1988, ('1.99.1', 'unwind'): 2026}[compiler, panic]
    require(rejected == expected, 'lifecycle mutation population changed')
    return {'constructors': constructors, 'destruction_bodies': destructors,
            'rejected_lifecycle_mutations': rejected, 'operation_review': dependencies,
            'scope': 'x86 package-external constructors and retained merged destruction bodies, plus prior operation closure; all owner clear/drop routes exercised, not every fixture call site, ARM lifecycle, arbitrary downstream inlining, exception-table proof or spill erasure'}
