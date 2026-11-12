"""Bounded AArch64 ELF volatile-clear and retained destruction-body review.

Exact instruction words and operands, including local branch offsets. Only the
external B immediate is relocated, to the separately checked clear body. This
does not review constructors, operation callers or every downstream call site.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('arm_cleanup_kernels',
        Path(__file__).with_name('aes_accelerated_linked_kernels.py'))
kernels = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernels)
require = kernels.require
TARGET = 'aarch64-unknown-linux-musl'
COMPILERS = ('1.90.0', '1.99.1')
ROLES = ('zeroize', 'destroy_key', 'destroy_block')


def candidates(table):
    patterns = {
        'zeroize': r'(?:_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h[0-9a-f]{16}E|'
                   r'_RNvNtC\w+_11brynja_core22secret_memory_volatile23zeroize_region_volatile)',
        'destroy_key': r'(?:_ZN30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key17h[0-9a-f]{16}E|'
                       r'_RNvNtNtC\w+_30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key)',
        'destroy_block': r'(?:_ZN30brynja_aes_accelerated_fixture9lifecycle13destroy_block17h[0-9a-f]{16}E|'
                         r'_RNvNtC\w+_30brynja_aes_accelerated_fixture9lifecycle13destroy_block)',
    }
    selected = {}
    for line in table.splitlines():
        if not ('zeroize_region_volatile' in line or
                ('30brynja_aes_accelerated_fixture9lifecycle' in line and 'destroy' in line)):
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ARM cleanup symbol row')
        address, size, name = match.groups()
        roles = [role for role, pattern in patterns.items() if re.fullmatch(pattern, name)]
        require(len(roles) == 1, 'unrecognized ARM cleanup symbol')
        role = roles[0]
        require(role not in selected, 'duplicate ARM cleanup symbol')
        selected[role] = name, int(address, 16), int(size, 16)
    require(set(selected) == set(ROLES), 'ARM cleanup symbol population changed')
    disjoint(selected.values())
    return selected


def disjoint(rows):
    ordered = sorted(rows, key=lambda row: row[1])
    require(all(a % 4 == 0 and n > 0 and n % 4 == 0 for _, a, n in ordered),
            'invalid ARM cleanup symbol extent')
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])),
            'overlapping ARM cleanup symbols')


def template(role, compiler, panic, row, clear=None):
    require(role in ROLES and compiler in COMPILERS and panic in ('abort', 'unwind'),
            'unreviewed ARM cleanup configuration')
    symbol, start, _ = row
    if role == 'zeroize':
        words = ([(0xb4000081, 'cbz x1, @+10'), (0xf1000421, 'subs x1, x1, #1'),
                  (0x3800141f, 'strb wzr, [x0], #1'), (0x54ffffc1, 'b.ne @+4'),
                  (0xd65f03c0, 'ret')] if compiler == '1.90.0' else
                 [(0xb40000a1, 'cbz x1, @+14'), (0xf1000421, 'subs x1, x1, #1'),
                  (0x3900001f, 'strb wzr, [x0]'), (0x91000400, 'add x0, x0, #1'),
                  (0x54ffffa1, 'b.ne @+4'), (0xd65f03c0, 'ret')])
    elif (compiler, panic) == ('1.99.1', 'unwind'):
        words = [(0x36000062, 'tbz w2, #0, @+c'), (0xb4000080, 'cbz x0, @+14'),
                 (None, 'b @clear'), (0xb4000040, 'cbz x0, @+14'),
                 (None, 'b @clear'), (0xd65f03c0, 'ret')]
    else:
        words = [(0xb4000040, 'cbz x0, @+8'), (None, 'b @clear'), (0xd65f03c0, 'ret')]
    lines, raw = [], bytearray()
    for word, line in words:
        if word is None:
            require(clear is not None, 'missing ARM clear target')
            name, address, _ = clear
            delta = address - (start + len(raw))
            require(delta % 4 == 0 and -(2**27) <= delta < 2**27, 'ARM clear target out of B range')
            word = 0x14000000 | ((delta // 4) & 0x03ffffff)
            line = f'b 0x{address:x} <{name}>'
        line = re.sub(r'@\+([0-9a-f]+)', lambda m:
                      f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', line)
        lines.append(line)
        raw.extend(word.to_bytes(4, 'little'))
    return lines, bytes(raw), [4] * len(lines)


def check(lines, raw, sizes, row, image, role, compiler, panic, clear=None):
    rows = [row] if role == 'zeroize' else [row, clear] if clear is not None else []
    require(rows, 'missing ARM clear target')
    disjoint(rows)
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    if role != 'zeroize':
        kernels.mapped(image, TARGET, clear[1], clear[2])
    require(len(raw) == row[2] and image[pos:pos + row[2]] == raw,
            'ARM cleanup decoded bytes differ from executable')
    require((lines, raw, sizes) == template(role, compiler, panic, row, clear),
            'ARM cleanup stream changed; explicit re-review required')
    return {'role': role, 'instructions': len(lines), 'symbol_bytes': len(raw)}


def mutations(lines, raw, sizes, row, image, *args):
    check(lines, raw, sizes, row, image, *args)
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    count = 0
    for index in range(len(lines) + len(raw)):
        altered_lines, altered_raw, altered_image = list(lines), raw, image
        if index < len(lines):
            altered_lines[index] = 'unreviewed-instruction'
        else:
            i = index - len(lines)
            altered_raw = raw[:i] + bytes([raw[i] ^ 1]) + raw[i + 1:]
            altered_image = image[:pos] + altered_raw + image[pos + len(raw):]
        try:
            check(altered_lines, altered_raw, sizes, row, altered_image, *args)
        except ValueError as error:
            require('ARM cleanup stream changed' in str(error), 'cleanup mutation rejected for unrelated reason')
            count += 1
        else:
            raise ValueError('ARM cleanup mutation accepted')
    return count


def inspect(table, assembly, image, compiler, panic, admission):
    require(compiler in COMPILERS and panic in ('abort', 'unwind') and admission in ('static', 'hosted'),
            'unreviewed ARM cleanup configuration')
    # Preserve the independent round-kernel review; never replace its evidence
    # with the cleanup checks or accept a check of branch targets by name only.
    dependency = kernels.inspect(table, assembly, image, TARGET)
    selected = candidates(table)
    disjoint([*selected.values(), *kernels.select(table, TARGET)])
    reports, rejected = [], 0
    for role in ROLES:  # Clear implementation is checked before its callers.
        row = selected[role]
        args = (*kernels.decode(assembly, row, TARGET), row, image, role, compiler, panic,
                None if role == 'zeroize' else selected['zeroize'])
        reports.append(check(*args))
        rejected += mutations(*args)
    expected = 55 if compiler == '1.90.0' else 90 if panic == 'unwind' else 60
    require(rejected == expected, 'ARM cleanup mutation population changed')
    return {'bodies': reports, 'rejected_cleanup_mutations': rejected, 'kernel_review': dependency,
            'scope': 'AArch64 ELF volatile clear and two retained destruction bodies, plus round kernels; '
                     'not constructors, operation callers, every fixture call site, arbitrary inlining, '
                     'native hardware, exception-table proof or spill/register erasure'}
