"""Bounded RV64 AES kernel analysis from ELF bytes, not disassembler prose.

Only the instructions used by these leaf routines are modeled. AES results are
opaque secret values: this checks control/address flow, bounds, initialization
and explicit scratch clearing, NOT AES correctness or hardware timing.
"""
from collections import Counter
import hashlib
import re
import struct

MASK = (1 << 64) - 1
SECRET = 'secret'
UNKNOWN = 'uninitialized'
SCRATCH = (5, 6, 7, 28, 29, 30, 31)


def require(ok, message):
    if not ok:
        raise ValueError('RV64 AES machine review: ' + message)


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode(raw):
    """Decode a deliberately small RV64I+C+scalar-AES subset; reject the rest."""
    rows = {}
    pc = 0
    while pc < len(raw):
        require(pc + 2 <= len(raw), 'truncated instruction')
        half = int.from_bytes(raw[pc:pc + 2], 'little')
        n = 4 if half & 3 == 3 else 2
        require(pc + n <= len(raw), 'truncated instruction')
        w = int.from_bytes(raw[pc:pc + n], 'little')
        inst = None
        if n == 2:
            quadrant, f = w & 3, w >> 13
            rd, rs = (w >> 7) & 31, (w >> 2) & 31
            imm = ((w >> 2) & 31) | ((w >> 12) & 1) << 5
            if quadrant == 1 and f in (0, 2) and rd != 0:
                inst = ('addi', rd, rd if f == 0 else 0, signed(imm, 6))
            elif quadrant == 2 and f == 0 and rd != 0 and imm != 0:
                inst = ('slli', rd, rd, imm)
            elif quadrant == 2 and w >> 12 == 8 and rd != 0:
                if rs != 0:
                    inst = ('add', rd, 0, rs)  # C.MV
                elif rd == 1:
                    inst = ('ret',)  # Only C.JR ra; no general indirect jump.
            elif quadrant == 1 and f in (6, 7):
                offset = (((w >> 12) & 1) << 8 | ((w >> 10) & 3) << 3
                          | ((w >> 5) & 3) << 6 | ((w >> 3) & 3) << 1
                          | ((w >> 2) & 1) << 5)
                inst = ('beq' if f == 6 else 'bne', 8 + ((w >> 7) & 7), 0,
                        pc + signed(offset, 9))
        else:
            op, rd, f, a, b, top = w & 127, (w >> 7) & 31, (w >> 12) & 7, (w >> 15) & 31, (w >> 20) & 31, w >> 25
            imm = w >> 20
            if op == 0x13:
                if f in (0, 4, 7):
                    inst = ({0: 'addi', 4: 'xori', 7: 'andi'}[f], rd, a, signed(imm, 12))
                elif f in (1, 5) and imm >> 6 == 0:
                    inst = ('slli' if f == 1 else 'srli', rd, a, imm)
                elif f == 1 and 0x310 <= imm <= 0x31a:
                    inst = ('aes64ks1i', rd, a, imm - 0x310)
                elif f == 1 and imm == 0x300:
                    inst = ('aes64im', rd, a)
            elif op == 0x33:
                if top == 0 and f in (0, 4, 6):
                    inst = ({0: 'add', 4: 'xor', 6: 'or'}[f], rd, a, b)
                elif f == 0 and top in (0x19, 0x1b, 0x1d, 0x1f):
                    inst = ({0x19: 'aes64es', 0x1b: 'aes64esm', 0x1d: 'aes64ds', 0x1f: 'aes64dsm'}[top], rd, a, b)
            elif op == 3 and f == 4:
                inst = ('lbu', rd, a, signed(imm, 12))
            elif op == 0x23 and f == 0:
                inst = ('sb', b, a, signed((w >> 25) << 5 | ((w >> 7) & 31), 12))
            elif op == 0x63 and f in (0, 1):
                offset = ((w >> 31) << 12 | ((w >> 7) & 1) << 11
                          | ((w >> 25) & 63) << 5 | ((w >> 8) & 15) << 1)
                inst = ('beq' if f == 0 else 'bne', a, b, pc + signed(offset, 13))
            elif w == 0x00008067:
                inst = ('ret',)
        require(inst is not None, f'unmodeled instruction at +{pc:x}: {w:0{n * 2}x}')
        rows[pc] = (n, inst)
        pc += n
    for _, inst in rows.values():
        if inst[0] in ('beq', 'bne'):
            require(inst[3] in rows, 'branch escapes body or enters instruction middle')
    return rows


def calculate(op, a, b):
    require(a != UNKNOWN and b != UNKNOWN, 'read of uninitialized register')
    if op == 'add' and isinstance(a, tuple) and type(b) is int:
        return (a[0], a[1] + signed(b & MASK, 64))
    if op == 'add' and isinstance(b, tuple) and type(a) is int:
        return calculate(op, b, a)
    require(not isinstance(a, tuple) and not isinstance(b, tuple), 'unmodeled pointer operation')
    if a == SECRET or b == SECRET:
        return SECRET
    require(type(a) is int and type(b) is int, 'unmodeled value')
    if op in ('sll', 'srl'):
        require(0 <= b < 64, 'invalid shift')
    return {'add': lambda: a + b, 'xor': lambda: a ^ b, 'or': lambda: a | b,
            'and': lambda: a & b, 'sll': lambda: a << b,
            'srl': lambda: (a & MASK) >> b}[op]() & MASK


def execute(rows, kind, bits, inverse=0):
    """One finite public path, with all input bytes abstracted as secret."""
    require(kind in ('expand', 'transform') and bits in (128, 192, 256)
            and inverse in (0, 1), 'unknown kernel configuration')
    k, extent = bits // 8, (bits // 32 + 7) * 16
    source = 'key' if kind == 'expand' else 'state'
    sizes = {source: k if kind == 'expand' else 16, 'schedule': extent}
    memory = {(name, i): SECRET if name != 'schedule' or kind == 'transform' else UNKNOWN
              for name, size in sizes.items() for i in range(size)}
    registers = [UNKNOWN] * 32
    registers[0], registers[10], registers[11], registers[12] = 0, (source, 0), ('schedule', 0), inverse
    reads, writes, aes = Counter(), Counter(), Counter()
    visited, changed = set(), set()
    pc = 0
    for steps in range(20000):
        require(pc in rows, 'execution escaped kernel')
        visited.add(pc)
        n, inst = rows[pc]
        op, *args = inst
        next_pc = pc + n
        if op == 'ret':
            required = SCRATCH if kind == 'expand' else (*SCRATCH[:-1], 12)
            require(all(registers[r] == 0 for r in required), 'scratch register not cleared')
            require(all(registers[r] != SECRET for r in changed), 'secret remains in register')
            destination = 'schedule' if kind == 'expand' else 'state'
            require(set(writes) == {(destination, i) for i in range(sizes[destination])}
                    and all(v == 1 for v in writes.values()), 'wrong destination write population')
            if kind == 'expand':
                require({i: count for (name, i), count in reads.items() if name == 'key'}
                        == {i: 1 for i in range(k)} and sum(reads.values()) == 2 * extent - k,
                        'wrong expansion read population')
                require(aes == {'aes64ks1i': {128: 10, 192: 8, 256: 13}[bits]}, 'wrong expansion AES population')
            else:
                require(reads == Counter({(name, i): 1 for name, size in sizes.items() for i in range(size)}),
                        'wrong state/schedule read population')
                middle = bits // 32 + 5
                expected = {'aes64dsm': 2 * middle, 'aes64ds': 2, 'aes64im': 2 * middle} if inverse else {
                    'aes64esm': 2 * middle, 'aes64es': 2}
                require(aes == expected, 'wrong round AES population')
            return {'steps': steps + 1, 'reads': sum(reads.values()), 'writes': sum(writes.values()),
                    'aes_instructions': dict(aes)}, visited
        if op in ('beq', 'bne'):
            a, b, target = args
            require(type(registers[a]) is int and type(registers[b]) is int,
                    'branch uses secret, pointer or uninitialized value')
            equal = registers[a] == registers[b]
            if equal == (op == 'beq'):
                next_pc = target
        elif op in ('lbu', 'sb'):
            reg, base, offset = args
            pointer = registers[base]
            require(isinstance(pointer, tuple), 'memory address is secret or uninitialized')
            name, index = pointer[0], pointer[1] + offset
            require(name in sizes and 0 <= index < sizes[name], 'out-of-bounds memory access')
            location = (name, index)
            if op == 'lbu':
                require(memory[location] != UNKNOWN, 'read before schedule initialization')
                value = memory[location]
                reads[location] += 1
            else:
                require(name == ('schedule' if kind == 'expand' else 'state'), 'write to read-only input')
                value = registers[reg]
                require(value == SECRET or type(value) is int, 'uninitialized/pointer store')
                memory[location] = SECRET if value == SECRET else value & 255
                writes[location] += 1
        else:
            reg, a, *rest = args
            if op.startswith('aes64'):
                values = [registers[a]]
                if op not in ('aes64ks1i', 'aes64im'):
                    values.append(registers[rest[0]])
                require(all(v == SECRET or type(v) is int for v in values), 'invalid AES operand')
                if op == 'aes64ks1i':
                    require(rest == [10], 'unexpected expansion immediate')
                value = SECRET
                aes[op] += 1
            else:
                immediate = op in ('addi', 'xori', 'andi', 'slli', 'srli')
                b = rest[0] if immediate else registers[rest[0]]
                operation = {'addi': 'add', 'xori': 'xor', 'andi': 'and',
                             'slli': 'sll', 'srli': 'srl'}.get(op, op)
                value = calculate(operation, registers[a], b)
        if op not in ('beq', 'bne', 'sb'):
            require(reg in (*SCRATCH, 12), 'write outside declared scratch registers')
            registers[reg] = value
            changed.add(reg)
        pc = next_pc
    raise ValueError('RV64 AES machine review: execution step bound exceeded')


def mapped(image, address, size):
    require(len(image) >= 64 and image[:7] == b'\x7fELF\x02\x01\x01', 'wrong ELF format')
    kind, machine, version = struct.unpack_from('<HHI', image, 16)
    offset = struct.unpack_from('<Q', image, 32)[0]
    header, stride, count = struct.unpack_from('<HHH', image, 52)
    require(kind in (2, 3) and machine == 243 and version == 1 and header == 64
            and stride == 56 and 0 < count < 65535 and offset >= 64
            and offset + stride * count <= len(image), 'invalid RV64 ELF program table')
    require(address >= 0 and 0 < size <= 16384 and address + size < 2**64, 'invalid symbol extent')
    loads, matches = [], []
    for i in range(count):
        kind, flags, pos, base, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', image, offset + i * stride)
        if kind != 1:
            continue
        require(filesz <= memsz and pos + filesz <= len(image) and base + memsz < 2**64, 'invalid ELF load extent')
        loads.append((base, memsz))
        if base <= address and address + size <= base + filesz and flags == 5:
            matches.append(pos + address - base)
    loads.sort()
    require(loads and all(a + n <= b for (a, n), (b, _) in zip(loads, loads[1:])), 'overlapping ELF loads')
    require(len(matches) == 1, 'body lacks unique read/execute mapping')
    return matches[0]


def select(nm):
    rows = []
    for line in nm.splitlines():
        if '17brynja_crypto_cpu3aes7riscv64' not in line:
            continue
        legacy = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] '
                              r'(_ZN17brynja_crypto_cpu3aes7riscv64(6expand|9transform)17h[0-9a-f]{16}E)', line)
        if legacy is not None:
            rows.append((legacy[3], int(legacy[1], 16), int(legacy[2], 16),
                         'expand' if legacy[4] == '6expand' else 'transform', None))
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] '
                             r'(_RINvNtNtC\w+_17brynja_crypto_cpu3aes7riscv64'
                             r'(6expandKj(10|18|20)_Kj(b0|d0|f0)|9transformKj(b|d|f))_EB\w+_)', line)
        require(match is not None, 'unrecognized RV64 kernel symbol')
        if match[5]:
            bits = int(match[5], 16) * 8
            require(int(match[6], 16) == (bits // 32 + 7) * 16, 'wrong expansion type extent')
            kind = 'expand'
        else:
            bits, kind = {11: 128, 13: 192, 15: 256}[int(match[7], 16)], 'transform'
        rows.append((match[3], int(match[1], 16), int(match[2], 16), kind, bits))
    require(len(rows) == 6 and Counter(r[3] for r in rows) == {'expand': 3, 'transform': 3}
            and len({r[0] for r in rows}) == 6, 'wrong six-kernel population')
    rows.sort(key=lambda r: r[1])
    require(all(n > 0 for _, _, n, _, _ in rows)
            and all(a[1] + a[2] <= b[1] for a, b in zip(rows, rows[1:])), 'overlapping kernel symbols')
    return rows


def inspect(nm, image):
    reports = []
    for symbol, start, size, kind, bits in select(nm):
        pos = mapped(image, start, size)
        raw = image[pos:pos + size]
        rows = decode(raw)
        matches = []
        # Legacy symbol mangling omits const generics. Accept exactly one width
        # by its full bounded access and operation populations, never its order.
        for candidate in ((bits,) if bits is not None else (128, 192, 256)):
            try:
                paths = [execute(rows, kind, candidate, inverse)[0]
                         for inverse in ((0, 1) if kind == 'transform' else (0,))]
                matches.append((candidate, paths))
            except ValueError:
                if bits is not None:
                    raise
        require(len(matches) == 1, 'legacy kernel does not uniquely match a complete width contract')
        bits, paths = matches[0]
        reports.append({'symbol': symbol, 'kind': kind, 'bits': bits, 'symbol_bytes': size,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'decoded_instructions': len(rows), 'paths': paths})
    require({(r['kind'], r['bits']) for r in reports} == {
        (kind, bits) for kind in ('expand', 'transform') for bits in (128, 192, 256)}, 'wrong kernel width population')
    return {'kernels': reports, 'scope': 'six leaf bodies; public branch/address flow, bounded initialized byte accesses and scratch clearing; '
            'AES arithmetic opaque; callers, spills, timing, physical faults and native admission not qualified'}
