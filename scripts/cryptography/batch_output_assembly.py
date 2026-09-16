"""Closed x86-64 SysV/AArch64 output Drop interpreter, not a general ISA proof."""
import itertools
import re

from batch_cleanup_flow import require
from batch_output_flow import equal as symbolic_equal
from batch_output_machine import Machine, offset


def equal(left, right):
    require(all(type(value) is int or (isinstance(value, tuple) and value[0] in
                ('owner', 'destination', 'length')) for value in (left, right)),
            'no branch on opaque register or stack address')
    return symbolic_equal(left, right)


def parse(body):
    code, labels, ended = [], {}, False
    for raw in body.splitlines():
        line = raw.split('//', 1)[0].strip()
        if line == '.cfi_endproc':
            ended = True
            break
        if not line or line.startswith('.cfi_') or re.fullmatch(r'\.p2align\s+\d+', line):
            continue
        if re.fullmatch(r'\.Lfunc_end\d+:', line) or re.fullmatch(r'\.size\s+\S+,\s+\S+', line):
            continue
        if re.fullmatch(r'\.?LBB[\w]+:', line):
            require(line[:-1] not in labels, 'unique assembly label')
            labels[line[:-1]] = len(code)
            continue
        parts = line.split(None, 1)
        # Commas within addressing operands are not instruction separators.
        args = re.split(r',\s*(?![^\[\]()]*[\])])', parts[1]) if len(parts) == 2 else []
        code.append((parts[0], args))
    require(ended and code, 'bounded assembly function extent')
    return code, labels


def arm_step(m, op, a):
    if op == 'mov' and len(a) == 2:
        m.write(a[0], m.operand(a[1]))
    elif op in ('add', 'sub') and len(a) == 3:
        amount = m.operand(a[2])
        require(type(amount) is int, 'concrete Arm stride')
        m.write(a[0], offset(m.read(a[1]), amount if op == 'add' else -amount))
    elif op in ('stp', 'ldp', 'str', 'ldr', 'ldur'):
        pair, store = op in ('stp', 'ldp'), op in ('stp', 'str')
        n = 2 if pair else 1
        require(len(a) in (n + 1, n + 2), 'exact Arm memory operands')
        registers, address = a[:n], a[n]
        require(all(re.fullmatch(r'x\d+', r) for r in registers), 'full-width Arm load/save')
        if address.endswith('!'):
            require(store and len(a) == n + 1 and address.startswith('[sp,'), 'reviewed stack preindex')
            m.write('sp', m.address(address[:-1]))
            address = '[sp]'
        pointer = m.address(address)
        for i, register in enumerate(registers):
            location = offset(pointer, i * 8)
            if store:
                m.store(location, m.read(register))
            else:
                m.write(register, m.load(location))
        if len(a) == n + 2:
            require(not store and address == '[sp]', 'reviewed stack postindex')
            m.write('sp', offset(m.read('sp'), m.operand(a[-1])))
    else:
        raise ValueError('unreviewed Arm output instruction: ' + repr((op, a)))


def x86_step(m, op, a):
    if op in ('movq', 'movl') and len(a) == 2:
        require(m.register(a[1])[1] == (op == 'movl'), 'exact move destination width')
        if op == 'movq' and a[0].startswith('%'):
            require(not m.register(a[0])[1], 'full-width source register')
        m.write(a[1], m.operand(a[0]))
    elif op == 'leaq' and len(a) == 2:
        require(not m.register(a[1])[1], 'full pointer destination')
        m.write(a[1], m.address(a[0]))
    elif op in ('addq', 'subq') and len(a) == 2:
        amount = m.operand(a[0])
        require(type(amount) is int and not m.register(a[1])[1], 'full concrete x86 stride')
        m.write(a[1], offset(m.read(a[1]), amount if op == 'addq' else -amount))
        m.flag = None
    elif op == 'xorl' and len(a) == 2 and a[0] == a[1]:
        require(m.register(a[0])[1], '32-bit xor zero')
        m.write(a[0], 0)
        m.flag = True
    elif op in ('cmpq', 'testq') and len(a) == 2:
        require(all(not m.register(arg)[1] for arg in a if arg.startswith('%')), 'full comparison width')
        if op == 'testq':
            require(a[0] == a[1], 'only self zero test')
            m.flag = equal(m.operand(a[0]), 0)
        else:
            m.flag = equal(m.operand(a[0]), m.operand(a[1]))
    elif op in ('pushq', 'popq') and len(a) == 1:
        require(not m.register(a[0])[1], 'full stack register')
        if op == 'pushq':
            value = m.read(a[0])
            m.write('%rsp', offset(m.read('%rsp'), -8))
            m.store(m.read('%rsp'), value)
        else:
            m.write(a[0], m.load(m.read('%rsp')))
            m.write('%rsp', offset(m.read('%rsp'), 8))
    else:
        raise ValueError('unreviewed x86 output instruction: ' + repr((op, a)))


def execute(code, labels, shapes, metadata, arm):
    m, pc, visited = Machine(shapes, arm), 0, set()
    for _ in range(512):
        require(0 <= pc < len(code), 'valid assembly successor')
        visited.add(pc)
        op, a = code[pc]
        pc += 1
        if op in (('bl',) if arm else ('callq',)) and len(a) == 1:
            m.clear(a[0])
        elif op in (('b',) if arm else ('jmp', 'jmpq')) and len(a) == 1:
            if a[0] in labels:
                pc = labels[a[0]]
            else:
                m.restored()
                m.clear(a[0])
                m.finish(metadata)
                return visited
        elif not arm and op in ('je', 'jne') and len(a) == 1:
            require(type(m.flag) is bool and a[0] in labels, 'known x86 flags/successor')
            if m.flag == (op == 'je'):
                pc = labels[a[0]]
        elif arm and op in ('cbz', 'cbnz') and len(a) == 2:
            require(a[1] in labels, 'known Arm successor')
            if equal(m.read(a[0]), 0) == (op == 'cbz'):
                pc = labels[a[1]]
        elif op == ('ret' if arm else 'retq') and not a:
            m.restored()
            m.finish(metadata)
            return visited
        elif arm:
            arm_step(m, op, a)
        else:
            x86_step(m, op, a)
    raise ValueError('assembly output loop exceeds reviewed bound')


def check(body, capacity, metadata, arm):
    code, labels = parse(body)
    visited, count = set(), 0
    for shapes in itertools.product(range(3), repeat=capacity):
        visited.update(execute(code, labels, shapes, metadata, arm))
        count += 1
    require(visited == set(range(len(code))), 'no hidden/unvisited assembly instructions')
    return count
