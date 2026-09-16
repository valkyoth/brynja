"""Closed LLVM interpreter for Option<&mut [u8]> destructor iteration.

Each slot is absent, present-empty or present-nonempty. Nonempty lengths and
destination addresses remain distinct symbolic values, never sampled integers.
Only zero tests on those lengths are supported. Unknown instructions fail
closed; external clear is assumed to clear its exact argument without unwinding.
This checks emitted LLVM, not arbitrary LLVM or the compiler's machine lowering.
"""
import itertools
import re

from batch_cleanup_flow import require

VALUE = r'(?:%[\w.]+|\d+|null|true|false)'


def instruction(line):
    if line == 'ret void':
        return ('ret',)
    match = re.fullmatch(r'br label %([\w.]+)', line)
    if match:
        return ('jump', match[1])
    match = re.fullmatch(r'br i1 (' + VALUE + r'), label %([\w.]+), label %([\w.]+)', line)
    if match:
        return ('branch', *match.groups())
    match = re.fullmatch(r'(%[\w.]+) = phi (?:i64|ptr) (.*)', line)
    if match:
        pairs = re.findall(r'\[ (' + VALUE + r'), %([\w.]+) \]', match[2])
        require(pairs and ', '.join(f'[ {v}, %{b} ]' for v, b in pairs) == match[2], 'exact phi inputs')
        require(len({b for _, b in pairs}) == len(pairs), 'unique phi predecessor')
        return ('phi', match[1], dict((b, v) for v, b in pairs))
    match = re.fullmatch(r'(%[\w.]+) = getelementptr (?:inbounds(?: nuw)? )?i8, ptr (' + VALUE + r'), i64 (' + VALUE + ')', line)
    if match:
        return ('gep', *match.groups())
    match = re.fullmatch(r'(%[\w.]+) = add(?: nuw)?(?: nsw)? i64 (' + VALUE + '), (' + VALUE + ')', line)
    if match:
        return ('add', *match.groups())
    match = re.fullmatch(r'(%[\w.]+) = load (ptr|i64), ptr (' + VALUE + r'), align 8', line)
    if match:
        return ('load', *match.groups())
    match = re.fullmatch(r'(%[\w.]+) = icmp (eq|ne) (?:ptr|i64) (' + VALUE + '), (' + VALUE + ')', line)
    if match:
        return ('compare', *match.groups())
    match = re.fullmatch(r'(?:%[\w.]+ = )?(?:tail )?call (?:noundef )?i8 @([^\s(]+)\('
                         r'ptr (?:(?:noalias|nofree|noundef|nonnull|align [1-9][0-9]*) )*'
                         r'(' + VALUE + r'), i64 (?:noundef )?(' + VALUE + r')\)(?: #\d+)?', line)
    if match:
        require(re.fullmatch(r'(?:_ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E|'
                             r'_RNvNtCs[A-Za-z0-9_]+_11brynja_core13secret_memory18clear_owned_region)',
                             match[1]), 'exact clearing callee')
        return ('clear', match[2], match[3])
    raise ValueError('unreviewed output-destructor LLVM instruction: ' + line)


def parse(body):
    blocks, current = {}, None
    for raw in body.splitlines()[1:]:
        line = raw.split(';', 1)[0].strip().split(', !', 1)[0]
        if not line or line == '}':
            continue
        label = re.fullmatch(r'([\w.]+):', line)
        if label:
            current = label[1]
            require(current not in blocks, 'unique output block label')
            blocks[current] = []
        else:
            require(current is not None, 'instruction without block')
            blocks[current].append(instruction(line))
    require('start' in blocks, 'output destructor entry')
    for code in blocks.values():
        require(code and code[-1][0] in ('ret', 'jump', 'branch'), 'terminated output block')
        require(all(op[0] not in ('ret', 'jump', 'branch') for op in code[:-1]), 'no hidden instruction after terminator')
        past_phi = False
        for op in code:
            require(not (past_phi and op[0] == 'phi'), 'phi must precede block instructions')
            past_phi |= op[0] != 'phi'
    return blocks


def value(token, env):
    if token.startswith('%'):
        require(token in env, 'unknown output SSA value: ' + token)
        return env[token]
    return {'null': 0, 'true': True, 'false': False}.get(token, int(token) if token.isdigit() else None)


def equal(left, right):
    # Pointers/positive lengths have distinct symbolic identities. A comparison
    # to another positive length would require extra cases, so reject it.
    if isinstance(left, tuple) and left[0] == 'length':
        require(right == 0 or left == right, 'only zero/equal tests on symbolic length')
    if isinstance(right, tuple) and right[0] == 'length':
        require(left == 0 or left == right, 'only zero/equal tests on symbolic length')
    return left == right


def execute(blocks, shapes, metadata):
    env = {'%self': ('owner', 0)}
    block, previous, cleared, visited = 'start', None, [], set()
    for _ in range(256):
        require(block in blocks, 'missing output successor')
        visited.add(block)
        code = blocks[block]
        phis = {}
        for op in code:
            if op[0] == 'phi':
                require(previous in op[2], 'phi missing actual predecessor')
                phis[op[1]] = value(op[2][previous], env)
        env.update(phis)
        for op in code:
            kind = op[0]
            if kind == 'phi':
                continue
            if kind in ('gep', 'add'):
                left, right = value(op[2], env), value(op[3], env)
                require(type(right) is int and right >= 0, 'exact nonnegative stride')
                if kind == 'gep':
                    require(isinstance(left, tuple) and left[0] == 'owner', 'only owner-relative pointer arithmetic')
                    env[op[1]] = ('owner', left[1] + right)
                else:
                    require(type(left) is int and 0 <= left + right < 2**64, 'no symbolic/overflowing stride')
                    env[op[1]] = left + right
            elif kind == 'load':
                pointer = value(op[3], env)
                require(isinstance(pointer, tuple) and pointer[0] == 'owner', 'load must derive from owner')
                offset = pointer[1]
                slot, field = divmod(offset, 16)
                require(0 <= slot < len(shapes), 'load within full destination table')
                if op[2] == 'ptr':
                    require(field == 0, 'destination pointer field')
                    env[op[1]] = 0 if shapes[slot] == 0 else ('destination', slot)
                else:
                    require(field == 8 and shapes[slot] != 0, 'length loaded only from present destination')
                    env[op[1]] = 0 if shapes[slot] == 1 else ('length', slot)
            elif kind == 'compare':
                result = equal(value(op[3], env), value(op[4], env))
                env[op[1]] = result if op[2] == 'eq' else not result
            elif kind == 'clear':
                cleared.append((value(op[1], env), value(op[2], env)))
            elif kind == 'ret':
                expected = [(('destination', i), ('length', i)) for i, shape in enumerate(shapes) if shape == 2]
                expected += [(('owner', offset), width) for offset, width in metadata]
                require(cleared == expected, 'all present nonempty outputs clear exactly once, then metadata')
                return visited
            elif kind in ('jump', 'branch'):
                successor = op[1]
                if kind == 'branch':
                    condition = value(op[1], env)
                    require(type(condition) is bool, 'boolean output branch')
                    successor = op[2] if condition else op[3]
                previous, block = block, successor
            else:
                raise ValueError('unknown output interpreter opcode')
    raise ValueError('output iteration did not terminate within the reviewed bound')


def check(body, capacity, metadata):
    blocks = parse(body)
    visited, cases = set(), 0
    for shapes in itertools.product(range(3), repeat=capacity):
        visited.update(execute(blocks, shapes, metadata))
        cases += 1
    require(visited == set(blocks), 'no unvisited output-destructor blocks')
    return cases
