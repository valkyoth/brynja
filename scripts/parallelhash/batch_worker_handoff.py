"""Local machine handoff from the reviewed stack-backed Storage owner.

Identify the unique empty Vec header (capacity=0, dangling base=1) independently
of cleanup calls; require it to dominate worker creation. On normal returning
paths, validate full-width field loads/address construction into cleanup ABI
registers inside a single-entry, call-free suffix. This is NOT a proof of all
preceding memory writes, aliases, allocation provenance or exception recovery.
Valid compiler-selected Vec layout and stack ownership remain assumptions.
"""
import re

import batch_worker_machine as machine
from batch_worker_machine import require


def stack_offset(operand, arm):
    pattern = r'\[sp(?:, #(-?\d+))?\]' if arm else r'(-?\d+)?\(%rsp\)'
    match = re.fullmatch(pattern, operand)
    return int(match[1] or 0) if match else None


def successors(code, labels, symbols, noreturn, arm):
    edges = {}
    for pc, (op, args) in enumerate(code):
        if op in ('ret', 'retq', 'brk', 'ud2') or symbols[pc] in noreturn:
            edges[pc] = ()
        elif op == ('b' if arm else 'jmp'):
            edges[pc] = (labels[args[0]],)
        else:
            branch = op in (machine.machine.ARM_BRANCH | {'cbz', 'cbnz', 'tbz', 'tbnz'}
                            if arm else machine.machine.X86_BRANCH)
            edges[pc] = (pc + 1, labels[args[-1]]) if branch else (pc + 1,)
    return edges


def reaches(edges, start, destination, blocked=None):
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc == blocked or pc in seen:
            continue
        if pc == destination:
            return True
        seen.add(pc)
        pending.extend(edges.get(pc, ()))
    return False


def reachable(edges, start):
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc not in seen:
            seen.add(pc)
            pending.extend(edges.get(pc, ()))
    return seen


def owner(code, edges, spawn, arm):
    candidates = []
    for pc, (op, args) in enumerate(code):
        if not arm and op == 'movq' and len(args) == 2 and args[0] == '$0':
            offset = stack_offset(args[1], False)
            if offset is not None and pc + 1 < len(code) and code[pc + 1] == (
                    'movq', ['$1', f'{offset + 8}(%rsp)']) and not any(
                        pc + 1 in targets for p, targets in edges.items() if p != pc):
                candidates.append((pc + 1, offset))
        elif arm and op == 'stp' and len(args) == 3 and args[0] == 'xzr':
            offset = stack_offset(args[2], True)
            if offset is None or not re.fullmatch(r'x\d+', args[1]):
                continue
            # Closed initializer suffix: mov wN,#1; optional compare; stp.
            source = 'w' + args[1][1:]
            for start in (pc - 1, pc - 2):
                if start >= 0 and code[start] == ('mov', [source, '#1']) and all(
                        step[0] == 'cmp' for step in code[start + 1:pc]):
                    if all(edges[i] == (i + 1,) and not any(i in targets for p, targets in edges.items() if p != i - 1)
                           for i in range(start + 1, pc + 1)):
                        candidates.append((pc, offset))
    require(len(candidates) == 1, 'one reviewed empty stack Storage header')
    site, offset = candidates[0]
    require(reaches(edges, 0, site) and not reaches(edges, 0, spawn, site),
            'original stack header initialization dominates worker creation')
    return site, offset


def stable_frame(code, edges, initial, sites, arm):
    reverse = {}
    for pc, targets in edges.items():
        for target in targets:
            reverse.setdefault(target, []).append(pc)
    ancestors = set().union(*(reachable(reverse, site) for site in sites))
    for pc in reachable(edges, initial + 1) & ancestors:
        op, args = code[pc]
        if arm:
            # Including pre/post-indexed stack memory operands. Calls must
            # restore SP under the separately assumed ordinary-return ABI.
            changed = (bool(args) and args[0] in ('sp', 'wsp')) or any(
                arg.startswith('[sp') and (arg.endswith('!') or i != len(args) - 1)
                for i, arg in enumerate(args))
        else:
            changed = op in ('pushq', 'popq') or (bool(args) and args[-1] in (
                '%rsp', '%esp', '%sp', '%spl'))
            if op == 'lock' and re.search(r'%(?:rsp|esp|sp|spl)\b', ' '.join(args)):
                changed = True  # Includes read/write xadd sources; no stack-lock forms reviewed.
        require(not changed, 'original owner frame remains stable before cleanup')


def register(token, arm):
    if arm:
        match = re.fullmatch(r'([xw])(\d+)', token)
        return ('x' + match[2], match[1] == 'x') if match else (None, False)
    aliases = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
               'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp'}
    if re.fullmatch(r'%r(?:[abcd]x|[sb]p|[sd]i|\d+)', token):
        return token, True
    if token.removeprefix('%') in aliases:
        return '%' + aliases[token[1:]], False
    match = re.fullmatch(r'%(r\d+)[dwb]', token)
    return ('%' + match[1], False) if match else (None, False)


def prefix(code, start, end, root, arm):
    values = {}
    def read(reg):
        name, wide = register(reg, arm)
        return values.get(name) if wide else None
    def write(reg, value):
        name, wide = register(reg, arm)
        require(name is not None and name not in ('%rsp',), 'reviewed argument register destination')
        values[name] = value if wide else None
    for op, args in code[start:end]:
        if not arm and op in ('movq', 'movl') and len(args) == 2:
            offset = stack_offset(args[0], False)
            value = ('field', offset) if offset is not None and op == 'movq' else read(args[0])
            if register(args[1], False)[0]:
                write(args[1], value if op == 'movq' else None)
            else:
                # Unrelated spills are common; no owner field may be overwritten
                # during the handoff. Unknown-address writes are not accepted.
                destination = stack_offset(args[1], False)
                require(destination is not None and (destination + (8 if op == 'movq' else 4) <= root or
                        destination >= root + 24), 'no handoff owner overwrite')
        elif not arm and op == 'leaq' and len(args) == 2:
            offset = stack_offset(args[0], False)
            require(offset is not None, 'stack-relative owner address')
            write(args[1], ('address', offset))
        elif arm and op == 'mov' and len(args) == 2:
            write(args[0], read(args[1]))
        elif arm and op in ('ldr', 'ldp') and len(args) == (3 if op == 'ldp' else 2):
            offset = stack_offset(args[-1], True)
            require(offset is not None, 'stack-relative full-width argument load')
            for index, reg in enumerate(args[:-1]):
                write(reg, ('field', offset + 8 * index))
        elif arm and op == 'add' and len(args) == 3 and args[1] == 'sp':
            require(re.fullmatch(r'#\d+', args[2]), 'constant owner frame offset')
            write(args[0], ('address', int(args[2][1:])))
        else:
            raise ValueError('unreviewed argument-setup instruction')
    registers = ('x0', 'x1') if arm else ('%rdi', '%rsi')
    return tuple(read(r) for r in registers)


def inspect(body, clear, drop, noreturn, arm, apple):
    _, sites, _ = machine.inspect(body, clear, drop, noreturn, arm, apple)
    code, labels, raw = machine.machine.parse(body, arm)
    symbols = [machine.machine.call_symbol(op, args, arm, apple) for op, args in code]
    spawn = next(i for i, symbol in enumerate(symbols) if re.fullmatch(machine.inline.SPAWN, symbol or ''))
    edges = successors(code, labels, symbols, noreturn, arm)
    initial, root = owner(code, edges, spawn, arm)
    stable_frame(code, edges, initial, sites, arm)
    active = reachable(edges, spawn)
    results = {}
    for pc in sorted(sites):
        for start in range(max(0, pc - 8), pc):
            # Only local fallthrough may enter the suffix on a post-spawn
            # normal path. Pre-spawn empty-vector exits are a separate scope;
            # exception-table edges are not interpreted by this checker.
            if start not in active or any(edges[i] != (i + 1,) or any(
                    i + 1 in targets for p, targets in edges.items() if p != i and p in active)
                   for i in range(start, pc)):
                continue
            try:
                args = prefix(code, start, pc, root, arm)
            except ValueError:
                continue
            expected = (('field', root + 8), ('field', root + 16)) if symbols[pc] == clear else (('address', root), None)
            if args == expected or (symbols[pc] == drop and args[0] == expected[0]):
                results[pc] = start
                break
        require(pc in results, 'machine cleanup arguments are not the original stack owner fields')
    return root, results, raw


def check(row, panic):
    return inspect(*machine.context(row, panic))


def mutations(row, panic):
    args = machine.context(row, panic)
    root, sites, raw = inspect(*args)
    body, clear, drop, noreturn, arm, apple = args
    count = 0
    for pc in sorted(sites):
        source_line, _ = raw[pc]
        lines = body.splitlines(keepends=True)
        changes = []
        for injected in (('mov x0, xzr', 'mov x1, xzr') if arm else ('xorl %edi, %edi', 'xorl %esi, %esi')):
            symbol = machine.machine.call_symbol(*machine.machine.parse(body, arm)[0][pc], arm, apple)
            if symbol == drop and ('x1,' in injected or '%esi' in injected):
                continue
            changes.append(''.join(lines[:source_line] + [injected + '\n'] + lines[source_line:]))
        # Corrupt real emitted field offsets/address construction independently
        # of the LLVM input (which stays unchanged in this campaign).
        code = machine.machine.parse(body, arm)[0]
        for index in range(sites[pc], pc):
            op, operands = code[index]
            line_number, line = raw[index]
            if arm and op in ('ldr', 'ldp') and stack_offset(operands[-1], True) in (root + 8, root + 16):
                old = operands[-1]
                new = f'[sp, #{stack_offset(old, True) + 8}]'
            elif not arm and op in ('movq', 'leaq') and stack_offset(operands[0], False) in (root, root + 8, root + 16):
                old = operands[0]
                new = f'{stack_offset(old, False) + 8}(%rsp)'
            elif arm and op == 'add' and operands[1:] == ['sp', f'#{root}']:
                old, new = f'#{root}', f'#{root + 8}'
            else:
                continue
            changes.append(''.join(lines[:line_number] + [line.replace(old, new) + '\n'] + lines[line_number + 1:]))
        for changed in changes:
            try:
                inspect(changed, clear, drop, noreturn, arm, apple)
            except ValueError as error:
                require('machine cleanup arguments are not' in str(error), 'argument mutation violates the handoff')
                count += 1
            else:
                raise AssertionError('machine argument substitution survived')
    return root, len(sites), count
