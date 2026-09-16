"""Conservative register/direct-stack facts, under explicit no-hidden-alias ABI.

Track full-width copies and known stack addresses; kill facts on narrow,
arithmetic, partial/overlapping stores and ABI clobbers. Unknown-address writes
and callee memory effects are NOT a whole-memory alias analysis: they must not
modify the tracked private spill cells. That reviewed ownership/callee contract
is an assumption, not proved here. No flags, predicate or exception semantics.
"""
import re

from batch_worker_handoff import register, require

LOADS = set('ldar ldarb ldapr ldaprb ldapur ldp ldr ldrb ldrh ldur ldurh'.split())
STORES = set('stlr stlur stp str strb strh stur sturb sturh'.split())
READ_ONLY = set('cmp ccmp cmn tst dmb'.split())


def width(reg, op):
    if op.endswith('b'):
        return 1
    if op.endswith('h'):
        return 2
    return 16 if reg.startswith(('q', 'v')) else 8 if reg.startswith('x') else 4


def step(op, args, facts):
    values = dict(facts)
    def read(reg):
        name, wide = register(reg, True)
        return values.get(name) if wide else None
    def write(reg, value=None):
        name, wide = register(reg, True)
        if name:
            values.pop(name, None)
            if wide and value is not None:
                values[name] = value
    def address(operand):
        match = re.fullmatch(r'\[(sp|x\d+)(?:, #(-?\d+))?\]!?', operand)
        if not match:
            return None
        base = ('stack', 0) if match[1] == 'sp' else read(match[1])
        return base[1] + int(match[2] or 0) if base and base[0] == 'stack' else None
    def invalidate(offset, size):
        for key in list(values):
            if isinstance(key, int) and key < offset + size and offset < key + 8:
                del values[key]
    if op in ('bl', 'blr'):
        for i in (*range(19), 30):
            values.pop('x' + str(i), None)
    elif op == 'mov' and len(args) == 2:
        write(args[0], ('stack', 0) if args[1] == 'sp' else read(args[1]))
    elif op in ('add', 'sub') and len(args) == 3 and re.fullmatch(r'#\d+', args[2]):
        source = ('stack', 0) if args[1] == 'sp' else read(args[1])
        offset = int(args[2][1:]) * (1 if op == 'add' else -1)
        write(args[0], ('stack', source[1] + offset) if source and source[0] == 'stack' else None)
    elif op in LOADS | STORES:
        indices = [i for i, arg in enumerate(args) if arg.startswith('[')]
        require(len(indices) == 1, 'single memory operand for tracked Arm load/store')
        index = indices[0]
        operand = args[index]
        offset, snapshot = address(operand), dict(values)
        for reg in args[:index]:
            size = width(reg, op)
            if op in LOADS:
                write(reg, snapshot.get(offset) if size == 8 and offset is not None else None)
            elif offset is not None:
                value = read(reg)
                invalidate(offset, size)
                if size == 8 and value is not None:
                    values[offset] = value
            if offset is not None:
                offset += size
        if operand.endswith('!') or index != len(args) - 1:
            match = re.match(r'\[(x\d+)', operand)
            if match:
                write(match[1])  # Unsupported writeback cannot preserve a fact.
    elif op in ('casa', 'ldadd', 'ldaddl'):
        # Atomic read/write operands differ from ordinary destination-first
        # arithmetic. No atomic operation preserves a tracked value.
        offset = address(args[-1])
        for arg in args[:-1]:
            write(arg)
        if offset is not None:
            invalidate(offset, width(args[0], op))
    elif op not in READ_ONLY and args:
        # Branches name labels or merely read registers; this conservative kill
        # must not erase cbz/tbz operands (ordinary CFG explores both edges).
        if op not in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz') and not op.startswith('b.'):
            write(args[0])
    if args and args[0] in ('sp', 'wsp'):
        # Prologue frame construction invalidates old frame-relative aliases.
        values = {k: v for k, v in values.items() if isinstance(k, str) and v[0] != 'stack'}
    return values
