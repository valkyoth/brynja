"""Actual debug bit-packer control flow beneath the complete verifier."""
import re

import debug_kmac_suffix as suffix

model, guard, require = suffix.model, suffix.guard, suffix.require


def lower(line):
    # Multiplication by one cannot overflow, including either LLVM flag.
    line = re.sub(r'^(%[-.$\w]+ = )mul(?: nuw)?(?: nsw)? i64 (%[-.$\w]+), 1$', r'\1add i64 \2, 0', line)
    match = re.fullmatch(r'(%[-.$\w]+ = )(add|sub)( nuw)? i8 (\S+), (\S+)', line)
    if match:
        return match[1] + 'call i8 @diagnostic_u8_' + match[2] + ('_nuw' if match[3] else '') + \
            '(i8 ' + match[4] + ', i8 ' + match[5] + ')'
    return line


def closure(function, definitions, names, text):
    root, functions, boundaries, constants, accelerated = suffix.closure(function, definitions, names, text)
    pending = [name for name, role in boundaries.items() if role in ('push_message', 'push_encoded', 'used')]
    for name in pending:
        del boundaries[name]
    while pending:
        name = pending.pop()
        if name in functions or name in boundaries or name.startswith('llvm.') or '16panic_in_cleanup' in name:
            continue
        if 'panicking' in name or '17len_mismatch_fail' in name:
            boundaries[name] = 'panic'
            continue
        if name not in definitions and '15copy_from_slice' in name:
            boundaries[name] = 'copy_slice'
            continue
        roles = [role for role, parts in (
            ('absorb', ('Absorb', '6absorb')),
            ('xor_bits', ('secret_memory', '20xor_secret_byte_bits')),
            ('first_mut', ('slice', '9first_mut')),
            ('copied', ('option', '6copied')),
            ('copy_precondition', ('copy_nonoverlapping', '18precondition_check')),
        ) if all(part in name for part in parts)]
        require(len(roles) <= 1, 'unambiguous packer leaf identity')
        if roles:
            boundaries[name] = roles[0]
            continue
        require(name in definitions, 'same-row actual packer helper: ' + name)
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed actual packer ABI')
        functions[name] = model.parameters(body), model.blocks(body)
        for lines in model.blocks(body).values():
            for line in lines:
                if 'call ' in line or 'invoke ' in line:
                    pending.append(guard.call(line)[0])
    return root, functions, boundaries, constants, accelerated


class PackingModel(suffix.SuffixModel):
    def __init__(self, *args):
        functions, *rest = args
        lowered = {name: (params, {label: [lower(line) for line in lines] for label, lines in graph.items()})
                   for name, (params, graph) in functions.items()}
        super().__init__(lowered, *rest)
        self.packing_events = []
        self.packing_fault = None

    def move(self, destination, source, width):
        if self.initializing or width not in (1, 8):
            return super().move(destination, source, width)
        self.address(destination, width)
        self.address(source, width)
        self.store(destination, width, self.load(source, width))

    def run(self, name, args, depth=0):
        if name.startswith('diagnostic_u8_') or name == 'llvm.uadd.with.overflow.i8':
            require(len(args) == 2 and all(type(value) is int and 0 <= value < 256 for value in args),
                    'initialized public byte arithmetic operands')
            value = args[0] - args[1] if '_sub' in name else args[0] + args[1]
            if name == 'llvm.uadd.with.overflow.i8':
                return value & 255, int(value > 255)
            require(not name.endswith('_nuw') or 0 <= value < 256, 'nonpoison public byte arithmetic')
            return value & 255
        if name == 'llvm.ctpop.i64':
            require(len(args) == 1 and type(args[0]) is int and 0 <= args[0] <= model.MASK, 'public alignment metadata')
            return args[0].bit_count()
        if name == 'llvm.usub.sat.i64':
            require(len(args) == 2 and all(type(value) is int and 0 <= value <= model.MASK for value in args),
                    'bounded public complete-byte length subtraction')
            return max(0, args[0] - args[1])
        role = self.boundaries.get(name)
        if role == 'copy_slice':
            destination, count, source, size, *_ = args
            require(count == size == 8, 'whole public emitted-counter copy')
            self.move(destination, source, size)
            return None
        if role == 'copy_precondition':
            source, destination, size, alignment, count, *_ = args
            require(size == alignment == 1 and count in (1, 8) and source.region != destination.region,
                    'disjoint public framing-counter byte copies only')
            self.address(source, count)
            self.address(destination, count)
            require(not self.pending_access(source, count) and not self.pending_access(destination, count),
                    'framing byte cannot cross the copy precondition')
            return None
        if role == 'copied':
            require(args == [model.Pointer(self.frame.region, self.frame.offset + 9)], 'only public used-bit metadata copied')
            return 1, self.load(args[0], 1)
        if role == 'first_mut':
            require(args[1] == 1, 'one original framing byte')
            self.address(args[0], 1, access=False)
            return args[0]
        if role == 'absorb':
            state, data, length = args
            require(self.load(state, 8) == model.Pointer('engine', self.base), 'original borrowed state receives packing bytes')
            self.address(data, length, access=False)
            self.packing_events.append(('absorb', data, length))
            ordinal = sum(event[0] == 'absorb' for event in self.packing_events)
            if self.packing_fault and self.packing_fault[:2] == ('absorb', ordinal):
                if self.packing_fault[2] == 'unwind':
                    raise model.Unwind((model.Pointer('exception'), 37))
                return self.packing_fault[2]
            return self.success_code
        if role == 'xor_bits':
            pending, source, position, count, used = args
            require(pending == model.Pointer(self.frame.region, self.frame.offset + 8)
                    and 0 <= position <= 8 and 0 < count <= 8 - position and 0 <= used <= 8 - count,
                    'bounded original pending-byte fragment')
            self.address(source, 1, access=False)
            self.packing_events.append(('xor', source, position, count, used))
            return 0  # Actual byte primitive retains its machine-code evidence.
        return super().run(name, args, depth)
