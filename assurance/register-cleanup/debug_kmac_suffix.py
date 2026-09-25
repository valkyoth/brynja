"""Compose actual suffix framing/consumption/destruction with the whole caller."""
import re

import debug_kmac_whole as whole
from debug_kmac_whole_model import WholeModel

model, guard, require = whole.model, whole.guard, whole.require


def closure(function, definitions, names, text):
    root, functions, boundaries, constants, accelerated = whole.closure(function, definitions, names, text)
    suffix = next(name for name, role in boundaries.items() if role == 'suffix')
    del boundaries[suffix]
    pending = [suffix]
    while pending:
        name = pending.pop()
        if name in functions or name in boundaries or name.startswith('llvm.') or '16panic_in_cleanup' in name:
            continue
        tokens = (('push_message', 'SecretPacker', '15push_bit_string'), ('push_encoded', 'SecretPacker', '10push_bytes'),
                  ('used', 'SecretPacker', '4used'), ('right_encode', 'sp800185', '17right_encode_u128'),
                  ('encoded_bytes', 'EncodedInteger', '8as_bytes'), ('bit_new', 'Fips202BitString', '3new'),
                  ('tail_index', 'array', '5index'), ('state_finish', 'backend', 'State', '6finish'))
        roles = [role for role, *parts in tokens if all(part in name for part in parts)]
        require(len(roles) <= 1 and name in definitions, 'bound unambiguous suffix dependency: ' + name)
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed suffix dependency ABI')
        if roles:
            boundaries[name] = roles[0]
            continue
        functions[name] = model.parameters(body), model.blocks(body)
        for lines in model.blocks(body).values():
            for line in lines:
                if 'call ' in line or 'invoke ' in line:
                    pending.append(guard.call(line)[0])
    return root, functions, boundaries, constants, accelerated


class SuffixModel(WholeModel):
    def __init__(self, *args):
        super().__init__(*args)
        self.frame = self.encoded = None
        self.initializing = False
        self.framing_clears, self.suffix_events = [], []
        self.message = None
        self.suffix_fault = None
        self.success_code = None
        self.allocate('empty', 0)
        self.state_drop = next(name for name in self.functions if ('drop_in_place' in name or 'drop_glue' in name)
                               and 'Cshake' in name and 'Reader' not in name and 'core_state' not in name
                               and 'Borrowed' not in name and 'Option' not in name and 'Backend' not in name)

    def typed(self, text, env):
        if text in ('ptr align 1 inttoptr (i64 1 to ptr)', 'ptr inttoptr (i64 1 to ptr)'):
            return model.Pointer('empty')
        return super().typed(text, env)

    def pending_access(self, pointer, width):
        return self.frame is not None and pointer.region == self.frame.region and not self.initializing and \
            pointer.offset <= self.frame.offset + 8 < pointer.offset + width

    def load(self, pointer, width):
        require(not self.pending_access(pointer, width), 'pending secret byte cannot enter descriptor model')
        return super().load(pointer, width)

    def store(self, pointer, width, value):
        require(not self.pending_access(pointer, width), 'pending secret byte cannot be stored by descriptor model')
        return super().store(pointer, width, value)

    def move(self, destination, source, width):
        if not self.initializing:
            return super().move(destination, source, width)
        require(width in (1, 8) and self.frame is not None and destination.region == self.frame.region
                and source.region != destination.region, 'only actual Framing initialization copies')
        self.address(destination, width)
        self.address(source, width)
        value = self.load(source, width)
        require(value == 0, 'framing starts zero before any input is accepted')
        self.store(destination, width, value)

    def run(self, name, args, depth=0):
        p = model.Pointer
        if 'Framing3new' in name:
            require(self.frame is None and len(args) == 1 and self.sizes[args[0].region] == 10,
                    'one actual ten-byte framing owner')
            self.frame, self.initializing = args[0], True
            try:
                value = model.Model.run(self, name, args, depth)
                require(value is None and all(self.load(p(self.frame.region, self.frame.offset + offset), size) == 0
                                             for offset, size in ((0, 8), (8, 1), (9, 1))),
                        'complete actual public-zero initialization before secret input')
                return value
            finally:
                self.initializing = False
        if name == 'llvm.memset.p0.i64':
            require(self.initializing and args[1:] == [0, 8, 0] and args[0].region != self.frame.region,
                    'exact zero public framing initializer')
            self.store(args[0], 8, 0)
            return None
        role = self.boundaries.get(name)
        if role == 'clear' and self.frame and args[0].region == self.frame.region:
            offset, size = args[0].offset - self.frame.offset, args[1]
            require((offset, size) in ((8, 1), (9, 1), (0, 8)), 'exact original framing cleanup regions')
            self.framing_clears.append((offset, size))
            # Only public framing counters are modeled. The pending secret byte
            # remains opaque; this records a request, not a byte-erasure proof.
            if offset != 8:
                self.store(args[0], size, 0)
            return 0
        if role not in ('push_message', 'push_encoded', 'used', 'right_encode', 'encoded_bytes', 'bit_new', 'tail_index', 'state_finish'):
            return super().run(name, args, depth)
        if self.suffix_fault and self.suffix_fault[0] == role:
            outcome = self.suffix_fault[1]
            if outcome == 'unwind' and role != 'state_finish':
                raise model.Unwind((p('exception'), 37))
            if role in ('push_message', 'push_encoded'):
                return outcome
        length, valid, _, _, _, _, _, failure = self.scenario
        bits = (length - 1) * 8 + valid if length else 0
        if role == 'right_encode':
            require(args[1] == bits and self.encoded is None, 'exact tag bit length encoded once')
            self.encoded = args[0]
            self.encoded_length = max(1, (bits.bit_length() + 7) // 8) + 1
            self.suffix_events.append('encode')
            return None
        if role == 'encoded_bytes':
            require(args == [self.encoded], 'original public right-encode owner')
            return self.encoded, self.encoded_length
        if role == 'tail_index':
            if args[0] == p('empty'):
                return args[0], 0
            require(args[0] == p(self.frame.region, self.frame.offset + 8), 'borrowed original pending byte')
            return args[0], 1
        if role == 'bit_new':
            out, start, count, tail = args
            used = self.load(p(self.frame.region, self.frame.offset + 9), 1)
            require(tail == used and count == int(used != 0) and
                    start == (p(self.frame.region, self.frame.offset + 8) if used else p('empty')),
                    'exact pending-byte slice, not a local secret-byte copy')
            self.fields(out, [(0, 8, start), (8, 8, count), (16, 8, tail), (24, 1, tail)])
            return None
        if role == 'state_finish':
            if self.accelerated:
                out, state, tail = args
                require(self.load(state, 8) == p('engine', self.base), 'original taken accelerated state')
            else:
                out, engine, active, tail = args
                require((engine, active) == (p('engine', self.base), 1), 'original taken portable state')
                state = self.allocate('suffix-state:' + str(self.frames), 16)
                self.fields(state, [(0, 8, engine), (8, 1, active)])
            used = self.load(p(self.frame.region, self.frame.offset + 9), 1)
            require(self.load(tail, 8) == (p(self.frame.region, self.frame.offset + 8) if used else p('empty'))
                    and self.load(p(tail.region, tail.offset + 24), 1) == used, 'original tail descriptor reaches state finish')
            outcome = self.suffix_fault[1] if self.suffix_fault and self.suffix_fault[0] == role else None
            if outcome is not None:
                self.run(self.state_drop, [state], depth + 1)
                if outcome == 'unwind':
                    raise model.Unwind((p('exception'), 37))
                self.fields(out, [(0, 8, 0), (8, 1, outcome)] if self.accelerated else [(0, 1, outcome), (8, 1, 2)])
            else:
                self.fields(out, [(0, 8, p('engine', self.base)), (8, 8, p('scratch')), (16, 8, 168)] if self.accelerated else
                            [(0, 8, p('engine', self.base)), (8, 1, 1)])
            self.suffix_events.append('consume')
            return None
        packer = args[0]
        state = self.load(packer, 8)
        require(self.load(state, 8) == p('engine', self.base) and
                self.load(p(packer.region, packer.offset + 8), 8) == self.frame, 'original state and framing borrows')
        if role == 'used':
            return self.load(p(self.frame.region, self.frame.offset + 9), 1)
        if role == 'push_message':
            require(self.message is not None, 'expected optional final message')
            descriptor = args[1]
            for offset, size, value in self.message:
                require(self.load(p(descriptor.region, descriptor.offset + offset), size) == value, 'whole original final-message descriptor')
            self.store(p(self.frame.region, self.frame.offset + 9), 1, self.message[-1][2] % 8)
            self.suffix_events.append('message')
        else:
            require(role == 'push_encoded' and args[1:] == [self.encoded, self.encoded_length], 'entire original encoding appended')
            self.suffix_events.append('append')
        require(self.success_code in (7, 20, 255), 'bound result success variant')
        return self.success_code
