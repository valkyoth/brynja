"""Descriptor-only execution of the complete KMAC verifier control flow."""
from debug_kmac_whole import model, require, destruction


class WholeModel(destruction.DestructorModel):
    def __init__(self, functions, names, boundaries, constants, accelerated, scenario):
        super().__init__(functions, names, {'state_drop': 'unused'}, 32, accelerated)
        self.boundaries, self.scenario = boundaries, scenario
        self.pairs, self.reads, self.outputs, self.leaves = [], [], [], []
        self.output_live = False
        self.output_clear = None
        self.output_clears = []
        self.boundary_counts = {}
        self.inject = None
        self.region_cells = {}
        self.step_limit = 1000000
        self.reader_drop = next(name for name in functions if ('drop_in_place' in name or 'drop_glue' in name)
                                and 'Cshake' in name and 'Reader' in name and 'Option' not in name)
        for name, value in constants.items():
            self.allocate(name, 1)
            self.memory[model.Pointer(name)] = (1, value)

    def value(self, token, env):
        if token == '{ i1 true, i8 poison }':
            return 1, model.UNKNOWN
        return super().value(token, env)

    def store(self, ptr, width, value):
        if isinstance(ptr, model.Pointer) and ptr.region == 'engine':
            return super().store(ptr, width, value)
        self.address(ptr, width)
        require(not ptr.region.startswith('@'), 'constant global is read-only')
        cells = self.region_cells.setdefault(ptr.region, set())
        for other in tuple(cells):
            size, _ = self.memory[other]
            if max(other.offset, ptr.offset) < min(other.offset + size, ptr.offset + width):
                cells.remove(other)
                del self.memory[other]
        cells.add(ptr)
        self.memory[ptr] = width, value

    def fields(self, pointer, fields):
        for offset, width, value in fields:
            self.store(model.Pointer(pointer.region, pointer.offset + offset), width, value)

    def move(self, destination, source, width):
        self.address(destination, width)
        self.address(source, width)
        require(destination.region != source.region and width in (16, 24, 32, 48), 'whole disjoint descriptor transfer')
        fields = [(ptr.offset - source.offset, *self.memory[ptr]) for ptr in self.region_cells.get(source.region, ())
                  if source.offset <= ptr.offset and ptr.offset + self.memory[ptr][0] <= source.offset + width]
        self.store(destination, width, model.UNKNOWN)
        self.fields(destination, fields)

    def run(self, name, args, depth=0):
        p = model.Pointer
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[3] == 0, 'nonvolatile descriptor transfer')
            self.move(*args[:3])
            return None
        if name == 'llvm.usub.with.overflow.i64':
            require(len(args) == 2 and all(type(value) is int for value in args), 'checked public length subtraction')
            return (args[0] - args[1]) & model.MASK, int(args[0] < args[1])
        role = self.boundaries.get(name)
        if role is None:
            return model.Model.run(self, name, args, depth)
        self.boundary_counts[role] = self.boundary_counts.get(role, 0) + 1
        injected = self.inject == (role, self.boundary_counts[role])
        if injected and role != 'final':
            self.leaves.append(('unwind', role))
            raise model.Unwind((p('exception'), 37))
        length, valid, present, strong, production, expected, mismatch, failure = self.scenario
        bits = 0 if length == 0 else (length - 1) * 8 + valid
        if role == 'none':
            pointer = self.load(args[0], 8)
            return int(pointer == 0) if self.accelerated else int(self.load(p(args[0].region, args[0].offset + 8), 1) == 2)
        if role == 'key':
            require(self.load(args[0], 8) == p('metadata', self.base), 'original metadata classification owner')
            return int(not strong)
        if role == 'ne':
            require(args[1].region.startswith('@') and self.load(args[1], 1) == 0, 'actual FullStrength constant')
            return int(self.load(args[0], 1) != 0)
        if role == 'suffix':
            out, state, optional, output_bits = args
            require(output_bits == bits and self.load(state, 8) == p('engine', self.base), 'original suffix state and exact tag length')
            require(self.load(optional, 8) == 0, 'selected no-final-message contract')
            error = failure[1] if failure and failure[0] == 'suffix' else None
            self.leaves.append(('suffix', error))
            if error is not None:
                self.fields(out, [(0, 8, 0), (8, 1, error)] if self.accelerated else [(0, 1, error), (8, 1, 2)])
            else:
                if self.accelerated:
                    self.fields(out, [(0, 8, p('engine', self.base)), (8, 8, p('scratch')), (16, 8, 168)])
                    self.store(state, 8, 0)
                else:
                    self.fields(out, [(0, 8, p('engine', self.base)), (8, 1, 1)])
                    self.store(p(state.region, state.offset + 8), 1, 2)
            return None
        if role in ('get', 'get_mut'):
            start, size, end = args
            self.address(start, size, access=False)
            require(type(end) is int, 'public slice end')
            return (start, end) if end <= size else (0, model.UNKNOWN)
        if role in ('first', 'last'):
            start, size = args
            self.address(start, size, access=False)
            return p(start.region, start.offset + (size - 1 if role == 'last' else 0)) if size else 0
        if role == 'chunks':
            out, start, size, step, _ = args
            require(start == p('candidate', self.base) and size == length - int(valid not in (0, 8)) and step == 64,
                    'original complete candidate prefix in 64-byte chunks')
            self.fields(out, [(0, 8, start), (8, 8, size), (16, 8, step)])
            return None
        if role == 'next_chunks':
            slot = args[0]
            start, size, step = [self.load(p(slot.region, slot.offset + offset), 8) for offset in (0, 8, 16)]
            if not size:
                return 0, model.UNKNOWN
            count = min(size, step)
            self.fields(slot, [(0, 8, p(start.region, start.offset + count)), (8, 8, size - count)])
            return start, count
        if role in ('bulk', 'final'):
            out = args[0]
            if role == 'bulk':
                _, reader, output, count = args
                require(self.load(reader, 8) == p('engine', self.base), 'original bulk reader owner')
            else:
                if self.accelerated:
                    _, reader, output, count, tail = args
                    require(self.load(reader, 8) == p('engine', self.base), 'original accelerated consuming owner')
                else:
                    _, engine, active, output, count, tail = args
                    require((engine, active) == (p('engine', self.base), 1), 'original portable consuming owner/flag')
                    reader = self.allocate('consuming:' + str(self.frames), 16)
                    self.fields(reader, [(0, 8, engine), (8, 1, active)])
                require(tail == valid and count == 1, 'exact candidate terminal bit shape')
                self.run(self.reader_drop, [reader], depth + 1)
                if injected:
                    self.leaves.append(('unwind', role))
                    raise model.Unwind((p('exception'), 37))
            require(output == p('metadata', self.base) and 0 < count <= 64 and not self.output_live,
                    'original bounded output with exclusive live ownership')
            self.reads.append((role, count))
            error = failure[1] if failure and failure[0] == role and (len(failure) < 3 or len(self.reads) == failure[2]) else None
            if error is not None:
                self.fields(out, [(0, 8, 2), (8, 1, error)])
            else:
                self.fields(out, [(0, 8, 1), (8, 8, output), (16, 8, count)])
                self.output_live = True
            self.leaves.append((role, error))
            return None
        if role in ('expose', 'output_drop'):
            slot = args[0]
            tag, output, count = [self.load(p(slot.region, slot.offset + offset), 8) for offset in (0, 8, 16)]
            require(tag == 1 and output == p('metadata', self.base) and 0 < count <= 64 and self.output_live,
                    'live original secret-output descriptor')
            if role == 'expose':
                return output, count
            self.output_clear = (output, count)
            before = len(self.output_clears)
            model.Model.run(self, name, args, depth)
            require(self.output_clears[before:] == [(output, count)], 'actual owned output destructor clears exactly once')
            self.output_clear = None
            self.outputs.append(count)
            self.output_live = False
            return None
        if role == 'output_zeroize':
            require(tuple(args) == self.output_clear and self.output_live, 'original live secret output at volatile boundary')
            self.address(args[0], args[1], access=False)
            self.output_clears.append(tuple(args))
            return None  # Actual volatile primitive retains separate evidence.
        if role == 'iter':
            start, count = args
            self.address(start, count, access=False)
            return start, p(start.region, start.offset + count)
        if role == 'zip':
            out, begin, end, candidate, count = args
            require(begin == p('metadata', self.base) and end == p('metadata', self.base + count)
                    and candidate == p('candidate', self.base + len(self.pairs)), 'exact next original comparison chunk')
            self.fields(out, [(n * 8, 8, value) for n, value in enumerate((begin, end, candidate, count, 0, count))])
            return None
        if role == 'identity':
            self.move(*args, 48)
            return None
        if role == 'next_zip':
            slot = args[0]
            begin, _, candidate, _, index, limit = [self.load(p(slot.region, slot.offset + n), 8) for n in range(0, 48, 8)]
            if index == limit:
                return 0, model.UNKNOWN
            require(0 <= index < limit <= 64, 'bounded paired-byte iteration')
            self.store(p(slot.region, slot.offset + 32), 8, index + 1)
            return p(begin.region, begin.offset + index), p(candidate.region, candidate.offset + index)
        if role == 'array':
            require(args == [p('metadata', self.base + 65)], 'original difference byte')
            return args[0], p('metadata', self.base + 66)
        if role == 'next_mut':
            slot = args[0]
            begin, end = self.load(slot, 8), self.load(p(slot.region, slot.offset + 8), 8)
            if begin == end:
                return 0
            require((begin, end) == (p('metadata', self.base + 65), p('metadata', self.base + 66)), 'single difference iterator')
            self.store(slot, 8, end)
            return begin
        if role == 'accumulate':
            index = len(self.pairs)
            offset = 0 if valid not in (0, 8) and index == length - 1 else index % 64
            require(self.output_live and args == [p('metadata', self.base + 65), p('metadata', self.base + offset),
                    p('candidate', self.base + index)] and index < length, 'exact original ordered comparison byte')
            self.pairs.append(tuple(args))
            return None
        if role == 'predicate':
            require(args == [p('metadata', self.base + 65)] and len(self.pairs) == length and not self.output_live,
                    'authentication decision only after complete comparison and output destruction')
            return int(mismatch is None)
        if role == 'clear':
            return destruction.DestructorModel.run(self, name, args, depth)
        raise ValueError('unmodeled whole-verifier boundary: ' + role)
