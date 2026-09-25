"""Scalar metadata model for the retained accelerated engine read body."""
import check_debug_accelerated_preflight as preflight

model, require = preflight.model, preflight.require


class ReadModel(preflight.PreflightModel):
    def __init__(self, functions, constants, names, length, counter, rate, position,
                 failed, squeezing, session, fault):
        super().__init__(functions, constants, names, length, 0, model.UNKNOWN, '',
                         counter, failed, squeezing, session, True)
        self.counter_bytes = bytearray(self.counter_bytes)
        self.rate, self.position, self.read_fault = rate, position, fault
        self.in_read = self.writing = False
        self.engine_guard = None
        self.engine_guard_stores, self.read_trace = [], []
        self.copies = self.permutations = self.decodes = self.copied = 0
        self.step_limit = 150000

    def load(self, ptr, width):
        if isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            self.address(ptr, width, access=False)
            if self.decoding:
                require(width == 1 and 640 <= ptr.offset < 656, 'only original counter bytes decoded')
                self.reads.append(ptr.offset - 640)
                return self.counter_bytes[ptr.offset - 640]
            if self.in_preflight:
                return super().load(ptr, width)
            require(self.in_read and width == 8 and ptr.offset in (608, 616), 'read accesses only rate/cursor metadata')
            return self.rate if ptr.offset == 608 else self.position
        if isinstance(ptr, model.Pointer) and ':' in ptr.region and width == 8 and self.writing:
            fields = preflight.decode.CounterModel.local_fields(self, ptr, width)
            if {(offset, size) for offset, size, _ in fields} == {(0, 1), (1, 1)}:
                return preflight.decode.PackedResult(tuple(fields))
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        require(isinstance(ptr, model.Pointer), 'known engine-model store pointer')
        if isinstance(value, preflight.decode.PackedResult):
            require(self.writing and width == 8 and ':' in ptr.region, 'local writer ABI fields only')
            super().store(ptr, width, model.UNKNOWN)
            self.fields(ptr, value.fields)
            return
        if ptr.region == 'storage':
            require(self.in_read and not self.in_preflight, 'only actual read mutates engine metadata')
            self.address(ptr, width, access=False)
            if self.writing:
                require(width == 1 and 640 <= ptr.offset < 656 and type(value) is int and 0 <= value <= 255,
                        'writer only changes original counter bytes')
                self.counter_bytes[ptr.offset - 640] = value
                self.read_trace.append(('byte', ptr.offset - 640, value))
            elif (ptr.offset, width) == (616, 8):
                require(type(value) is int and 0 <= value <= model.MASK, 'bounded engine cursor')
                self.position = value
                self.read_trace.append(('position', value))
            else:
                require((ptr.offset, width, value) == (859, 1, 1), 'only terminal state transition')
                self.failed = value
                self.read_trace.append(('failed',))
            return
        super().store(ptr, width, value)
        if width == 8 and value == model.Pointer('storage') and ptr.offset == 0 and self.sizes[ptr.region] == 16:
            require(self.engine_guard in (None, ptr), 'unique original engine guard')
            self.engine_guard = ptr
        if self.engine_guard is not None and ptr == model.Pointer(self.engine_guard.region, 8):
            require(width == 1 and value in (0, 1), 'actual engine guard completion bit')
            self.engine_guard_stores.append(value)

    def run(self, name, args, depth=0):
        if name == self.names['read']:
            require(not self.in_read and args == [model.Pointer('storage'), model.Pointer('output'), self.length],
                    'original engine/read destination and length')
            self.in_read = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_read = False
        if name == self.names['counter']:
            require(self.in_read and not self.decoding and args == [model.Pointer('storage', 640)],
                    'actual read/preflight decodes original counter')
            self.decodes += 1
            self.decoding = True
            try:
                value = model.Model.run(self, name, args, depth)
            finally:
                self.decoding = False
            if self.read_fault == ('counter', 2, 'overflow') and self.decodes == 2:
                value = preflight.MAXIMUM
            self.read_trace.append(('decode', value))
            return value
        if name == self.names['writer']:
            require(self.in_read and not self.writing and len(args) == 2
                    and args[0] == model.Pointer('storage', 640), 'actual original output-counter writer')
            self.read_trace.append(('write-counter', args[1]))
            if self.read_fault == ('writer', 0, 'unwind'):
                raise model.Unwind(self.exception)
            self.writing = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.writing = False
        if name == self.names['permutation']:
            require(self.in_read and args == [model.Pointer('storage'), model.Pointer('storage', 656)],
                    'original session and complete original lane array')
            self.permutations += 1
            self.read_trace.append(('permute',))
            if self.read_fault and self.read_fault[:2] == ('permute', self.permutations):
                if self.read_fault[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.read_fault[2]
            return self.names['session_success']
        if name == self.names['lane_copy']:
            require(self.in_read and len(args) == 4, 'lane-copy boundary under read guard')
            destination, length, source, source_length = args
            require(destination == model.Pointer('output', self.copied)
                    and source == model.Pointer('storage', 656 + self.position)
                    and length == source_length == min(self.length - self.copied, self.rate - self.position)
                    and 0 < length <= 200, 'exact nonempty original source/destination prefixes')
            self.address(destination, length, access=False)
            require(source.offset + length <= 856, 'copy remains within original lanes')
            self.copies += 1
            self.read_trace.append(('copy', self.copied, self.position, length))
            if self.read_fault and self.read_fault[:2] == ('copy', self.copies):
                if self.read_fault[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.read_fault[2]
            self.copied += length
            return self.names['copy_success']
        if name == self.names['split']:
            require(self.in_read and len(args) == 5, 'borrowed split descriptor ABI')
            result, source, length, count, _ = args
            require(isinstance(result, model.Pointer), 'original local split-result pointer')
            require(source == model.Pointer('output', self.copied) and length == self.length - self.copied
                    and type(count) is int and 0 < count <= length, 'bounded original remaining-output split')
            self.fields(result, [(0, 8, source), (8, 8, count),
                                 (16, 8, model.Pointer(source.region, source.offset + count)), (24, 8, length - count)])
            return None
        if name == self.names['wipe']:
            require(self.in_read and len(args) == 2 and isinstance(args[0], model.Pointer)
                    and args[0].region == 'storage' and type(args[1]) is int, 'read cleanup uses original engine memory')
            self.address(args[0], args[1], access=False)
            self.read_trace.append(('wipe', args[0].offset, args[1]))
            return None
        if self.writing and name == 'llvm.memcpy.p0.p0.i64' and args[2] == 8:
            destination, source, _, volatile = args
            require(volatile == 0 and ':' in destination.region and ':' in source.region
                    and destination.region != source.region, 'nonoverlapping local writer ABI transfer')
            fields = preflight.decode.CounterModel.local_fields(self, source, 8)
            super().store(destination, 8, model.UNKNOWN)
            self.fields(destination, fields)
            return None
        if self.in_read and name == 'llvm.memcpy.p0.p0.i64':
            return preflight.operation.guard.portable.GuardModel.run(self, name, args, depth)
        if self.read_fault and name in (self.names['subtract'], self.names['end_add'], self.names['lane_get']):
            role = next(key for key in ('subtract', 'end_add', 'lane_get') if self.names[key] == name)
            if self.read_fault == (role, 0, 'none'):
                self.read_trace.append(('missing', role))
                return (0, model.UNKNOWN)
        return super().run(name, args, depth)
