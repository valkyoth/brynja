"""Compose actual debug read bodies with the actual borrowed reader machinery."""
import check_debug_accelerated_read as read

preflight, model, require = read.preflight, read.model, read.require
bridges = preflight.bridges


class ComposedRead(read.ReadModel):
    def __init__(self, functions, constants, names, length, mode, valid, producer,
                 counter, rate, position, failed, squeezing, session_fault, read_fault, failure):
        super().__init__(functions, constants, names, length, counter, rate, position,
                         failed, squeezing, names['session_success'], None)
        self.mode, self.valid, self.producer = mode, valid, producer
        self.failure, self.session_fault, self.chunk_fault = failure, session_fault, read_fault
        self.session_calls = self.read_calls = 0
        self.step_limit = 400000

    def load(self, pointer, width):
        if self.in_read:
            return super().load(pointer, width)
        return preflight.PreflightModel.load(self, pointer, width)

    def store(self, pointer, width, value):
        if self.in_read:
            return super().store(pointer, width, value)
        require(isinstance(pointer, model.Pointer), 'known composed store address')
        bridges.BridgedOperation.store(self, pointer, width, value)
        if pointer.region == 'storage':
            if (pointer.offset, width) == (859, 1):
                self.failed = value
            elif (pointer.offset, width) == (616, 8):
                self.position = value

    def run(self, name, args, depth=0):
        if name == self.names['preflight']:
            require(not self.in_preflight and args == [model.Pointer('storage'), self.length],
                    'original outer or chunk-sized engine preflight')
            self.armed()
            self.preflight_calls += 1
            before = len(self.engine_events), len(self.reads), len(self.decoded)
            if not self.in_read:
                self.events.append(('preflight',))
            self.in_preflight = True
            try:
                return model.Model.run(self, name, args, depth)
            finally:
                self.in_preflight = False
                if not self.in_read:
                    a, b, c = before
                    self.events.append(('engine-preflight', tuple(self.engine_events[a:]),
                                        tuple(self.reads[b:]), tuple(self.decoded[c:])))
        if name == self.names['session']:
            self.session_calls += 1
            self.session_result = (self.session_fault[1] if self.session_fault
                                   and self.session_fault[0] == self.session_calls else self.names['session_success'])
            return preflight.PreflightModel.run(self, name, args, depth)
        if name == self.names['counter'] and not self.in_read:
            return preflight.PreflightModel.run(self, name, args, depth)
        if name == self.names['read']:
            return self.read_chunk(name, args, depth)
        if self.in_read and name == self.names['lane_copy']:
            require(len(args) == 4, 'four borrowed staging copy arguments')
            destination, length, source, source_length = args
            require(destination == model.Pointer('storage', 864 + self.copied)
                    and source == model.Pointer('storage', 656 + self.position)
                    and length == source_length == min(self.length - self.copied, self.rate - self.position)
                    and 0 < length <= 168, 'exact original lanes to original staging prefix')
            self.address(destination, length, access=False)
            require(destination.offset + length <= 1032 and source.offset + length <= 856,
                    'nonoverlapping bounded original lanes and staging')
            self.copies += 1
            self.read_trace.append(('copy', self.copied, self.position, length))
            if self.read_fault and self.read_fault[:2] == ('copy', self.copies):
                if self.read_fault[2] == 'unwind':
                    raise model.Unwind(self.exception)
                return self.read_fault[2]
            self.copied += length
            return self.names['copy_success']
        if self.in_read and name == self.names['split']:
            require(len(args) == 5, 'complete original split arguments')
            result, source, length, count, _ = args
            require(isinstance(result, model.Pointer) and source == model.Pointer('storage', 864 + self.copied)
                    and length == self.length - self.copied and type(count) is int and 0 < count <= length,
                    'bounded original remaining staging split')
            self.fields(result, [(0, 8, source), (8, 8, count),
                                 (16, 8, model.Pointer('storage', source.offset + count)), (24, 8, length - count)])
            return None
        if self.in_read:
            return super().run(name, args, depth)
        if self.in_preflight:
            return preflight.PreflightModel.run(self, name, args, depth)
        return bridges.BridgedOperation.run(self, name, args, depth)

    def read_chunk(self, name, args, depth):
        self.armed()
        require(not self.in_read and args == [model.Pointer('storage'), model.Pointer('storage', 864), self.chunk]
                and 0 < self.chunk <= 168, 'actual outer operation to original engine/staging chunk')
        self.read_calls += 1
        self.events.append(('read', self.chunk))
        length, failure = self.length, self.failure
        self.length, self.failure = self.chunk, None
        self.read_fault = self.chunk_fault[1] if self.chunk_fault and self.chunk_fault[0] == self.read_calls else None
        self.engine_guard = None
        self.engine_guard_stores, self.read_trace = [], []
        self.copies = self.permutations = self.decodes = self.copied = 0
        before = len(self.engine_events), len(self.reads)
        self.in_read = True
        try:
            return model.Model.run(self, name, args, depth)
        finally:
            a, b = before
            self.events.append(('engine-read', tuple(self.read_trace), tuple(self.engine_events[a:]),
                                tuple(self.reads[b:]), self.copied, tuple(self.engine_guard_stores)))
            self.in_read = False
            self.length, self.failure = length, failure
