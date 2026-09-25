"""Compose retained volatile clearing with original accelerated reader storage."""
import re

import check_debug_volatile_clear as clear
import check_debug_reader_primitives as primitives

model, require = primitives.model, primitives.require


def closure(case, consuming):
    root, producer, names, merged = primitives.closure(case, consuming)
    wipe, precondition, selected = clear.closure(case.core)
    require(wipe == names['wipe'], 'same-row original reader clearing entry')
    names['clear_precondition'] = precondition
    for name, body in selected.items():
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed clearing helper ABI')
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical reader/clear shared helper')
        merged[name] = body
    return root, producer, names, merged


class ClearingReader(primitives.ReaderPrimitives):
    def __init__(self, *args):
        super().__init__(*args)
        self.clearing = None
        self.clear_cells = {}
        self.completed_clears = []
        self.step_limit = 2000000

    def store(self, ptr, width, value):
        if self.clearing is not None:
            # These are fresh helper-local descriptor frames, never payload or
            # caller metadata. Reuse the tested indexed store to avoid scanning
            # all earlier byte-write frames at every iterator step.
            require(isinstance(ptr, model.Pointer) and re.match(r'^\d+:', ptr.region)
                    and self.clear_frame_start < int(ptr.region.split(':', 1)[0]) <= self.frames,
                    'clearing only spills into helper-local descriptor frames')
            self.local_cells = self.clear_cells
            return clear.ClearModel.store(self, ptr, width, value)
        return super().store(ptr, width, value)

    def next_byte(self, pointer):
        require(self.clearing is not None, 'volatile operation inside original clear call')
        base, length, checked, stored, fences = self.clearing
        require(stored < length and fences == 0 and pointer == model.Pointer(base.region, base.offset + stored),
                'exact next original byte, no skipped/repeated/out-of-region clear')
        self.address(pointer, 1, access=False)
        return checked, stored

    def volatile_store(self, pointer, value):
        checked, stored = self.next_byte(pointer)
        require(checked == stored + 1 and type(value) is int and value == 0,
                'one checked volatile zero, no payload read or ordinary store')
        self.clearing[3] += 1
        if pointer.region == 'storage' and 640 <= pointer.offset < 656:
            self.counter_bytes[pointer.offset - 640] = 0

    def compiler_fence(self, order):
        require(self.clearing is not None, 'clear fence in active original call')
        _, length, checked, stored, fences = self.clearing
        require(checked == stored == length and fences == 0 and order == 'seq_cst',
                'one SeqCst compiler fence after all original bytes, including empty slices')
        self.clearing[4] += 1

    def run(self, name, args, depth=0):
        if name == self.names['clear_precondition']:
            require(len(args) == 3 and args[1] == 1, 'original byte-alignment precondition')
            checked, stored = self.next_byte(args[0])
            require(checked == stored, 'exactly one valid-pointer check before each byte')
            self.clearing[2] += 1
            return None  # Valid borrowed byte pointers assumed; panic body unqualified.
        if name != self.names['wipe']:
            return super().run(name, args, depth)
        require(self.clearing is None and self.primitive is None and len(args) == 2,
                'nonrecursive clear at reader primitive boundary')
        base, length = args
        require(isinstance(base, model.Pointer) and base.region in ('storage', 'output')
                and type(length) is int and 0 <= length <= model.MASK >> 1,
                'original live borrowed clearing region')
        self.address(base, length, access=False)
        # Retain the independently checked caller trace and argument checks.
        require(super().run(name, args, depth) is None, 'void caller clearing request')
        self.clear_frame_start = self.frames
        self.clearing = [base, length, 0, 0, 0]
        try:
            value = model.Model.run(self, name, args, depth)
            require(value is None and self.clearing == [base, length, length, length, 1],
                    'actual complete volatile clearing body and final fence')
            self.completed_clears.append((base.region, base.offset, length))
            return value
        finally:
            self.clearing = None
