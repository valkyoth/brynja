"""Scalar constructor split initialization and directly returned tag provenance."""
from hmac_constructor_state import State as OwnerState
from hmac_engine_codegen import require


class State(OwnerState):
    def __init__(self):
        super().__init__()
        self.initializing = set()
        self.tag_fields = set()

    def key(self):
        return super().key(), frozenset(self.initializing), frozenset(self.tag_fields)

    def forget_tags(self, address, size):
        require(type(size) is int and 0 <= size < (1 << 64), 'unreviewed scalar write extent')
        root, offset = address
        self.tag_fields = {(base, start) for base, start in self.tag_fields
                           if base != root or start >= offset + size or start + 8 <= offset}

    def transfer(self, destination, source, size):
        require(not ({destination[0], source[0]} & self.initializing),
                'copy of partially initialized scalar owner')
        self.forget_tags(destination, size)
        super().transfer(destination, source, size)

    def store(self, address, size, value):
        if address[0] in self.initializing:
            require(address[1] == 0 and size == 1 and value == 0,
                    'inline constructor leading byte changed')
        self.forget_tags(address, size)
        super().store(address, size, value)

    def end(self, root):
        self.initializing.discard(root)
        self.tag_fields = {address for address in self.tag_fields if address[0] != root}
        super().end(root)
