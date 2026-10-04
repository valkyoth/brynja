"""Arithmetic for explicitly reviewed caller frames, not a stack-depth analyzer.

Inputs must be tied to emitted instructions separately. Unknown callees stop at
their entry: the caller-provided home space is NOT the callee's full footprint.
"""
from dataclasses import dataclass


def require(ok, message):
    if not ok: raise ValueError('frame geometry: ' + message)


@dataclass(frozen=True)
class Window:
    low: int
    high: int

    def __post_init__(self):
        require(type(self.low) is int and type(self.high) is int and
                0 <= self.low < self.high <= (1 << 64)-1 and
                self.high-self.low == 65536 and self.low % 4096 == 0,
                'one bounded aligned 64-KiB window')

    def span(self, name, address, size):
        require(type(address) is int and type(size) is int and size > 0
                and self.low <= address <= self.high-size, 'complete span inside admitted window')
        return dict(name=name, offset_from_low=address-self.low,
                    offset_from_high=address-self.high, bytes=size)


@dataclass(frozen=True)
class Frame:
    window: Window
    entry: int
    current: int

    @classmethod
    def enter(cls, window, caller_sp, fixed_bytes, alignment=16):
        require(type(caller_sp) is int and caller_sp % 16 == 0, 'aligned call-site RSP')
        require(type(fixed_bytes) is int and 0 <= fixed_bytes <= 65536
                and fixed_bytes % 8 == 0 and alignment in (16, 32), 'reviewed fixed frame/alignment')
        entry = caller_sp-8
        require(alignment == 32 or (entry-fixed_bytes) % 16 == 0,
                'fixed frame preserves alignment without invented rounding')
        current = (entry-fixed_bytes) & -alignment
        # Includes return address AND the complete caller-provided home space.
        window.span('frame and caller home', current, entry+40-current)
        return cls(window, entry, current)

    def slot(self, name, offset, size, origin='current'):
        require(origin in ('current', 'entry'), 'known stack base')
        return self.window.span(name, getattr(self, origin)+offset, size)

    def unknown_callee(self, name):
        require(self.current % 16 == 0, 'aligned unknown call site')
        result = self.window.span(name, self.current-8, 40)
        return result | dict(callee_frame_bytes=None, callee_spills_qualified=False)


def scheduler(window):
    """This image's reviewed straight caller chains, NOT all reachable paths."""
    body = Frame.enter(window, window.high-32, 168)
    root = Frame.enter(window, body.current, 11160, 32)
    leaf = Frame.enter(window, body.current, 136)
    closure = Frame.enter(window, root.current, 168)
    dispatch = Frame.enter(window, closure.current, 72)
    copy = Frame.enter(window, root.current, 40)
    spans = [
        body.slot('body saved RBX', 16, 8, 'entry'),
        body.slot('body saved RSI', 24, 8, 'entry'),
        body.slot('body saved RDI', -8, 8, 'entry'),
        body.slot('body security cookie', 144, 8),
        body.slot('body CPU inventory', 32, 88),
        body.slot('body marker', -40, 16, 'entry'),
        root.slot('root pushes', -64, 64, 'entry'),
        closure.slot('closure pushes', -64, 64, 'entry'),
        dispatch.slot('dispatch saved RBX', 16, 8, 'entry'),
        dispatch.slot('dispatch saved RBP', 80, 8),
        dispatch.slot('dispatch pushes', -24, 24, 'entry'),
        dispatch.slot('dispatch reply', 96, 8),
        dispatch.slot('close reply', 104, 8),
        dispatch.slot('join reply', 32, 8),
        copy.slot('copy adapter saved RBX', -8, 8, 'entry'),
    ]
    return dict(spans=spans, frames={name: dict(entry_from_high=f.entry-window.high,
                current_from_high=f.current-window.high) for name,f in
                (('body',body), ('root',root), ('leaf',leaf), ('closure',closure),
                 ('dispatch',dispatch), ('copy_adapter',copy))},
                unknown_callees=[dispatch.unknown_callee('CallEnclave entry/home'),
                                 copy.unknown_callee('SDK copy entry/home')],
                maximum_transitive_depth_qualified=False, runtime_placement_measured=False)
