#!/usr/bin/env python3
"""Trusted-host live-window locking experiment, never platform qualification."""
from windows_enclave_worker import LIMIT
from windows_protection_probe import Layout, require, locked_pages

SIZE, PAGE = 65536, 4096
FAULTS = ('after-lock', 'after-observe', 'before-unlock')


def geometry(low, base):
    require(type(low) is int and type(base) is int and 0 <= base < 1 << 64
            and base <= low < low + SIZE <= min(base + LIMIT, 1 << 64)
            and low % 16 == 0, 'bounded aligned live enclave window')
    start = low // PAGE * PAGE
    end = (low + SIZE + PAGE - 1) // PAGE * PAGE
    require(base <= start < end <= base + LIMIT, 'rounded window inside enclave')
    return start, end - start


def flags_check(flags, size, locked):
    require(type(flags) is list and len(flags) == size // PAGE
            and all(type(f) is int and 0 <= f < 1 << 64 for f in flags),
            'complete live-window page observation')
    if locked:
        locked_pages(flags)
    else:
        # VirtualLock has no reference count: never release another owner's lock.
        require(all(not (f & 1 and f & (1 << 22)) for f in flags),
                'live window already locked by another owner')


class Handshake:
    """One operation, one synchronous worker; no host dereference of enclave bytes.

    The finish notification is trusted synthetic image behavior, not attestation
    against a malicious host/image. Exceptions cannot escape a ctypes callback.
    """
    def __init__(self, host, base, deny=False, fault=None):
        require(fault is None or fault in FAULTS, 'known callback fault')
        self.host, self.base, self.deny, self.fault = host, base, deny, fault
        self.low = self.start = self.size = None
        self.phase, self.locked, self.error = 'new', False, None
        self.trace, self.snapshots = [], {}

    def snapshot(self, label, locked):
        flags = self.host.working_set(self.start, Layout(PAGE, self.size, self.size))
        flags_check(flags, self.size, locked)
        self.snapshots[label] = flags

    def inject(self, stage):
        if self.fault == stage:
            raise RuntimeError('injected callback fault: ' + stage)

    def __call__(self, argument):
        try:
            require(type(argument) is int and 0 < argument < 1 << 64,
                    'integer callback argument')
            event, low = argument & 15, argument & ~15
            require(event in (0, 1), 'known callback event')
            start, size = geometry(low, self.base)
            if event == 0:
                require(self.phase == 'new', 'admission must occur exactly once')
                self.low, self.start, self.size = low, start, size
                self.phase = 'admitting'
                self.trace.append('admit')
                if self.deny:
                    self.trace.append('deny')
                    return 0
                self.snapshot('before', False)
                self.host.lock(start, size)
                self.locked = True
                self.trace.append('lock')
                self.inject('after-lock')
                self.snapshot('admitted', True)
                self.trace.append('all-pages-locked')
                self.inject('after-observe')
                self.phase = 'admitted'
                self.trace.append('admit-ack')
                return 1
            require(self.phase in ('admitting', 'admitted') and low == self.low,
                    'finish must match the admitted live window')
            self.phase = 'finishing'
            self.trace.append('clear-confirmed')
            if self.locked:
                self.snapshot('cleared', True)
                self.trace.append('still-locked')
                self.inject('before-unlock')
                self.host.unlock(start, size)
                self.locked = False
                self.trace.append('unlock')
            self.phase = 'finished'
            self.trace.append('finish-ack')
            return 1
        except BaseException as error:
            if self.error is None:
                self.error = error
            self.trace.append('callback-error')
            return 0


def validate(values, base, unwind, mutant, deny, trace, snapshots, locked):
    require(not (mutant and deny), 'denial and mutant are separate controls')
    require(len(values) == 8 and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
            'complete integer live-window result')
    result, low, high, handler, marker, steps, cleared, admitted = values
    start, size = geometry(low, base)
    require(high == low + SIZE, 'exact live window size')
    expected = 0 if deny else (47 if unwind else 31)
    require(steps == expected and admitted == int(not deny)
            and cleared == int(not mutant)
            and result == (0 if mutant else expected | 64), 'exact execution/cleanup outcome')
    if deny:
        require(handler == marker == 0, 'denied body must not execute')
    else:
        require(low <= handler < high and low <= marker <= high - 256
                and not marker <= handler < marker + 256, 'distinct body frames inside live window')
    expected_trace = ['admit', 'deny'] if deny else ['admit', 'lock', 'all-pages-locked', 'admit-ack']
    if not mutant:
        expected_trace += ['clear-confirmed']
        if not deny:
            expected_trace += ['still-locked', 'unlock']
        expected_trace += ['finish-ack']
    require(trace == expected_trace and locked is mutant, 'exact callback ordering and lock ownership')
    names = set() if deny else ({'before', 'admitted'} if mutant else {'before', 'admitted', 'cleared'})
    require(type(snapshots) is dict and set(snapshots) == names, 'complete phase observations')
    for name, flags in snapshots.items():
        flags_check(flags, size, name != 'before')
    return {'values': [result, low - base, high - base,
                       handler - base if handler else 0, marker - base if marker else 0,
                       steps, cleared, admitted], 'trace': trace, 'snapshots': snapshots,
            'locked_until_teardown': locked, 'page_count': size // PAGE,
            'rounded_start_offset': start - base}
