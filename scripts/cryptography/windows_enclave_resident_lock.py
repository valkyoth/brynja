"""Trusted-host staging residency diagnostic; never reads enclave payload."""
from windows_enclave_window_lock import Handshake, flags_check, PAGE
from windows_enclave_worker import LIMIT
from windows_protection_probe import Layout, require


class Resident:
    def __init__(self, host, base, fault=None):
        require(fault in (None, 'deny-stage', 'after-stage-lock', 'stage-observe', 'deny'),
                'known staging fault')
        self.host, self.base, self.fault = host, base, fault
        self.window = Handshake(host, base, deny=fault == 'deny')
        self.page, self.phase, self.locked, self.error = None, 'new', False, None
        self.events, self.snapshots = [], {}

    def snapshot(self, name, locked):
        flags = self.host.working_set(self.page, Layout(PAGE, PAGE, PAGE))
        flags_check(flags, PAGE, locked)
        self.snapshots[name] = flags

    def __call__(self, argument):
        try:
            require(type(argument) is int and 0 < argument < 1 << 64, 'integer staging event')
            event, page = argument & 15, argument & ~15
            if event in (0, 1):
                require(self.phase == 'observed' and self.locked,
                        'compute only after staged-page residency observation')
                if event == 0:
                    require(page + 65536 + PAGE <= self.page - PAGE or
                            self.page + 2*PAGE <= page - PAGE,
                            'complete staging reservation distinct from guarded stack')
                self.events.append('window-'+str(event))
                value = self.window(argument)
                require(self.window.error is None, 'inner window callback failed')
                return value
            require(event in (8, 9, 10) and page % PAGE == 0 and
                    self.base <= page-PAGE < page+2*PAGE <= self.base+LIMIT,
                    'complete aligned staging reservation inside enclave')
            if event == 8:
                require(self.phase == 'new', 'one staging admission')
                self.page, self.phase = page, 'attempted'
                self.events.append('stage-admit')
                if self.fault == 'deny-stage':
                    self.events.append('stage-deny')
                    return 0
                self.snapshot('before', False)
                self.host.lock(page, PAGE)
                self.locked = True
                self.events.append('stage-lock')
                self.snapshot('admitted', True)
                if self.fault == 'after-stage-lock':
                    self.events.append('stage-reject-after-lock')
                    return 0
                self.phase = 'admitted'
                return 1
            require(page == self.page, 'same live staging allocation')
            if event == 9:
                require(self.phase == 'admitted' and self.locked, 'observe admitted page')
                self.snapshot('staged', True)
                self.events.append('stage-observe')
                if self.fault == 'stage-observe':
                    self.events.append('stage-reject-observe')
                    return 0
                self.phase = 'observed'
                return 1
            require(self.phase in ('attempted', 'admitted', 'observed') and
                    self.window.phase in ('new', 'finished') and not self.window.locked,
                    'retire once and only after compute retirement')
            self.events.append('stage-clear-confirmed')
            if self.locked:
                self.snapshot('cleared', True)
                self.host.unlock(page, PAGE)
                self.locked = False
                self.events.append('stage-unlock')
            self.phase = 'finished'
            self.events.append('stage-finish')
            return 1
        except BaseException as error:
            self.error = error
            self.events.append('callback-error')
            return 0
