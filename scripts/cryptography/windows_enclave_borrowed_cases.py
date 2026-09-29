"""Public-only buffers for the direct-copy experiment, not a production adapter."""
import ctypes as c
import hashlib
import struct
from windows_enclave_wire_cases import WireHandshake, token_check, PUBLIC
from windows_enclave_sha256_build import vectors
from windows_protection_probe import require

MODES = ('publish', 'mutate', 'cancel', 'bad-header', 'bad-source', 'bad-input',
         'page-fault', 'bad-destination', 'deny-copy', 'enclave-input')


def messages(mode):
    require(mode in MODES, 'known borrowed-input campaign')
    return vectors() if mode in ('publish', 'mutate', 'cancel') else [b'a' * 64] * 3


def outcome(mode):
    status = {'publish': 1, 'mutate': 1, 'cancel': 2, 'bad-header': 10,
              'bad-source': 11, 'bad-input': 11, 'page-fault': 11,
              'bad-destination': 12, 'deny-copy': 11, 'enclave-input': 11}[mode]
    hooks = 2 if status in (1, 2, 12) else 0
    return status, 21 if hooks else 0, hooks


class Request:
    def __init__(self, mode, iteration, host=None):
        self.mode, self.message = mode, messages(mode)[iteration]
        self.wire, self.command = (c.c_ubyte * 64)(), (c.c_ubyte * 64)()
        self.payload = (c.c_ubyte * len(self.message))(*self.message)
        self.output = (c.c_ubyte * 48)(*([0xa5] * 48))
        self.destination = c.addressof(self.output) + 8
        self.offers, self.copies, self.allocation, self.host = [], 0, None, host
        address = c.addressof(self.payload) if self.message else 0
        if mode == 'bad-input':
            address = 1
        if mode == 'page-fault':
            require(host is not None, 'real page-fault allocation required')
            self.allocation = host.reserve(8192)
            try:
                host.commit(self.allocation, 4096)
                address = self.allocation + 4096 - 32
                c.memset(address, 0x5a, 32)
            except BaseException:
                self.close()
                raise
        header = [4 if mode == 'bad-header' else 3, 0, len(self.message), address,
                  c.addressof(self.command), 64, 0, 0]
        self.wire[:] = struct.pack('<8Q', *header)
        self.source = 1 if mode == 'bad-source' else c.addressof(self.wire)

    def close(self):
        if self.allocation is not None:
            self.host.ok(self.host.dll.VirtualFree(self.allocation, 0, 0x8000), 'release input fault fixture')
            self.allocation = None

    def copied(self):
        self.copies += 1
        require(self.copies == 1 and bool(self.message), 'exactly one nonempty payload copy')
        if self.mode == 'mutate':
            self.wire[:] = b'\xff' * 64
            self.payload[:] = b'\xcc' * len(self.payload)
        return self.mode != 'deny-copy'

    def exchange(self, step):
        require(step == len(self.offers) and step in (0, 1), 'ordered exchanges')
        words = list(struct.unpack('<8Q', bytes(self.command)))
        token_check(words[:4])
        require(words[4:] == [outcome(self.mode)[0] if step else 0, 0, 0, 0], 'exact offer')
        if step:
            require(words[:4] == self.offers[0][:4], 'stable result identity')
        self.offers.append(words)
        action, flag, destination, width = 1, PUBLIC, self.destination, 32
        if self.mode == 'cancel':
            action, flag, destination, width = 2, 0, 0, 0
        if self.mode == 'bad-destination':
            destination = 1
        self.command[:] = struct.pack('<8Q', *words[:4], action, flag, destination, width)
        return True

    def check_output(self):
        raw = bytes(self.output)
        require(raw[:8] == raw[40:] == b'\xa5' * 8, 'output canaries')
        digest = hashlib.sha256(self.message).digest()
        success = outcome(self.mode)[0] == 1
        require(raw[8:40] == (digest if success else b'\xa5' * 32), 'independent digest/output preservation')
        return digest.hex() if success else None


class BorrowedHandshake(WireHandshake):
    def __call__(self, argument):
        if type(argument) is int and argument & 15 == 0 and self.request.mode == 'enclave-input':
            admitted = super().__call__(argument)
            if admitted == 1:
                # Only alter our public header, never dereference enclave memory.
                # This address is within the fully admitted 64 KiB window, not
                # an invalid/null host pointer accidentally testing another case.
                self.request.wire[24:32] = struct.pack('<Q', self.low + 4096)
            return admitted
        if type(argument) is not int or argument & 15 != 4:
            return super().__call__(argument)
        try:
            require(self.phase == 'admitted' and self.locked and argument & ~15 == self.low,
                    'payload copy inside locked worker')
            return int(self.request.copied())
        except BaseException as error:
            if self.error is None:
                self.error = error
            return 0


def validate_report(values, base, low, high, mode, iteration):
    require(type(values) is list and len(values) == 8
            and all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'complete worker report')
    status, snapshot, workspace, output, absorbed, cleared, replay, size = values
    regions = [(snapshot, 1152), (workspace, 1170), (output, 32)]
    require(all(low <= p and p + n <= high for p, n in regions), 'bounded input/owner storage')
    require(all(p + n <= q or q + m <= p for i, (p, n) in enumerate(regions)
                for q, m in regions[i + 1:]), 'disjoint input/owner storage')
    first, second, hooks = outcome(mode)
    require((status, replay, absorbed, cleared, size) ==
            (first, second, len(messages(mode)[iteration]) if hooks else 0, 1, 1170), 'exact cleanup/outcome')
    return [status, snapshot - base, workspace - base, output - base, absorbed, cleared, replay, size]


def validate_offers(offers, mode, iteration, previous):
    first, _, hooks = outcome(mode)
    require(type(offers) is list and len(offers) == hooks, 'exact offer count')
    for step, offer in enumerate(offers):
        require(type(offer) is list and len(offer) == 8, 'complete offer')
        token_check(offer[:4])
        require(offer[4:] == [first if step else 0, 0, 0, 0], 'offer disposition')
        require(offer[:4] == offers[0][:4], 'stable scope')
    if not offers:
        return previous
    token = offers[0][:4]
    require(token[2] == iteration + 1, 'advancing epoch')
    if previous:
        require(token[:2] == previous[:2] and token[2] == previous[2] + 1, 'instance continuity')
    return token


def copy_count(mode, iteration):
    return int(bool(messages(mode)[iteration]) and mode not in
               ('bad-header', 'bad-source', 'bad-input', 'page-fault', 'enclave-input'))
