"""Public buffers and exact outcomes for the nonqualifying wire experiment."""
import ctypes as c
import hashlib
import struct

from windows_enclave_window_lock import Handshake
from windows_protection_probe import require

MODES = ('publish', 'mutate', 'cancel', 'foreign', 'stale', 'cross-instance',
         'no-public', 'bad-slot', 'bad-version', 'bad-source', 'bad-destination',
         'deny-first', 'deny-second')
PUBLIC = 0x5055424c4943


def outcome(mode, iteration):
    require(mode in MODES and type(iteration) is int and iteration in range(3), 'fixed wire campaign')
    first = {'publish': 1, 'mutate': 1, 'cancel': 2, 'foreign': 10,
             'stale': 1 if iteration == 0 else 10, 'cross-instance': 10,
             'no-public': 10, 'bad-slot': 10, 'bad-version': 10, 'bad-source': 11,
             'bad-destination': 12, 'deny-first': 13, 'deny-second': 1}[mode]
    hooks = 0 if mode in ('bad-version', 'bad-source') else 1 if mode == 'deny-first' else 2
    replay = 0 if hooks < 2 else 13 if mode == 'deny-second' else 21
    return first, replay, hooks


def message(mode, iteration):
    outcome(mode, iteration)
    length = (0, 56, 1024)[iteration] if mode == 'publish' else 3
    return bytes((i * 17 + 3) % 256 for i in range(length))


def token_check(token):
    require(type(token) is list and len(token) == 4
            and all(type(v) is int and 0 <= v < 1 << 64 for v in token)
            and token[0] | token[1] != 0 and token[2] > 0 and token[3] == 1,
            'complete public instance/scope token')


class Request:
    def __init__(self, mode, iteration, previous=None, foreign=None):
        self.mode, self.iteration = mode, iteration
        self.message = message(mode, iteration)
        self.previous, self.foreign = previous, foreign
        self.offers = []
        self.wire, self.command = (c.c_ubyte * 1072)(), (c.c_ubyte * 64)()
        self.output = (c.c_ubyte * 48)(*([0xa5] * 48))
        self.destination = c.addressof(self.output) + 8
        header = [3 if mode == 'bad-version' else 2, 0, len(self.message),
                  c.addressof(self.command), 64, 0]
        self.wire[:] = struct.pack('<6Q', *header) + self.message.ljust(1024, b'\0')
        self.source = 1 if mode == 'bad-source' else c.addressof(self.wire)

    def exchange(self, step):
        require(step == len(self.offers) and step in (0, 1), 'ordered wire exchanges')
        words = list(struct.unpack('<8Q', bytes(self.command)))
        token_check(words[:4])
        require(words[4:] == [0 if step == 0 else outcome(self.mode, self.iteration)[0], 0, 0, 0],
                'exact offer status and reserved fields')
        if step:
            require(words[:4] == self.offers[0][:4], 'same scope throughout exchange')
        self.offers.append(words)
        token = words[:4]
        if self.mode == 'foreign':
            token[0] ^= 1
        elif self.mode == 'stale' and self.iteration:
            require(self.previous is not None, 'previous scope token required')
            token = self.previous[:]
        elif self.mode == 'cross-instance':
            require(self.foreign is not None, 'donor instance token required')
            token = self.foreign[:]
        elif self.mode == 'bad-slot':
            token[3] = 2
        action, flags, destination, width = 1, PUBLIC, self.destination, 32
        if self.mode == 'cancel':
            action, flags, destination, width = 2, 0, 0, 0
        elif self.mode == 'no-public':
            flags = 0
        elif self.mode == 'bad-destination':
            destination = 1
        self.command[:] = struct.pack('<8Q', *token, action, flags, destination, width)
        if self.mode == 'mutate':
            self.wire[:] = b'\xff' * 1072
        return not ((self.mode == 'deny-first' and step == 0)
                    or (self.mode == 'deny-second' and step == 1))

    def check_output(self):
        raw = bytes(self.output)
        require(raw[:8] == raw[40:] == b'\xa5' * 8, 'host output canaries')
        success = outcome(self.mode, self.iteration)[0] == 1
        digest = hashlib.sha256(self.message).digest()
        require(raw[8:40] == (digest if success else b'\xa5' * 32), 'exact public output disposition')
        return digest.hex() if success else None


class WireHandshake(Handshake):
    def __init__(self, host, base, request):
        super().__init__(host, base)
        self.request = request

    def __call__(self, argument):
        if type(argument) is not int or argument & 15 not in (2, 3):
            return super().__call__(argument)
        try:
            require(self.phase == 'admitted' and self.locked and argument & ~15 == self.low,
                    'wire exchange inside admitted window')
            return int(self.request.exchange((argument & 15) - 2))
        except BaseException as error:
            if self.error is None:
                self.error = error
            return 0


def validate_report(values, base, low, high, mode, iteration):
    require(type(values) is list and len(values) == 8
            and all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'complete wire report')
    status, snapshot, workspace, output, absorbed, cleared, replay, size = values
    regions = [(snapshot, 1136), (workspace, 1170), (output, 32)]
    require(all(low <= p and p + n <= high for p, n in regions), 'bounded wire storage')
    require(all(p + n <= q or q + m <= p for i, (p, n) in enumerate(regions)
                for q, m in regions[i + 1:]), 'disjoint wire storage')
    first, second, hooks = outcome(mode, iteration)
    require((status, replay, absorbed, cleared, size) ==
            (first, second, len(message(mode, iteration)) if hooks else 0, 1, 1170),
            'exact wire/cleanup outcome')
    return [status, snapshot - base, workspace - base, output - base, absorbed, cleared, replay, size]


def validate_offers(offers, mode, iteration, previous):
    first, _, hooks = outcome(mode, iteration)
    require(type(offers) is list and len(offers) == hooks, 'exact wire hook count')
    for step, offer in enumerate(offers):
        require(type(offer) is list and len(offer) == 8
                and all(type(v) is int for v in offer), 'complete public offer')
        token_check(offer[:4])
        require(offer[4:] == [first if step else 0, 0, 0, 0], 'exact public offer outcome')
        require(offer[:4] == offers[0][:4], 'stable scope during call')
    if offers:
        token = offers[0][:4]
        require(token[2] == iteration + 1, 'strictly increasing admitted scope epoch')
        if previous:
            require(token[:2] == previous[:2] and token[2] == previous[2] + 1,
                    'stable instance and advancing scope')
        return token
    return previous
