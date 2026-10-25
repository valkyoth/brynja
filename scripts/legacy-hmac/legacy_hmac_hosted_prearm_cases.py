"""Independent public-shape oracle and boundary populations, not real buffers."""
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Request:
    key: int = 4
    chunks: tuple = (1, 2)
    tail: int = 1
    bits: int = 8
    max_key: int = 8
    max_chunks: int = 8
    max_bits: int = 128
    width: int = 16
    candidate: object = None
    cancelled: bool = False
    quarantined: bool = False

    def error(self):
        if self.quarantined:
            return 9
        if self.key > self.max_key or len(self.chunks) > self.max_chunks:
            return 3
        if (self.tail == 0 and self.bits != 0) or (self.tail > 0 and not 1 <= self.bits <= 8):
            return 4
        bits = (self.tail - 1) * 8 + self.bits if self.tail else 0
        bits += sum(self.chunks) * 8
        if bits > min(self.max_bits, 2**128 - 1):
            return 3
        if self.candidate is not None and self.candidate != self.width:
            return 5
        return 6 if self.cancelled else None


def scalar(identity):
    top = 16 if identity == 'md5' else 20
    base = Request(width=top)
    cases = []
    for width in range(10, top + 1):
        for candidate in (None, 0, width - 1, width, width + 1, 2**63 - 1):
            cases.append(replace(base, width=width, candidate=candidate))
    for length in (0, 1, 8, 9, 2**63 - 1):
        cases.append(replace(base, key=length))
    for count in range(10):
        for limit in (max(0, count - 1), count, count + 1):
            cases.append(replace(base, chunks=tuple(i % 3 for i in range(count)), max_chunks=limit))
    for chunks in ((), (0,), (7,), (0, 7), (2, 3, 5), tuple(range(17)), (2**63 - 1, 2**63 - 1)):
        for tail in (0, 1, 3):
            bits = 0 if not tail else 5
            total = sum(chunks) * 8 + ((tail - 1) * 8 + bits if tail else 0)
            for budget in (max(0, total - 1), total, total + 1, 2**128 - 1):
                cases.append(replace(base, chunks=chunks, tail=tail, bits=bits, max_bits=budget, max_chunks=20))
    for tail in (0, 1, 3, 2**63 - 1):
        for bits in (*range(10), 255):
            cases.append(replace(base, tail=tail, bits=bits, max_bits=2**128 - 1))
    cases.extend((replace(base, key=9, bits=0), replace(base, max_chunks=0, bits=0),
                  replace(base, bits=0, candidate=0), replace(base, max_bits=0, candidate=0)))
    cases += [replace(case, candidate=case.width) for case in cases if case.candidate is None]
    cases = list(dict.fromkeys(cases))
    cases += [replace(case, cancelled=True) for case in cases]
    if identity == 'sha1_compiled':
        cases += [replace(case, quarantined=True) for case in cases[:20]]
    return cases


@dataclass(frozen=True)
class Batch:
    mask: int = 255
    backend: int = 0
    keys: tuple = (4,) * 8
    tails: tuple = (1,) * 8
    bits: tuple = (8,) * 8
    max_key: int = 8
    max_bits: int = 128
    width: int = 16
    candidate: object = None
    cancelled: bool = False
    quarantined: bool = False

    def error(self):
        if self.quarantined:
            return 9
        width = 4 if self.backend else 8
        if not any(all(self.mask & (1 << lane) for lane in range(start, start + width))
                   for start in range(0, 8, width)):
            return 7
        for lane in range(8):
            active = bool(self.mask & (1 << lane))
            if active:
                if self.keys[lane] > self.max_key:
                    return 3
                length, bits = self.tails[lane], self.bits[lane]
                if (not length and bits) or (length and not 1 <= bits <= 8):
                    return 4
                if ((length - 1) * 8 + bits if length else 0) > self.max_bits:
                    return 3
            if self.candidate is not None:
                value = self.candidate[lane]
                if (value is not None) != active or active and value != self.width:
                    return 5
        return 6 if self.cancelled else None


def batch():
    cases = []
    for backend in (0, 1):
        for mask in range(256):
            base = Batch(mask=mask, backend=backend)
            candidates = tuple(base.width if mask & (1 << lane) else None for lane in range(8))
            cases.extend((base, replace(base, candidate=candidates)))
        base = Batch(backend=backend)
        for lane in range(8):
            def changed(field, value):
                items = list(getattr(base, field))
                items[lane] = value
                return replace(base, **{field: tuple(items)})
            cases += [changed('keys', n) for n in (0, 8, 9, 2**63 - 1)]
            cases += [changed('bits', n) for n in (*range(10), 255)]
            cases += [changed('tails', n) for n in (0, 16, 17, 2**63 - 1)]
            for value in (None, 0, 15, 16, 17):
                candidates = [16] * 8
                candidates[lane] = value
                cases.append(replace(base, candidate=tuple(candidates)))
        for width in range(10, 17):
            cases += [replace(base, width=width, candidate=(n,) * 8) for n in (width - 1, width, width + 1)]
        for length in (0, 1, 2**63 - 1):
            for bits in (0, 1, 7, 8, 9, 255):
                for limit in (0, 8, 2**128 - 1):
                    cases.append(replace(base, tails=(length,) * 8, bits=(bits,) * 8, max_bits=limit))
        # A complete NEON group can coexist with absent lanes. Verification
        # must reject extra candidates as well as missing/wrong-width tags.
        for mask in (15, 240):
            for lane in range(8):
                candidates = [16 if mask & (1 << i) else None for i in range(8)]
                candidates[lane] = None if mask & (1 << lane) else 16
                cases.append(replace(base, mask=mask, candidate=tuple(candidates)))
        for lane in range(7):
            keys, bits = [4] * 8, [8] * 8
            bits[lane], keys[lane + 1] = 0, 9
            cases.append(replace(base, keys=tuple(keys), bits=tuple(bits), candidate=(0,) * 8))
    # Optimizers split validation into compute-only and verification-only
    # loops. Every shape boundary must exercise both emitted copies.
    cases += [replace(case, candidate=tuple(case.width if case.mask & (1 << lane) else None for lane in range(8)))
              for case in cases if case.candidate is None]
    cases = list(dict.fromkeys(cases))
    cases += [replace(case, cancelled=True) for case in cases]
    cases += [replace(case, quarantined=True) for case in cases[:20]]
    return cases
