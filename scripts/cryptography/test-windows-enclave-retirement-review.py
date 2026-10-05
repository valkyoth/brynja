"""Focused saved-code binding/predicate regressions; not an enclave execution."""
import hashlib
import json
import unittest
from unittest.mock import patch

import windows_enclave_retirement_review as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n: bytearray(s[1]) for n, s in review.BODIES.items()}
        refs = {}
        for name, calls in review.CALLS.items():
            refs[name] = [dict(offset=o, symbol=s, addend=0, trailing=0) for o, s in calls.items()]
            for offset in calls: bodies[name][offset-1:offset+4] = b'\xe8\0\0\0\0'
        for name, offset, hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)] = code
        for name, offset, opcode, target in review.BRANCHES:
            width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
            end = offset+len(opcode)+width
            bodies[name][offset:end] = opcode+(target-end).to_bytes(width, 'little', signed=True)
        return {n: bytes(b) for n, b in bodies.items()}, refs

    def test_instruction_and_branch_mutations(self):
        bodies, refs = self.synthetic()
        review.check_instructions(bodies, refs)
        sites = [(n, o, len(bytes.fromhex(h))) for n, o, h in review.ANCHORS]
        sites += [(n, o-1, 5) for n, calls in review.CALLS.items() for o in calls]
        sites += [(n, o, len(op)+(4 if len(op) == 2 or op == b'\xe9' else 1))
                  for n, o, op, _ in review.BRANCHES]
        for name, offset, size in sites:
            for index in range(offset, offset+size):
                altered = bytearray(bodies[name])
                altered[index] ^= 1
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies | {name: bytes(altered)}, refs)

    def test_call_target_addend_and_shape(self):
        bodies, refs = self.synthetic()
        for name, rows in refs.items():
            for field, value in (('symbol', 'other'), ('addend', 1), ('trailing', 1), ('offset', 0)):
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies, refs | {name: [rows[0] | {field: value}, *rows[1:]]})
            for changed in (rows[1:], rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies, refs | {name: changed})

    def test_complete_relocation_inventory(self):
        _, refs = self.synthetic()
        hashes = {n: hashlib.sha256(json.dumps(r, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                  for n, r in refs.items()}
        with patch.dict(review.REFERENCES, hashes, clear=True):
            review.check_references(refs)
            for name, rows in refs.items():
                variants = [rows[1:], rows+[rows[0]]]
                if len(rows) > 1: variants.append(list(reversed(rows)))
                for changed in variants:
                    with self.assertRaises(ValueError): review.check_references(refs | {name: changed})
            with self.assertRaises(ValueError): review.check_references({})

    def test_exact_body_population(self):
        bodies, _ = self.synthetic()
        specs = {n: (review.BODIES[n][0], len(b), hashlib.sha256(b).hexdigest()) for n, b in bodies.items()}
        count = 0
        with patch.dict(review.BODIES, specs, clear=True):
            review.check_bodies(bodies)
            for name, body in bodies.items():
                for index in range(len(body)):
                    altered = bytearray(body)
                    altered[index] ^= 1
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name: bytes(altered)})
                    count += 1
                for changed in (body[:-1], body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name: changed})
                with self.assertRaises(ValueError):
                    review.check_bodies({n: b for n, b in bodies.items() if n != name})
            with self.assertRaises(ValueError): review.check_bodies(bodies | {'extra': b''})
        self.assertEqual(count, 5490)

    def test_readers_live_workers_reservation_and_wrong_generation(self):
        for generation in (1, 33, 16384):
            for lanes in range(1, 5):
                mask = (1 << lanes)-1
                ready = (generation << 32) | 0x20000 | (mask << 12) | (mask << 8) | mask
                self.assertTrue(review.retirement_ready(ready, generation))
                self.assertFalse(review.retirement_ready(ready, generation-1))
                for readers in range(1, 4096):
                    self.assertFalse(review.retirement_ready(ready | (readers << 20), generation))
                for live in range(1, 16):
                    self.assertFalse(review.retirement_ready(ready | (live << 4), generation))
                for bit in (16, 18):
                    self.assertFalse(review.retirement_ready(ready | (1 << bit), generation))
                self.assertFalse(review.retirement_ready(ready & ~0x20000, generation))

    def test_every_claim_success_and_expected_mask(self):
        for expected in range(16):
            for claimed in range(16):
                for success in range(16):
                    word = (7 << 32) | 0x20000 | (expected << 12) | (success << 8) | claimed
                    self.assertEqual(review.retirement_ready(word, 7), expected != 0 and expected == claimed == success)
        for bad in (-1, 1 << 64, True, 0.5):
            with self.assertRaises(ValueError): review.retirement_ready(bad, 1)
        for bad in (-1, 1 << 32, True, 0.5):
            with self.assertRaises(ValueError): review.retirement_ready(0, bad)

    def test_identity_before_parsing(self):
        with patch.object(review.caller, 'function', side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object', b'native', b'image')


if __name__ == '__main__': unittest.main()
