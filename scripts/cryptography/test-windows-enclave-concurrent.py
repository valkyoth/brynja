#!/usr/bin/env python3
"""Exercise concurrency orchestration and failure cleanup without secret data."""
import threading
import unittest

from windows_enclave_concurrent import INVALID, exercise
from windows_protection_probe import ProbeError


class Fake:
    def __init__(self, fault=None):
        self.fault = fault
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.active = set()
        self.claimed = set()
        self.completed = set()
        self.terminated = False
        self.deleted = False

    def create(self):
        return 1

    def load(self, base, image):
        return self.fault != 'load', 577

    def initialize(self, base):
        return 1 if self.fault == 'count' else 5

    def export(self, base, name):
        if self.fault == 'export':
            raise ProbeError('missing export')
        return 'worker' if name == b'PublicConcurrentWorker' else 'control'

    def call(self, routine, value):
        if routine == 'control':
            with self.lock:
                if value == 0:
                    return 32 if self.fault == 'mask' else sum(1 << i for i in self.active)
                if value == 1:
                    self.release.set()
                    return 0 if self.fault == 'release' else 1
                if value == 2:
                    return 1 if self.fault == 'early' else sum(1 << i for i in self.completed)
                if value == 3:
                    return 1 if self.fault == 'exhausted' else 0
                return 0 if self.fault == 'control' else INVALID
        with self.lock:
            if value >= 4:
                return 0 if self.fault == 'lane' else INVALID
            if value in self.claimed:
                return 0 if self.fault == 'duplicate' else INVALID
            self.claimed.add(value)
            self.active.add(value)
        self.release.wait(1)
        with self.lock:
            self.active.remove(value)
            self.completed.add(value)
        if self.fault == 'worker':
            raise ProbeError('worker failure')
        return 0 if self.fault == 'result' else value + 100

    def terminate(self, base):
        assert not self.active, 'termination before worker exit'
        self.terminated = True

    def delete(self, base):
        assert not self.active, 'deletion before worker exit'
        self.deleted = True


class Tests(unittest.TestCase):
    def test_overlap_and_join(self):
        api = Fake()
        record = exercise(api, 'synthetic', 0.2)
        self.assertEqual(record['overlapping_worker_mask'], 15)
        self.assertTrue(record['synthetic_only'])
        self.assertFalse(record['production_qualified'])
        self.assertTrue(api.terminated and api.deleted)

    def test_failures_release_join_and_delete(self):
        for fault in ('load', 'count', 'export', 'mask', 'release', 'early',
                      'exhausted', 'control', 'lane', 'duplicate', 'worker', 'result'):
            with self.subTest(fault=fault):
                api = Fake(fault)
                with self.assertRaises(ProbeError):
                    exercise(api, 'synthetic', 0.2)
                self.assertTrue(api.deleted)
                self.assertFalse(api.active)

    def test_live_worker_blocks_deletion(self):
        api = Fake()
        original = api.call
        stalled = threading.Event()

        def call(routine, value):
            if routine == 'worker' and value == 0:
                stalled.wait(1)
                return 100
            return original(routine, value)

        api.call = call
        try:
            with self.assertRaisesRegex(ProbeError, 'refusing unsafe enclave deletion'):
                exercise(api, 'synthetic', 0.02)
            self.assertFalse(api.terminated or api.deleted)
        finally:
            stalled.set()


if __name__ == '__main__':
    unittest.main()
