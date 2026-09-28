#!/usr/bin/env python3
"""Portable failure-injection tests; these do not qualify Windows behavior."""
import ctypes as c
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import windows_protection_probe as probe
import windows_protection_api as native


class Fake:
    def __init__(self, failure=None):
        self.failure, self.events, self.value = failure, [], None

    def event(self, name):
        self.events.append(name)
        if name == self.failure:
            raise probe.ProbeError('injected ' + name)

    def geometry(self):
        self.event('geometry')
        return 4096, 65536

    def reserve(self, size):
        self.event('reserve')
        assert size == 65536
        return 0x100000

    def commit(self, address, size):
        self.event('commit')
        assert (address, size) == (0x101000, 8192)

    def check_regions(self, *_):
        self.event('regions')

    def lock(self, *_):
        self.event('lock')

    def working_set(self, *_):
        self.event('working_set')
        return [1 | (1 << 22)] * 2

    def register(self, *_):
        self.event('register')

    def fill(self, address, size, value):
        self.event('clear' if value == 0 else 'fill')
        assert (address, size) == (0x101000, 8192)
        self.value = value

    def matches(self, address, size, value):
        self.event('clear_readback' if value == 0 else 'readback')
        assert (address, size) == (0x101000, 8192)
        return self.value == value

    def unregister(self, *_):
        self.event('unregister')

    def unlock(self, *_):
        self.event('unlock')

    def release(self, base):
        assert base == 0x100000
        self.event('release')


class Tests(unittest.TestCase):
    def test_layout_boundaries(self):
        for page in (4096, 16384, 65536):
            for size in (1, page, page + 1, 1048576):
                shape = probe.layout(page, 65536, size)
                self.assertGreaterEqual(shape.payload, size)
                self.assertEqual(shape.payload % page, 0)
                self.assertLess(shape.payload - size, page)
                self.assertGreaterEqual(shape.reserved, shape.payload + 2 * page)
                self.assertEqual(shape.reserved % 65536, 0)
        for size in (0, -1, True, 1048577, 2**64, 1.5):
            with self.subTest(size=size), self.assertRaises(probe.ProbeError):
                probe.layout(4096, 65536, size)
        for page, granularity in ((0, 65536), (4097, 65536), (131072, 131072),
                                  (4096, 4097), (4096, 2048), (4096, 2**32)):
            with self.subTest(page=page, granularity=granularity), self.assertRaises(probe.ProbeError):
                probe.layout(page, granularity, 1)

    def test_valid_and_locked_are_both_required(self):
        for flags in ([], [0], [1], [1 << 22], [1 | (1 << 22), 1]):
            with self.subTest(flags=flags), self.assertRaises(probe.ProbeError):
                probe.locked_pages(flags)
        probe.locked_pages([1 | (1 << 22)])

    def test_success_order_and_nonqualification(self):
        api = Fake()
        result = probe.record(probe.experiment(api), {'test_only': True})
        self.assertEqual(api.events, ['geometry', 'reserve', 'commit', 'regions', 'lock',
                                     'working_set', 'register', 'fill', 'readback',
                                     'working_set', 'clear', 'clear_readback',
                                     'unregister', 'unlock', 'release'])
        self.assertEqual(result['status'], 'OBSERVATIONS_ONLY')
        for name in ('strict_qualified', 'dump_exclusion_verified', 'protected_worker_stack_verified'):
            self.assertIs(result[name], False)
        json.dumps(result)

    def test_every_failure_rejects_and_rolls_back_only_acquired_resources(self):
        for failure in ('geometry', 'reserve', 'commit', 'regions', 'lock', 'working_set',
                        'register', 'fill', 'readback'):
            api = Fake(failure)
            with self.subTest(failure=failure), self.assertRaises(probe.ProbeError):
                probe.experiment(api)
            acquired = failure not in ('geometry', 'reserve')
            committed = acquired and failure != 'commit'
            locked = committed and failure not in ('regions', 'lock')
            registered = failure in ('fill', 'readback')
            expected = (['clear', 'clear_readback'] if committed else [])
            expected += ['unregister'] if registered else []
            expected += ['unlock'] if locked else []
            expected += ['release'] if acquired else []
            self.assertEqual(api.events[api.events.index(failure) + 1:], expected)

    def test_cleanup_failure_does_not_report_success_or_release_early(self):
        cleanup = ['clear', 'clear_readback', 'unregister', 'unlock', 'release']
        for failure in cleanup:
            api = Fake(failure)
            with self.subTest(failure=failure), self.assertRaises(probe.ProbeError):
                probe.experiment(api)
            self.assertEqual(api.events[api.events.index('clear'):],
                             cleanup[:cleanup.index(failure) + 1])

    def test_missing_pages_and_post_write_unlock_are_rejected(self):
        for results in (([],), ([1 | (1 << 22)],), ([1, 1],),
                        ([1 | (1 << 22)] * 2, [1, 1])):
            api = Fake()
            with patch.object(api, 'working_set', side_effect=results), self.assertRaises(probe.ProbeError):
                probe.experiment(api)
            self.assertEqual(api.events[-2:], ['unlock', 'release'])
            self.assertEqual(api.value, 0)

    def test_failed_readback_rejects(self):
        for replies in ((False, True), (True, False)):
            api = Fake()
            with patch.object(api, 'matches', side_effect=replies), self.assertRaises(probe.ProbeError):
                probe.experiment(api)
            if not replies[-1]:
                self.assertNotIn('unlock', api.events)
                self.assertNotIn('release', api.events)

    def test_64_bit_ffi_layout(self):
        if c.sizeof(c.c_void_p) == 8:
            native.check_abi()
        else:
            with self.assertRaises(probe.ProbeError):
                native.check_abi()

    def test_hresult_and_dword_bounds(self):
        for value in (1, -1, -2147467259):
            with self.assertRaises(probe.ProbeError):
                native.Windows.hresult(value, 'test')
        native.Windows.hresult(0, 'test')
        api = object.__new__(native.Windows)
        api.dll = Mock()
        for size in (0, -1, 2**32):
            with self.assertRaises(probe.ProbeError):
                api.register(0x100000, size)
        api.dll.WerRegisterExcludedMemoryBlock.assert_not_called()
        api.dll.WerRegisterExcludedMemoryBlock.return_value = 0
        api.register(0x100000, 8192)
        api.dll.WerRegisterExcludedMemoryBlock.assert_called_once_with(0x100000, 8192)

    def test_win32_failure_and_missing_exports_are_not_success(self):
        with patch.object(c, 'get_last_error', return_value=5, create=True):
            for value in (0, None, False):
                with self.assertRaisesRegex(probe.ProbeError, 'Windows error 5'):
                    native.Windows.ok(value, 'synthetic failure')
        api = object.__new__(native.Windows)
        api.dll = object()
        with self.assertRaisesRegex(probe.ProbeError, 'required OS export absent'):
            api.bind('MissingFunction', None, [])

    def test_release_uses_original_base_zero_size_and_mem_release(self):
        api = object.__new__(native.Windows)
        api.dll = Mock()
        api.release(0x100000)
        api.dll.VirtualFree.assert_called_once_with(0x100000, 0, 0x8000)

    def test_native_entry_rejects_other_os_before_loading_dll(self):
        with patch.object(native.sys, 'platform', 'linux'), self.assertRaises(probe.ProbeError):
            native.Windows()
        if sys.platform != 'win32':
            result = subprocess.run([sys.executable, str(Path(probe.__file__))],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertIn('native Windows required', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_region_checks_reject_guard_commit_and_payload_geometry_drift(self):
        shape = probe.layout(4096, 65536, 4097)

        def regions():
            return [native.MemoryInfo(base=0x100000, allocation=0x100000, size=4096,
                                      state=native.RESERVE, kind=native.PRIVATE),
                    native.MemoryInfo(base=0x101000, allocation=0x100000, size=8192,
                                      state=native.COMMIT, protect=native.READWRITE, kind=native.PRIVATE),
                    native.MemoryInfo(base=0x103000, allocation=0x100000, size=53248,
                                      state=native.RESERVE, kind=native.PRIVATE)]

        api = object.__new__(native.Windows)
        with patch.object(api, 'query', side_effect=regions()):
            api.check_regions(0x100000, 0x101000, shape)
        for index, field, value in ((0, 'state', native.COMMIT), (2, 'state', native.COMMIT),
                                    (1, 'protect', 0x40), (1, 'size', 12288),
                                    (1, 'size', 4096), (2, 'allocation', 0x200000),
                                    (0, 'base', 0xff000), (1, 'kind', 0x40000)):
            changed = regions()
            setattr(changed[index], field, value)
            with self.subTest(index=index, field=field), \
                    patch.object(api, 'query', side_effect=changed), self.assertRaises(probe.ProbeError):
                api.check_regions(0x100000, 0x101000, shape)

    def test_ffi_queries_every_payload_page_and_requires_complete_virtual_query(self):
        api = object.__new__(native.Windows)
        api.dll = Mock()
        shape = probe.layout(4096, 65536, 4097)

        def query_working_set(_process, entries, size):
            self.assertEqual(size, 32)
            self.assertEqual([entry.address for entry in entries], [0x101000, 0x102000])
            for entry in entries:
                entry.flags = 1 | (1 << 22)
            return 1

        api.dll.K32QueryWorkingSetEx.side_effect = query_working_set
        self.assertEqual(api.working_set(0x101000, shape), [1 | (1 << 22)] * 2)
        for size in (0, 32, 47):
            api.dll.VirtualQuery.return_value = size
            with self.assertRaises(probe.ProbeError):
                api.query(0x100000)

    def test_native_machine_check_rejects_emulation_and_unknown_targets(self):
        for process, machine, accepted in ((0, 0x8664, True), (0, 0xaa64, True),
                                          (0x8664, 0xaa64, False), (0x14c, 0x8664, False),
                                          (0, 0x14c, False), (0, 0, False)):
            dll = Mock()

            def machine_query(_handle, process_out, native_out):
                c.cast(process_out, c.POINTER(native.U16))[0] = process
                c.cast(native_out, c.POINTER(native.U16))[0] = machine
                return 1

            dll.IsWow64Process2.side_effect = machine_query
            with self.subTest(process=process, machine=machine), \
                    patch.object(native.sys, 'platform', 'win32'), \
                    patch.object(c, 'WinDLL', return_value=dll, create=True):
                if accepted:
                    self.assertEqual(native.Windows().native_machine, hex(machine))
                    self.assertIs(dll.WerRegisterExcludedMemoryBlock.restype, c.c_int32)
                    self.assertEqual(dll.VirtualAlloc.argtypes,
                                     [native.PTR, native.SIZE, native.U32, native.U32])
                else:
                    with self.assertRaises(probe.ProbeError):
                        native.Windows()
                dll.VirtualAlloc.assert_not_called()


if __name__ == '__main__':
    unittest.main()
