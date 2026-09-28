#!/usr/bin/env python3
"""AWE orchestration tests: no Windows calls or privilege changes."""
import ctypes as c
import unittest
from unittest.mock import Mock, patch

import windows_awe_probe as awe
from windows_protection_probe import ProbeError, layout


class Fake:
    def __init__(self, fail=None, count=2):
        self.events, self.fail, self.count = [], fail, count
        self.pages = object()

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise ProbeError(name)

    def allocate(self, count):
        self.event('allocate')
        assert count == 2
        return self.pages, self.count

    def reserve_awe(self, size):
        self.event('reserve')
        assert size == 65536
        return 0x100000

    def map_pages(self, address, count, pages):
        self.event('unmap' if pages is None else 'map')
        assert (address, count) == (0x101000, 2)
        assert pages is None or pages is self.pages

    def fill(self, address, size, value):
        self.event('clear' if value == 0 else 'fill')
        assert (address, size) == (0x101000, 8192)

    def matches(self, address, size, value):
        self.event('clear_readback' if value == 0 else 'readback')
        assert (address, size) == (0x101000, 8192)
        return True

    def free(self, pages, count):
        self.event('free')
        assert pages is self.pages and count == self.count

    def release(self, base):
        self.event('release')
        assert base == 0x100000


class Tests(unittest.TestCase):
    shape = layout(4096, 65536, 4097)

    def test_privilege_errors_and_not_all_assigned_never_pass(self):
        for failure in (None, 'OpenProcessToken', 'LookupPrivilegeValueW',
                        'AdjustTokenPrivileges', 'CloseHandle', 'not_assigned'):
            api = object.__new__(awe.Awe)
            api.dll = Mock()
            api.dll.CloseHandle.return_value = int(failure != 'CloseHandle')
            advapi = Mock()
            for name in ('OpenProcessToken', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges'):
                getattr(advapi, name).return_value = int(name != failure)
            with self.subTest(failure=failure), \
                    patch.object(c, 'WinDLL', return_value=advapi, create=True), \
                    patch.object(c, 'set_last_error', create=True) as reset, \
                    patch.object(c, 'get_last_error', return_value=1300 if failure == 'not_assigned' else 0,
                                 create=True):
                if failure:
                    with self.assertRaises(ProbeError):
                        api.enable_assigned_privilege()
                else:
                    api.enable_assigned_privilege()
                self.assertEqual(api.dll.CloseHandle.call_count, int(failure != 'OpenProcessToken'))
                if failure not in ('OpenProcessToken', 'LookupPrivilegeValueW'):
                    reset.assert_called_once_with(0)
                    args = advapi.AdjustTokenPrivileges.call_args.args
                    self.assertIs(args[1], False)
                    state = c.cast(args[2], c.POINTER(awe.Privileges)).contents
                    self.assertEqual((state.count, state.attributes), (1, 2))
                    self.assertEqual(advapi.LookupPrivilegeValueW.call_args.args[1], 'SeLockMemoryPrivilege')

    def test_success_and_body_failure_clear_before_unmap_free_release(self):
        for raises in (False, True):
            api = Fake()
            try:
                with awe.mapping(api, self.shape, 0xa5) as address:
                    self.assertEqual(address, 0x101000)
                    if raises:
                        raise ValueError('synthetic callback')
            except ValueError:
                self.assertTrue(raises)
            self.assertEqual(api.events, ['allocate', 'reserve', 'map', 'fill', 'readback',
                                         'clear', 'clear_readback', 'unmap', 'free', 'release'])

    def test_partial_allocation_freed_without_reserving_or_exposing(self):
        for count in (0, 1):
            api = Fake(count=count)
            with self.assertRaisesRegex(ProbeError, 'partial'):
                with awe.mapping(api, self.shape, 0xa5):
                    self.fail('must not admit')
            self.assertEqual(api.events, ['allocate'] + (['free'] if count else []))

    def test_bounded_allocation_before_ffi(self):
        for count in (-1, 0, True, 257, 2**64):
            api = Mock()
            with self.assertRaises(ProbeError):
                awe.acquire(api, count)
            api.allocate.assert_not_called()

    def test_every_acquisition_failure_has_expected_rollback(self):
        expected = {'allocate': [], 'reserve': ['free'], 'map': ['free', 'release'],
                    'fill': ['clear', 'clear_readback', 'unmap', 'free', 'release'],
                    'readback': ['clear', 'clear_readback', 'unmap', 'free', 'release']}
        for failure, tail in expected.items():
            api = Fake(fail=failure)
            with self.subTest(failure=failure), self.assertRaises(ProbeError):
                with awe.mapping(api, self.shape, 0xa5):
                    self.fail('must not admit')
            self.assertEqual(api.events[api.events.index(failure) + 1:], tail)

    def test_cleanup_failure_never_releases_uncertain_mapping(self):
        for failure in ('clear', 'clear_readback', 'unmap', 'free', 'release'):
            api = Fake(fail=failure)
            with self.subTest(failure=failure), self.assertRaises(ProbeError):
                with awe.mapping(api, self.shape, 0xa5):
                    pass
            self.assertEqual(api.events[-1], failure)

    def test_false_readback_never_releases_uncleared_pages(self):
        api = Fake()
        with patch.object(api, 'matches', side_effect=[True, False]), self.assertRaises(ProbeError):
            with awe.mapping(api, self.shape, 0xa5):
                pass
        self.assertNotIn('free', api.events)

    def test_partial_free_is_rejected_and_pfn_array_not_changed(self):
        api = object.__new__(awe.Awe)
        api.dll = Mock()
        pages = (awe.SIZE * 2)(123, 456)

        def partial(_process, count, pfns):
            self.assertIs(pfns, pages)
            c.cast(count, c.POINTER(awe.SIZE))[0] = 1
            return 1

        api.dll.FreeUserPhysicalPages.side_effect = partial
        with self.assertRaisesRegex(ProbeError, 'partial AWE release'):
            api.free(pages, 2)
        self.assertEqual(list(pages), [123, 456])


if __name__ == '__main__':
    unittest.main()
