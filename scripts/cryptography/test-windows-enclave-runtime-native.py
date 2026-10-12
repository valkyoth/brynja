"""Host-independent tests of the guarded native component oracle and cleanup."""
import ctypes as C
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import windows_enclave_runtime_native as n


class Tests(unittest.TestCase):
    def test_no_unsupported_avx_forcing(self):
        for level in (1,2,3,5,6):
            initial=(level,1,0x80000,0x2000000)
            self.assertEqual(n.settings('detected',initial),initial)
            for mode in n.MODES:
                if mode.startswith('avx') and level<3:
                    with self.assertRaises(ValueError):n.settings(mode,initial)
                else:
                    values=n.settings(mode,initial)
                    self.assertLessEqual(values[0],max(3,level))
                    if mode.endswith('_rep'):self.assertEqual(values[1:3],(2,0))
                    if mode=='avx_streaming':self.assertEqual(values[3],0)
        for level in (0,4,7,True,None):
            with self.assertRaises(ValueError):n.modes(level)
        with self.assertRaises(ValueError):n.settings('unknown',(6,0,0,0))

    def test_oracle_detects_copy_fill_canary_source_and_return_errors(self):
        srcbuf=C.create_string_buffer(128);dstbuf=C.create_string_buffer(128)
        src=SimpleNamespace(address=C.addressof(srcbuf),size=128)
        dst=SimpleNamespace(address=C.addressof(dstbuf),size=128)
        def copy(d,s,k):C.memmove(d,s,k);return d
        def fill(d,v,k):C.memset(d,v,k);return d
        for length in (0,1,16,33,64):n.check_case(copy,fill,src,dst,length,1,31)
        def wrong_return(d,s,k):copy(d,s,k);return d+1
        def no_copy(d,s,k):return d
        def overrun(d,s,k):copy(d,s,k);C.memset(d+k,0,1);return d
        def source_write(d,s,k):copy(d,s,k);C.memset(s,0,1);return d
        def no_fill(d,v,k):return d
        def wrong_fill(d,v,k):C.memset(d,0,k);return d
        def fill_overrun(d,v,k):fill(d,v,k);C.memset(d+k,0,1);return d
        for bad in (wrong_return,no_copy,overrun,source_write):
            with self.assertRaises(ValueError):n.check_case(bad,fill,src,dst,33,1,31)
        for bad in (no_fill,wrong_fill,fill_overrun,lambda d,v,k:d+1):
            with self.assertRaises(ValueError):n.check_case(copy,bad,src,dst,33,1,31)

    def test_region_releases_once_on_success_and_exception(self):
        api=Mock(page=4096);api.VirtualAlloc.return_value=0x10000;api.VirtualFree.return_value=1
        with n.Region(api,4097) as region:
            self.assertEqual((region.size,region.address),(8192,0x11000))
        api.VirtualAlloc.assert_called_once_with(None,16384,0x3000,1)
        api.protect.assert_called_once_with(0x11000,8192,4)
        api.VirtualFree.assert_called_once_with(0x10000,0,0x8000)
        region.close();self.assertEqual(api.VirtualFree.call_count,1)
        api.reset_mock();api.protect.side_effect=ValueError('protect failed')
        with self.assertRaises(ValueError):n.Region(api,1)
        api.VirtualFree.assert_called_once_with(0x10000,0,0x8000)
        api.reset_mock();api.VirtualAlloc.return_value=0
        with self.assertRaises(ValueError):n.Region(api,1)
        api.VirtualFree.assert_not_called()

    def test_free_failure_is_not_silently_accepted(self):
        api=Mock(page=4096);api.VirtualAlloc.return_value=0x10000;api.VirtualFree.return_value=0
        region=n.Region(api,1)
        with self.assertRaises(ValueError):region.close()


if __name__=='__main__':unittest.main()
