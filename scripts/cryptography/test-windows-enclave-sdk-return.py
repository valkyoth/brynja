"""Offline import/export linkage regressions, not native SDK execution."""
import struct
import unittest
from unittest.mock import patch

import windows_enclave_sdk_return as review


class Tests(unittest.TestCase):
    def fixture(self, exports=False):
        header = bytearray(512)
        struct.pack_into('<I',header,0x3c,64)
        struct.pack_into('<H',header,84,240)
        struct.pack_into('<I',header,88+108,16)
        struct.pack_into('<II',header,88+112+(0 if exports else 8),0x2000,40)
        data = bytearray(1024)
        data[0x80:0x80+12] = b'vertdll.dll\0'
        name = review.SYMBOL.encode()+b'\0'
        if exports:
            struct.pack_into('<IIHHIIIIIII',data,0,0,0,0,0,0x2080,1,1,1,0x2100,0x2120,0x2130)
            struct.pack_into('<I',data,0x100,0x1000)
            struct.pack_into('<I',data,0x120,0x2140)
            data[0x140:0x140+len(name)] = name
        else:
            struct.pack_into('<IIIII',data,0,0x20c0,0,0,0x2080,0x2100)
            struct.pack_into('<Q',data,0xc0,0x2140)
            struct.pack_into('<Q',data,0x100,0x2140)
            data[0x142:0x142+len(name)] = name
        return header,data

    def rows(self, data):
        return [dict(rva=0x1000,virtual_size=16,code=b'\xc3'*16,flags=0x60000020),
                dict(rva=0x2000,virtual_size=len(data),code=bytes(data),flags=0x40000040)]

    def parsed(self, header, data, exports=False, symbol=None):
        with patch.object(review.pe,'linked',return_value=(self.rows(data),[])):
            return review.export(bytes(header),symbol or review.SYMBOL) if exports else review.imports(bytes(header))

    def test_named_import_and_export(self):
        h,d = self.fixture()
        self.assertEqual(self.parsed(h,d),{'vertdll.dll':{review.SYMBOL:0x2100}})
        h,d = self.fixture(True)
        self.assertEqual(self.parsed(h,d,True),0x1000)

    def test_import_descriptor_and_lookup_mutations(self):
        h,d = self.fixture()
        for offset, fmt, value in ((0,'I',0),(4,'I',1),(8,'I',1),(12,'I',0x9000),
                                   (16,'I',0),(0xc0,'Q',1<<63),(0x100,'Q',0x2141),
                                   (0x108,'Q',1),(20,'I',1)):
            changed = bytearray(d); struct.pack_into('<'+fmt,changed,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError): self.parsed(h,changed)
        for length in (20,39,1320):
            changed = bytearray(h); struct.pack_into('<I',changed,88+112+8+4,length)
            with self.assertRaises(ValueError): self.parsed(changed,d)
        duplicate = bytearray(d)
        struct.pack_into('<Q',duplicate,0xc8,0x2140)
        struct.pack_into('<Q',duplicate,0x108,0x2140)
        with self.assertRaises(ValueError): self.parsed(h,duplicate)

    def test_export_identity_forwarder_and_bounds(self):
        h,d = self.fixture(True)
        for offset,fmt,value in ((20,'I',0),(20,'I',8193),(24,'I',2),(0x100,'I',0x2001),
                                 (0x100,'I',0),(0x100,'I',0x2100),(0x120,'I',0x9000),(0x130,'H',1)):
            changed = bytearray(d); struct.pack_into('<'+fmt,changed,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError): self.parsed(h,changed,True)
        changed = bytearray(d); changed[0x80] = ord('x')
        with self.assertRaises(ValueError): self.parsed(h,changed,True)
        with self.assertRaises(ValueError): self.parsed(h,d,True,'absent')
        changed = bytearray(d)
        struct.pack_into('<II',changed,20,2,2)
        struct.pack_into('<I',changed,0x124,0x2140)
        with self.assertRaises(ValueError): self.parsed(h,changed,True)

    def test_directory_and_string_bounds(self):
        h,d = self.fixture()
        for count in (0,1,17):
            changed = bytearray(h); struct.pack_into('<I',changed,88+108,count)
            with self.assertRaises(ValueError): review.directory(changed,1)
        for size in (0,65537):
            changed = bytearray(h); struct.pack_into('<I',changed,88+124,size)
            with self.assertRaises(ValueError): review.directory(changed,1)
        for value in (b'',b'a'*256,b'\xff\0'):
            row = dict(rva=1,virtual_size=len(value),code=value,flags=0x40000040)
            with self.assertRaises(ValueError): review.string([row],1)
        rows = self.rows(d)
        with self.assertRaises(ValueError): review.string(rows+[rows[1]],0x2080)

    def test_thunk_exact_bytes_and_frame_boundary(self):
        code = b'\xff\x25'+(0x2100-0x1006).to_bytes(4,'little',signed=True)
        row = dict(rva=0x1000,virtual_size=6,code=code,flags=0x60000020)
        self.assertEqual(review.thunk([row],[],0x1000,0x2100),code.hex())
        for index in range(6):
            changed = bytearray(code); changed[index] ^= 1
            with self.assertRaises(ValueError): review.thunk([row | {'code':bytes(changed)}],[],0x1000,0x2100)
        for changed in ([row,row],[row | {'flags':0xe0000020}],[row | {'virtual_size':5}]):
            with self.assertRaises(ValueError): review.thunk(changed,[],0x1000,0x2100)
        for extent in ((0x1000,0x1006,0),(0xfff,0x1001,0),(0x1005,0x1007,0)):
            with self.assertRaises(ValueError): review.thunk([row],[extent],0x1000,0x2100)

    def test_copy_direction_syscall_status_and_tail(self):
        review.copy_edges()
        rva,hexcode = review.status.sdk.BODIES[review.SYMBOL]
        code = bytes.fromhex(hexcode)
        for index in range(len(code)):
            changed = bytearray(code); changed[index] ^= 1
            with patch.dict(review.status.sdk.BODIES,{review.SYMBOL:(rva,changed.hex())}):
                with self.assertRaises(ValueError): review.copy_edges()


if __name__ == '__main__': unittest.main()
