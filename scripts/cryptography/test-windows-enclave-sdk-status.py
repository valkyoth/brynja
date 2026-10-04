"""Synthetic drift, transfer and geometry regressions; no SDK code execution."""
import unittest
from unittest.mock import patch

import windows_enclave_sdk_status as status


class Tests(unittest.TestCase):
    def bodies(self):
        return {n:bytes.fromhex(code) for n,(_,code) in status.BODIES.items()}

    def test_exact_population(self):
        status.check_bodies(self.bodies())
        for name in status.BODIES:
            changed = self.bodies()
            del changed[name]
            with self.assertRaises(ValueError): status.check_bodies(changed)
        with self.assertRaises(ValueError):
            status.check_bodies(self.bodies() | {'extra':b''})

    def test_every_body_byte_and_length(self):
        self.assertEqual(sum(map(len,self.bodies().values())),478)
        for name,code in self.bodies().items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                with self.subTest(name=name,index=index), self.assertRaises(ValueError):
                    status.check_bodies(self.bodies() | {name:bytes(changed)})
            for changed in (code[:-1],code+b'\x90'):
                with self.assertRaises(ValueError):
                    status.check_bodies(self.bodies() | {name:changed})

    def test_transfer_targets_and_explicit_diagnostic_stop(self):
        status.check_edges()
        for source,offset,_,_ in status.EDGES:
            population = status.sdk.BODIES if source in status.sdk.BODIES else status.BODIES
            rva,code = population[source]
            changed = bytearray.fromhex(code)
            changed[offset+1] ^= 1
            with patch.dict(population,{source:(rva,changed.hex())}):
                with self.assertRaises(ValueError): status.check_edges()
        with patch.object(status,'DEEP_DIAGNOSTIC_RVA',0x16911):
            with self.assertRaises(ValueError): status.check_edges()

    def test_relative_transfer_bounds_and_sign(self):
        self.assertEqual(status.relative_target(100,b'\xe9\xfb\xff\xff\xff',0,0xe9),100)
        for code,offset,opcode in ((b'\xe8\0\0\0',0,0xe8),
                                   (b'\xe8\0\0\0\0',-1,0xe8),
                                   (b'\xe8\0\0\0\0',1,0xe8),
                                   (b'\xe8\0\0\0\0',0,0xe9),
                                   (b'\xc3\0\0\0\0',0,0xc3)):
            with self.assertRaises(ValueError): status.relative_target(100,code,offset,opcode)

    def test_exact_geometry_and_tail_transfer(self):
        result = status.geometry(status.Window(0,65536))
        copy = result['paths']['copy']
        call = result['paths']['call_error']
        self.assertEqual(copy['frames'],dict(status=-11488,convert=-11536,
                                            lookup=-11584,diagnostic_entry=-11664))
        self.assertEqual(call['frames'],dict(status=-11744,convert=-11792,
                                            lookup=-11840,diagnostic_entry=-11920))
        self.assertEqual(len(copy['spans']),7)
        self.assertEqual(len(call['spans']),8)
        for path,offset in ((copy,-11672),(call,-11928)):
            self.assertEqual(path['unknown_callee']['offset_from_high'],offset)
            self.assertIsNone(path['unknown_callee']['callee_frame_bytes'])
            self.assertFalse(path['unknown_callee']['callee_spills_qualified'])
            for span in path['spans']:
                self.assertGreaterEqual(span['offset_from_low'],0)
                self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
        self.assertEqual(copy['spans'][0]['offset_from_high'],-11488)
        self.assertEqual(copy['spans'][1]['offset_from_high'],-11552)
        self.assertEqual(copy['spans'][-1]['offset_from_high'],-11632)
        self.assertTrue(result['copy_status_is_tail_transfer'])

    def test_translation_and_limits(self):
        result = status.geometry(status.Window(0,65536))
        self.assertEqual(result,status.geometry(status.Window(1<<32,(1<<32)+65536)))
        for field in ('kernel_storage_qualified','loaded_module_identity_proven',
                      'diagnostic_callee_depth_qualified','maximum_transitive_depth_qualified',
                      'thread_relative_status_storage_cleared_by_window'):
            self.assertIs(result[field],False)

    def test_rejects_wrong_sdk_before_status_parsing(self):
        with patch.object(status.sdk.pe,'linked',side_effect=AssertionError('must not parse')):
            with self.assertRaises(ValueError): status.inspect(b'MZ-unreviewed')

    def test_synthetic_section_mapping_and_no_qualification(self):
        code = bytearray(0x17000)
        for rva,body in status.BODIES.values():
            code[rva:rva+len(bytes.fromhex(body))] = bytes.fromhex(body)
        row = dict(rva=0,code=bytes(code),virtual_size=len(code),flags=0x20000000)
        metadata = dict(image_sha256=status.sdk.IMAGE_SHA256,version_observed='synthetic')
        # Bypass the outer file/body check only to exercise bounded extraction.
        with patch.object(status.sdk,'inspect',return_value=metadata):
            with patch.object(status.sdk.pe,'linked',return_value=([row],None)):
                result = status.inspect(b'fixture')
            self.assertFalse(result['whole_image_qualified'])
            self.assertFalse(result['native_enclave_run_added'])
            self.assertEqual([r['bytes'] for r in result['thread_relative_writes']],[4,4])
            for rows in ([],[row,row],[row|{'flags':0}],
                         [row|{'flags':0xa0000000}],
                         [row|{'virtual_size':0x168d8}],
                         [row|{'code':row['code'][:0x168d8]}]):
                with patch.object(status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): status.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
