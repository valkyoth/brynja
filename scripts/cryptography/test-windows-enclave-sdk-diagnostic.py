"""Offline diagnostic review regressions; never executes Microsoft code."""
import unittest
from unittest.mock import patch

import windows_enclave_sdk_diagnostic as diagnostic


class Tests(unittest.TestCase):
    def bodies(self):
        return {name:bytes.fromhex(code) for name,(_,code) in diagnostic.BODIES.items()}

    def rows(self):
        code = bytearray(0x20000)
        data = bytearray(0x1000)
        for rva,body in diagnostic.BODIES.values():
            code[rva:rva+len(bytes.fromhex(body))] = bytes.fromhex(body)
        for rva,body in diagnostic.FORMATS.items():
            data[rva-0x20000:rva-0x20000+len(body)] = body
        return [dict(rva=0,code=bytes(code),virtual_size=len(code),flags=0x20000000),
                dict(rva=0x20000,code=bytes(data),virtual_size=len(data),flags=0)]

    def inspect_rows(self, rows):
        with patch.object(diagnostic.status,'inspect',return_value=dict(
                image_sha256='synthetic',version_observed='synthetic')):
            with patch.object(diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                return diagnostic.inspect(b'fixture')

    def test_population_and_all_body_mutations(self):
        bodies = self.bodies()
        diagnostic.check_bodies(bodies)
        self.assertEqual(sum(map(len,bodies.values())),1039)
        for name,code in bodies.items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                with self.subTest(name=name,index=index), self.assertRaises(ValueError):
                    diagnostic.check_bodies(bodies | {name:bytes(changed)})
            for changed in (code[:-1],code+b'\x90'):
                with self.assertRaises(ValueError):
                    diagnostic.check_bodies(bodies | {name:changed})
            with self.assertRaises(ValueError):
                diagnostic.check_bodies({n:b for n,b in bodies.items() if n != name})
        with self.assertRaises(ValueError): diagnostic.check_bodies(bodies | {'extra':b''})

    def test_each_transfer_and_previous_boundary(self):
        diagnostic.check_edges()
        self.assertEqual(len(diagnostic.EDGES),13)
        for name,instruction,_,_ in diagnostic.EDGES:
            rva,code = diagnostic.BODIES[name]
            changed = bytearray.fromhex(code)
            changed[instruction-rva+1] ^= 1
            with patch.dict(diagnostic.BODIES,{name:(rva,changed.hex())}):
                with self.assertRaises(ValueError): diagnostic.check_edges()
        with patch.object(diagnostic.status,'DEEP_DIAGNOSTIC_RVA',0x16911):
            with self.assertRaises(ValueError): diagnostic.check_edges()

    def test_exact_frames_all_four_sequential_capacities(self):
        self.assertEqual(diagnostic.CAPACITIES,(128,256,384,512))
        for capacity in diagnostic.CAPACITIES:
            result = diagnostic.geometry(diagnostic.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                row = result[path]
                self.assertEqual(row['frames'],dict(retry=-11744+shift,
                    buffer_fixed=-12080+shift,buffer_dynamic=-12080-capacity+shift,
                    format_adapter=-12144-capacity+shift,format_wrapper=-12256-capacity+shift))
                self.assertEqual(len(row['spans']),15)
                spans = {s['name']:s for s in row['spans']}
                buffer = spans['diagnostic output buffer']
                self.assertEqual(buffer['bytes'],capacity)
                self.assertEqual(buffer['offset_from_high']+capacity,-12048+shift)
                self.assertEqual(spans['probe R10/R11 saves and return']['offset_from_high'],
                                 -12104+shift)
                self.assertEqual(spans['exception record']['bytes'],152)
                for callee in row['unknown_callees']:
                    self.assertIsNone(callee['callee_frame_bytes'])
                    self.assertFalse(callee['callee_spills_qualified'])
                for span in row['spans']:
                    self.assertGreaterEqual(span['offset_from_low'],0)
                    self.assertLessEqual(span['offset_from_high']+span['bytes'],0)

    def test_capacity_rejection_and_translation(self):
        for capacity in (-1,0,127,129,513,1<<64,True,128.0,'128'):
            with self.assertRaises(ValueError):
                diagnostic.geometry(diagnostic.Window(0,65536),capacity)
        for capacity in diagnostic.CAPACITIES:
            self.assertEqual(diagnostic.geometry(diagnostic.Window(0,65536),capacity),
                diagnostic.geometry(diagnostic.Window(1<<32,(1<<32)+65536),capacity))

    def test_real_file_identity_checked_before_parsing(self):
        with patch.object(diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): diagnostic.inspect(b'MZ-unreviewed')

    def test_section_bounds_permissions_and_ambiguity(self):
        rows = self.rows()
        self.inspect_rows(rows)
        for index in (0,1):
            for bad in (rows[index]|{'flags':rows[index]['flags']|0x80000000},
                        rows[index]|{'flags':rows[index]['flags']^0x20000000},
                        rows[index]|{'virtual_size':1},rows[index]|{'code':b''}):
                changed = list(rows)
                changed[index] = bad
                with self.assertRaises(ValueError): self.inspect_rows(changed)
            with self.assertRaises(ValueError): self.inspect_rows(rows+[rows[index]])
            with self.assertRaises(ValueError): self.inspect_rows(rows[:index]+rows[index+1:])

    def test_every_format_byte_including_terminator(self):
        self.assertEqual(sum(body.count(b'%lx') for body in diagnostic.FORMATS.values()),1)
        for rva,body in diagnostic.FORMATS.items():
            for index in range(len(body)):
                rows = self.rows()
                data = bytearray(rows[1]['code'])
                data[rva-0x20000+index] ^= 1
                rows[1] = rows[1]|{'code':bytes(data)}
                with self.assertRaises(ValueError): self.inspect_rows(rows)

    def test_report_preserves_unreviewed_paths_and_nonclaims(self):
        result = self.inspect_rows(self.rows())
        for field in ('loaded_module_identity_proven','native_enclave_run_added',
                      'whole_image_qualified','production_qualified',
                      'maximum_transitive_depth_qualified','probe_page_touches_bounded_by_window',
                      'thread_relative_storage_cleared_by_window','buffer_full_wipe_in_body_observed'):
            self.assertIs(result[field],False)
        self.assertTrue(result['retry_is_sequential_not_recursive'])
        self.assertEqual({r['rva'] for r in result['unresolved']},
                         {0x2968,0x2958,0x1058,0x1f030,0xbc90,0x1160})
        self.assertEqual(result['thread_relative_flag']['offset'],0x17ee)
        self.assertEqual(result['thread_relative_flag']['mask'],2)


if __name__ == '__main__': unittest.main()
