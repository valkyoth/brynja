"""Actual unwind/prologue allocations; handlers and leaves remain explicit."""
from pathlib import Path
import unittest

import windows_enclave_runtime_frames as f

SAVED=Path(__file__).resolve().parents[2]/'release-reports/windows-local-20261004'


def rows(header,codes,tail=b''):
    return [dict(rva=100,virtual_size=4+len(codes)+len(tail),
                 code=header+codes+tail,flags=0x40000040),
            dict(rva=1000,virtual_size=100,code=bytes(100),flags=0x60000020)]


class Tests(unittest.TestCase):
    def test_small_allocation_matches_instruction(self):
        table=rows(bytes([1,4,1,0]),bytes([4,0x42]))
        record=f.decode(table,(1000,1020,100))
        self.assertEqual(record['fixed_bytes'],40)
        self.assertEqual(f.allocations(bytes.fromhex('4883ec28'),[],record),[(0,4)])
        for code in (bytes.fromhex('4883ec20'),b'\xc3',bytes.fromhex('4883c428')):
            with self.assertRaises(ValueError):f.allocations(code,[],record)

    def test_large_and_push_allocation(self):
        record=f.decode(rows(bytes([1,9,3,0]),bytes.fromhex('090101100230')),(1000,1020,100))
        self.assertEqual(record['fixed_bytes'],32784)
        # Metadata must identify real instruction endpoints, not just add up.
        with self.assertRaises(ValueError):f.allocations(bytes(20),[],record)

    def test_handler_flags_retained_not_erased(self):
        for flags in (1,2,3):
            record=f.decode(rows(bytes([1|(flags<<3),4,1,0]),bytes([4,0x42]),
                bytes(2)+(1001).to_bytes(4,'little')),(1000,1020,100))
            self.assertEqual(record['handler_flags'],flags);self.assertEqual(record['handler_rva'],1001)
        with self.assertRaises(ValueError):
            f.decode(rows(bytes([9,4,1,0]),bytes([4,0x42]),bytes(6)),(1000,1020,100))

    def test_unsupported_or_malformed_metadata_rejected(self):
        for header,slots in (([2,4,1,0],[4,0x42]),([33,4,1,0],[4,0x42]),
            ([1,30,1,0],[4,0x42]),([1,4,1,0],[5,0x42]),([1,4,1,0],[0,0x42]),
            ([1,4,1,0],[4,0x01]),([1,4,1,0],[4,0x21]),([1,4,1,0],[4,0x00]),
            ([1,4,1,0],[4,0x03]),([1,4,1,0],[4,0x06]),([1,4,1,0],[4,0x58]),
            ([1,4,1,1],[4,0x42]),([1,4,2,0],[2,0x30,4,0x50])):
            with self.assertRaises(ValueError):f.decode(rows(bytes(header),bytes(slots)),(1000,1020,100))

    def test_probe_amount_and_relocation_are_bound(self):
        code=bytes.fromhex('b888130000e8000000004829c4')
        record=dict(fixed_bytes=5000,operations=[dict(opcode=1,end=13,bytes=5000)])
        refs=[dict(offset=6,symbol='__chkstk',trailing=0,addend=0)]
        self.assertEqual(f.allocations(code,refs,record),[(0,13)])
        for ref in (refs[0] | {'symbol':'not_chkstk'},refs[0] | {'offset':5},refs[0] | {'addend':1}):
            with self.assertRaises(ValueError):f.allocations(code,[ref],record)
        for at in range(len(code)):
            changed=bytearray(code);changed[at]^=1
            with self.assertRaises(ValueError):f.allocations(bytes(changed),refs,record)

    def test_duplicate_or_overlapping_allocations_rejected(self):
        op=dict(opcode=2,end=4,bytes=40)
        with self.assertRaises(ValueError):
            f.allocations(bytes.fromhex('4883ec28'),[],dict(fixed_bytes=80,operations=[op,op]))


class SavedTests(unittest.TestCase):
    def test_all_actual_functions_reconciled(self):
        count=0;largest=0;handlers=0;leaves=0
        for row in f.r.catalog():
            data,image=f.workers.load(SAVED,row);functions,bound=f.workers.bind(data,image)
            report=f.inspect(image,functions,bound)
            self.assertEqual(report['worker_count'],len(functions));self.assertFalse(report['cumulative_depth_proven'])
            count+=report['worker_count'];largest=max(largest,report['maximum_fixed_frame_bytes'])
            handlers+=report['exception_handler_count'];leaves+=report['leaf_count']
            for name,rec in report['functions'].items():
                if not rec['metadata_present']:
                    self.assertIsNone(rec['fixed_bytes']);continue
                code,refs,runtime=functions[name]
                for start,end in rec['allocation_instruction_spans']:
                    bad=bytearray(code);bad[end-1]^=1
                    with self.assertRaises(ValueError):f.allocations(bytes(bad),refs,rec)
        self.assertEqual(count,1023);self.assertEqual(largest,13048)
        self.assertGreater(handlers,0);self.assertGreater(leaves,0)


if __name__=='__main__':unittest.main()
