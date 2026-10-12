"""CFG, decoded-byte and Win64 stack regressions; no enclave execution."""
import unittest
from unittest.mock import patch

import windows_enclave_stack_flow as f


def code(*rows):
    result={};at=0
    for raw,text in rows:
        value=bytes.fromhex(raw);result[at]=(value,text);at+=len(value)
    return result


def call_frame(size=32):
    return code(('55','pushq %rbp'),('4883ec'+format(size,'02x'),f'subq $0x{size:x}, %rsp'),
        ('e8f60f0000','callq 0x180002000'),
        ('4883c4'+format(size,'02x'),f'addq $0x{size:x}, %rsp'),('5d','popq %rbp'),('c3','retq'))


class DecodeTests(unittest.TestCase):
    def test_full_length_nop_with_tab_after_last_byte(self):
        raw='6666666666662e0f1f840000000000'
        row='180001000: '+ ' '.join(raw[i:i+2] for i in range(0,len(raw),2))+'\tnopw (%rax, %rax)'
        self.assertEqual(f.decode.parse(row)[4096][0],bytes.fromhex(raw))

    def test_decoder_rejects_duplicate_bad_outside_and_empty(self):
        row='180001000: c3\tretq'
        for text in (row+'\n'+row,'180001000: ff\t(bad)','170001000: c3\tretq','nothing'):
            with self.assertRaises(ValueError):f.decode.parse(text)

    def test_signed_image_binding_and_base(self):
        image=bytearray(256);image[0x3c:0x40]=(64).to_bytes(4,'little')
        image[64:68]=b'PE\0\0';image[88:90]=b'\x0b\x02'
        image[112:120]=f.decode.IMAGE_BASE.to_bytes(8,'little')
        record=dict(rva=4096,size=1);instructions={4096:(b'\xc3','retq')}
        with patch.object(f.decode.workers.catalog.sdk.pe,'linked',return_value=([],[])), \
                patch.object(f.decode.workers.catalog.sdk,'mapped',return_value=b'\xc3'):
            self.assertEqual(f.decode.body(image,record,instructions),{0:(b'\xc3','retq')})
            for bad in ({},{4096:(b'\xcc','int3')},{4096:(b'\x90\xc3','retq')}):
                with self.assertRaises(ValueError):f.decode.body(image,record,bad)
            image[112]^=1
            with self.assertRaises(ValueError):f.decode.body(image,record,instructions)

    def test_direct_and_indirect_control_encodings(self):
        self.assertEqual(f.decode.relative(bytes.fromhex('ebfe'),100),100)
        self.assertEqual(f.decode.relative(bytes.fromhex('0f85faffffff'),100),100)
        f.decode.indirect(bytes.fromhex('41ffd0'),2)
        f.decode.indirect(bytes.fromhex('ffe0'),4)
        for raw,extension in ((b'\xff',2),(b'\xff\xe0',2),(b'\xff\xd0',4),(b'\x90\xd0',2)):
            with self.assertRaises(ValueError):f.decode.indirect(raw,extension)
        with self.assertRaises(ValueError):f.decode.relative(b'\xff\xd0',100)

    def test_missing_fallthrough_and_mid_instruction_edges(self):
        for rows in (code(('90','nop')),code(('eb01','jmp 3'),('4889c0','movq %rax, %rax'),('c3','retq')),
                code(('7502','jne 4'),('c3','retq'))):
            with self.assertRaises(ValueError):f.decode.graph(rows,4096,[])

    def test_table_dispatch_is_nonempty_local_and_instruction_aligned(self):
        rows=code(('ffe0','jmpq *%rax'),('c3','retq'))
        self.assertEqual(f.decode.graph(rows,4096,[2])[0][0],[2])
        for targets in ([],[1],[100]):
            with self.assertRaises(ValueError):f.decode.graph(rows,4096,targets)

    def test_unassigned_control_cannot_fall_through(self):
        for op in ('syscall','iretq','loop 0','retq $8'):
            with self.assertRaises(ValueError):f.decode.graph(code(('0f05',op),('c3','retq')),4096,[])
        for raw,text in (('e9fb0f0000','callq 0x180002000'),('e8fb0f0000','jmp 0x180002000')):
            with self.assertRaises(ValueError):f.decode.graph(code((raw,text),('c3','retq')),4096,[])


class FlowTests(unittest.TestCase):
    def test_call_alignment_home_and_return_slot(self):
        for result in f.inspect(call_frame(),4096,[],set()):
            self.assertEqual(result['local_low'],-40)
            self.assertEqual(result['calls'][0]['entry_offset'],-48)
            self.assertEqual(result['calls'][0]['allocated_outgoing_bytes'],32)
            self.assertEqual(result['normal_returns'],[15])

    def test_not_enough_home_or_misaligned(self):
        for size in (8,16,24,40):
            with self.assertRaises(ValueError):f.inspect(call_frame(size),4096,[],set())

    def test_matched_saved_registers_and_normal_returns(self):
        for rows in (code(('55','pushq %rbp'),('c3','retq')),
                code(('55','pushq %rbp'),('5b','popq %rbx'),('c3','retq')),
                code(('50','pushq %rax'),('58','popq %rax'),('c3','retq'))):
            with self.assertRaises(ValueError):f.inspect(rows,4096,[],set())

    def test_tail_requires_restoration(self):
        rows=code(('e9fb0f0000','jmp 0x180002000'))
        self.assertEqual(f.inspect(rows,4096,[],set())[0]['calls'][0]['entry_offset'],0)
        with self.assertRaises(ValueError):
            f.inspect(code(('55','pushq %rbp'),('e9fa0f0000','jmp 0x180002000')),4096,[],set())

    def test_dynamic_alignment_both_entry_residues(self):
        rows=code(('55','pushq %rbp'),('488d2c24','leaq (%rsp), %rbp'),
            ('4883ec40','subq $0x40, %rsp'),('4883e4e0','andq $-0x20, %rsp'),
            ('488d6500','leaq (%rbp), %rsp'),('5d','popq %rbp'),('c3','retq'))
        reports=f.inspect(rows,4096,[],set())
        self.assertEqual([r['local_low'] for r in reports],[-72,-88])
        self.assertEqual([r['alignment'][0]['padding'] for r in reports],[0,16])

    def test_unknown_frame_base_cannot_restore(self):
        rows=code(('55','pushq %rbp'),('488d2c24','leaq (%rsp), %rbp'),
            ('4883ec20','subq $0x20, %rsp'),('4889c5','movq %rax, %rbp'),
            ('488d6500','leaq (%rbp), %rsp'),('5d','popq %rbp'),('c3','retq'))
        with self.assertRaises(ValueError):f.inspect(rows,4096,[],set())

    def test_exact_probe_request_and_special_save_interface(self):
        rows=code(('b800010000','movl $0x100, %eax'),('e8f60f0000','callq 0x180002000'),
            ('4829c4','subq %rax, %rsp'),('4881c400010000','addq $0x100, %rsp'),('c3','retq'))
        report=f.inspect(rows,4096,[],{8192})[0]
        self.assertEqual(report['local_low'],-256);self.assertTrue(report['calls'][0]['probe'])
        self.assertEqual(report['calls'][0]['entry_offset'],-8)
        with self.assertRaises(ValueError):f.inspect(rows,4096,[],set())
        bad=dict(rows);bad[0]=(bytes.fromhex('b900010000'),'movl $0x100, %ecx')
        with self.assertRaises(ValueError):f.inspect(bad,4096,[],{8192})

    def test_stack_growth_loop_and_different_join_states_reject(self):
        growing=code(('55','pushq %rbp'),('ebfd','jmp 0'))
        joining=code(('7501','jne 3'),('55','pushq %rbp'),('c3','retq'))
        for rows in (growing,joining):
            with self.assertRaises(ValueError):f.inspect(rows,4096,[],set())

    def test_plain_register_loop_is_finite(self):
        rows=code(('ffc0','incl %eax'),('75fc','jne 0'),('c3','retq'))
        self.assertEqual(f.inspect(rows,4096,[],set())[0]['reachable_instructions'],3)

    def test_unknown_rsp_write_and_unbounded_allocation_reject(self):
        for raw,text in (('4889c4','movq %rax, %rsp'),('4829cc','subq %rcx, %rsp'),
                ('4881ec00000100','subq $0x10000, %rsp'),('c9','leave'),
                ('4894','xchgq %rsp, %rax'),('480fc1e0','xaddq %rsp, %rax')):
            with self.assertRaises(ValueError):f.inspect(code((raw,text),('c3','retq')),4096,[],set())

    def test_explicit_trap_not_normal_cleanup(self):
        result=f.inspect(code(('55','pushq %rbp'),('0f0b','ud2')),4096,[],set())[0]
        self.assertEqual(result['normal_returns'],[]);self.assertEqual(result['terminal_traps'],[1])

    def test_leaf_fifth_argument_exact_read_not_zero_footprint(self):
        rows=code(('448b5c2428','movl 0x28(%rsp), %r11d'),('c3','retq'))
        scans=f.inspect(rows,4096,[],set())
        name='prefix17secret_memory_xor8xor_bits'
        self.assertEqual(f.leaf_accesses(name,rows,scans)['incoming_bytes'],36)
        for changed in ('movl %r11d, 0x28(%rsp)','movq 0x28(%rsp), %r11','movl 0x30(%rsp), %r11d'):
            bad=dict(rows);bad[0]=(rows[0][0],changed)
            with self.assertRaises(ValueError):f.leaf_accesses(name,bad,scans)
        with self.assertRaises(ValueError):f.leaf_accesses('other',rows,scans)
        with self.assertRaises(ValueError):f.leaf_accesses('other',call_frame(),f.inspect(call_frame(),4096,[],set()))


if __name__=='__main__':unittest.main()
