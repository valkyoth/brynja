"""Saved update byte/cleanup regressions and separate arithmetic oracles."""
import copy
import random
import unittest

import windows_enclave_sha3_update as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())['functions']
        self.helpers = r.t.specification(r.t.SPEC.read_bytes())['functions']

    def test_all_actual_bytes_and_reference_operands(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for pin in self.pins.values():
            code = bytes.fromhex(pin['code_hex']);refs = pin['references'];r.t.instructions(code,refs,pin)
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                with self.assertRaises(ValueError): r.t.instructions(bad,refs,pin)
            for at in range(len(refs)):
                bad = copy.deepcopy(refs);bad[at]['offset'] += 1
                with self.assertRaises(ValueError): r.t.instructions(code,bad,pin)

    def test_landmarks_independent_of_hash_identity(self):
        for rate in r.RATES:
            items = r.sequences(rate,self.helpers);text = '\n'.join(i.replace('|','\n') for i in items)
            r.landmarks(rate,text,self.helpers)
            for item in items:
                with self.assertRaises(ValueError):
                    r.landmarks(rate,text.replace(item.replace('|','\n'),'int3'),self.helpers)

    def test_all_permutation_erasure_sequences(self):
        first = ['callq '+r.PERMUTE];second = list(first)
        for lines,regs,sizes in ((first,('%r13','%rbp','%r12','%r15'),(40,40,200,168)),
                                 (second,('%r13','%rbp','%r15'),(40,40,200))):
            for reg,size in zip(regs,sizes): lines += [f'movl ${size}, %edx',f'movq {reg}, %rcx','callq '+r.ZERO]
        first.append('movb $0, 1038(%rsi)');lines = first+second
        self.assertEqual(r.erasures('\n'.join(lines))['permutation_sites'],2)
        for at in range(len(lines)):
            bad = list(lines);bad[at] = 'int3'
            with self.assertRaises(ValueError): r.erasures('\n'.join(bad))
        with self.assertRaises(ValueError): r.erasures('\n'.join(lines+first))

    def test_multiply_high_division_against_integer_division(self):
        generator = random.Random(0x53504f4e4745)
        values = set(range(4097)) | {(1<<64)-1}
        for bit in range(64): values.update(((1<<bit)-1,1<<bit,(1<<bit)+1))
        values.update(generator.getrandbits(64) for _ in range(10000))
        for rate in r.RATES:
            for n in values:
                self.assertEqual(r.block_bytes(rate,n),(n//rate)*rate)
                quotient = n//rate
                for delta in (-1,0,1):
                    boundary = quotient*rate+delta
                    if 0<=boundary<1<<64:
                        self.assertEqual(r.block_bytes(rate,boundary),(boundary//rate)*rate)

    def test_buffer_partition_and_no_overread(self):
        for rate in r.RATES:
            for buffered in range(rate):
                for length in (*range(2*rate+1),(1<<63)-1,(1<<64)-1):
                    p = r.partition(rate,buffered,length)
                    self.assertLessEqual(p['copied'],length)
                    self.assertLessEqual(p['copied'],rate-buffered)
                    self.assertEqual(p['copied']+p['direct_bytes']+p['tail'],length)
                    self.assertEqual(p['used'],(buffered+length)%rate)
                    self.assertEqual(p['partial_permutations']+p['direct_bytes']//rate,(buffered+length)//rate)
                    self.assertLess(p['tail'],rate)
            for buffered in (-1,rate,255):
                with self.assertRaises(ValueError): r.partition(rate,buffered,1)

    def test_checked_u128_counter_before_admission(self):
        maximum = (1<<128)-1
        for total in (0,1,(1<<64)-1,1<<64,maximum-(1<<64),maximum-1,maximum):
            for length in (0,1,2,(1<<64)-2,(1<<64)-1):
                self.assertEqual(r.counter_admit(total,length),total+length if total+length<=maximum else None)
        for total,length in ((-1,0),(1<<128,0),(0,-1),(0,1<<64)):
            with self.assertRaises(ValueError): r.counter_admit(total,length)

    def test_common_shape_allows_only_reviewed_rate_differences(self):
        for rate in r.RATES:
            body = '\n'.join((r.DIV[rate].replace('|','\n'),f'cmpq ${rate}, %rdi','jne .LBBX_10',
                'cmpq $168, %rdi','ja .LBBX_11',f'cmpq ${rate-1}, %rdi','subq $72, %rsp'))
            shape = r.common_shape(rate,body,'name')
            self.assertEqual(shape,'REVIEWED_RATE_DIVISION\ncmpq $RATE, %rdi\njne .LBBX_10\ncmpq $168, %rdi\nja .LBBX_11\ncmpq $RATE_MINUS_ONE, %rdi\nsubq $72, %rsp')
            self.assertNotEqual(shape,r.common_shape(rate,body.replace('subq $72','subq $80'),'name'))
            with self.assertRaises(ValueError): r.common_shape(rate,body.replace('mulq','imulq'),'name')

    def test_call_graph_rejects_wrong_rate_and_callee(self):
        callees = {k:dict(entry=n,rva=10000+i*100,image_sha256='same',reference_targets={}) for i,(k,n) in enumerate(
            (('copy',self.helpers['copy']['name']),('xor',self.helpers['xor']['name']),('zero',r.ZERO),('permutation',r.PERMUTE)))}
        records = {k:dict(entry=p['name'],rva=100+i*100,image_sha256='same',
                         reference_targets={c['entry']:c['rva'] for c in callees.values()}) for i,(k,p) in enumerate(self.pins.items())}
        anchors = [dict(image_sha256='same',reference_targets={p['name']:records[k]['rva'] for k,p in self.pins.items()})]
        r.connections(records,anchors,callees,self.pins)
        for key,record in records.items():
            for name in record['reference_targets']:
                bad = copy.deepcopy(records);bad[key]['reference_targets'][name] += 1
                with self.assertRaises(ValueError): r.connections(bad,anchors,callees,self.pins)
            bad = copy.deepcopy(anchors);del bad[0]['reference_targets'][record['entry']]
            with self.assertRaises(ValueError): r.connections(records,bad,callees,self.pins)
        for key in callees:
            bad = copy.deepcopy(callees);bad[key]['image_sha256'] = 'wrong'
            with self.assertRaises(ValueError): r.connections(records,anchors,bad,self.pins)


if __name__=='__main__': unittest.main()
