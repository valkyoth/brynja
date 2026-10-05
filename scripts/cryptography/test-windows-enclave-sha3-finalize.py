"""Regress saved finalization/squeezing review without asserting full qualification."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha3_finalize as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())['functions']
        self.helpers = r.t.specification(r.t.SPEC.read_bytes())['functions']

    def test_all_body_bytes_and_relocations(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for pin in self.pins.values():
            raw = bytes.fromhex(pin['code_hex']);refs = pin['references'];r.t.instructions(raw,refs,pin)
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.t.instructions(bad,refs,pin)
            for at in range(len(refs)):
                for field in ('symbol','offset','addend','trailing'):
                    bad = copy.deepcopy(refs);bad[at][field] = 'wrong' if field=='symbol' else bad[at][field]+1
                    with self.assertRaises(ValueError): r.t.instructions(raw,bad,pin)

    def test_semantic_sequences_without_hashes(self):
        for kind in ('enter','finalize','squeeze'):
            for rate in (136,168):
                seqs = r.s.sequences(kind,rate,self.helpers,self.pins)
                text = '\n'.join(s.replace('|','\n') for s in seqs)
                if kind=='finalize': text += '\njmp '+r.s.ZERO+'\n.Lfunc_end'+('18:' if rate==136 else '22:')+'\n'
                r.s.landmarks(kind,rate,text,self.helpers,self.pins)
                for seq in seqs:
                    with self.assertRaises(ValueError):
                        r.s.landmarks(kind,rate,text.replace(seq.replace('|','\n'),'int3'),self.helpers,self.pins)
                if kind=='finalize':
                    with self.assertRaises(ValueError): r.s.landmarks(kind,rate,text.replace('jmp '+r.s.ZERO,'retq'),self.helpers,self.pins)

    def test_all_immediate_scratch_erasure_sites(self):
        for kind in ('finalize','squeeze'):
            lines = []
            for seq in r.s.erasure_sequences(kind): lines += ['callq '+r.s.PERMUTE,*seq]
            self.assertEqual(r.s.cleanup(kind,'\n'.join(lines)),3 if kind=='finalize' else 1)
            for at in range(len(lines)):
                bad = list(lines);bad[at] = 'int3'
                with self.assertRaises(ValueError): r.s.cleanup(kind,'\n'.join(bad))
            with self.assertRaises(ValueError): r.s.cleanup(kind,'\n'.join(lines+['callq '+r.s.PERMUTE]))

    def test_padding_against_independent_bit_concatenation(self):
        for rate in (136,168):
            for used in range(rate):
                whole = bytes((i*73+used)%256 for i in range(used))
                for valid in range(8):
                    for suffix,width in ((4,3),(6,3),(31,5)):
                        tail = (used*31+valid)%256
                        bits = [(byte>>i)&1 for byte in whole for i in range(8)]
                        bits += [(tail>>i)&1 for i in range(valid)]
                        bits += [(suffix>>i)&1 for i in range(width)]
                        while len(bits)%(rate*8)!=rate*8-1: bits.append(0)
                        bits.append(1)
                        expected = bytes(sum(bits[i+j]<<j for j in range(8)) for i in range(0,len(bits),8))
                        blocks = r.padding(rate,whole,tail,valid,suffix,width)
                        self.assertEqual(b''.join(blocks),expected)
                        self.assertTrue(all(len(b)==rate for b in blocks))
            for tail in range(256):
                for valid in range(1,8):
                    self.assertEqual(r.padding(rate,bytes(rate-1),tail,valid,31,5),
                                     r.padding(rate,bytes(rate-1),tail & ((1<<valid)-1),valid,31,5))

    def test_squeeze_ranges_crossings_and_commits(self):
        for rate in (136,168):
            for start in range(rate+1):
                for length in (0,1,rate-1,rate,rate+1,2*rate+7,1024):
                    value = r.squeeze_plan(rate,start,length,19,length+3,3)
                    self.assertIsNone(value['error']);self.assertEqual(value['total'],19+length)
                    self.assertEqual(value['initialized'],length+3)
                    self.assertEqual(sum(n for _,n in value['ranges']),length)
                    self.assertEqual(sum(value['writes']),length)
                    self.assertEqual(value['staging_clears'],len(value['writes']))
                    expected_position = (start+length-1)%rate+1 if length else start
                    expected_permutations = (start+length-1)//rate if length else 0
                    self.assertEqual((value['position'],value['permutations']),(expected_position,expected_permutations))
                    self.assertTrue(all(0<=at<rate and 0<n<=rate-at for at,n in value['ranges']))

    def test_squeeze_failures_and_zero_work(self):
        maximum = (1<<128)-1
        for rate in (136,168):
            value = r.squeeze_plan(rate,0,1,maximum,1,0)
            self.assertEqual((value['error'],value['ranges'],value['staging_clears']),('OutputTooLong',[],0))
            for start in (rate+1,255):
                value = r.squeeze_plan(rate,start,1,0,1,0)
                self.assertEqual((value['error'],value['ranges'],value['staging_clears']),('StateConsumed',[],0))
            for has_region,cap,init in ((False,1024,0),(True,0,0),(True,(1<<64)-1,(1<<64)-1)):
                value = r.squeeze_plan(rate,0,1,20,cap,init,has_region)
                self.assertEqual((value['error'],value['writes'],value['staging_clears'],value['total']),('SecretMemory',[],1,20))
            value = r.squeeze_plan(rate,0,rate+1,20,rate,0)
            self.assertEqual((value['error'],value['writes'],value['initialized'],value['staging_clears'],value['total']),
                             ('SecretMemory',[rate],rate,2,20))
            value = r.squeeze_plan(rate,255,0,20,0,0,False)
            self.assertEqual((value['error'],value['position'],value['staging_clears']),(None,255,0))

    def test_compiler_preconditions_are_load_bearing(self):
        lines = []
        for role,pin in self.pins.items():
            tokens = 'dereferenceable(1041) dereferenceable(32)' if role.startswith('enter') else 'dereferenceable(1040) '
            tokens += 'dereferenceable_or_null(1) range(i8 4, 32) range(i8 3, 6)' if role.startswith('finalize') else 'dereferenceable(24)'
            lines.append('define internal fastcc void @'+pin['name']+'('+tokens+')')
        raw = '\n'.join(lines).encode()
        with patch.object(r.ops.s,'IR_HASH',r.digest(raw)): r.preconditions(raw,self.pins)
        for token in ('dereferenceable(1041)','dereferenceable(1040)','dereferenceable_or_null(1)','range(i8 4, 32)','range(i8 3, 6)','dereferenceable(24)'):
            bad = raw.replace(token.encode(),b'unbounded')
            with patch.object(r.ops.s,'IR_HASH',r.digest(bad)):
                with self.assertRaises(ValueError): r.preconditions(bad,self.pins)

    def test_rate_normalization_preserves_backing_bounds(self):
        values = []
        for rate in (136,168):
            body = f'cmpq ${rate*8}, %r14\njne .LBB18_14\ncmpq $1344, %r14\njae .LBB18_16\nmovl $168, %edx'
            value = r.s.common_shape('finalize',rate,body,'name',self.pins);values.append(value)
            self.assertIn('cmpq $1344, %r14\njae .LBBX_16',value)
            self.assertIn('movl $168, %edx',value)
            self.assertNotEqual(value,r.s.common_shape('finalize',rate,body.replace('jae','jb'),'name',self.pins))
        self.assertEqual(values[0],values[1])

    def test_actual_operation_specific_connections(self):
        names = {k:self.helpers[k]['name'] for k in ('copy','copy_bytes','mask','xor')}
        names.update(zero=r.s.ZERO,permutation=r.s.PERMUTE)
        names.update({'update'+str(rate):r.state.s.UPDATE+format(rate,'x')+'_E6updateB6_' for rate in (136,168)})
        external = {k:dict(entry=n,rva=10000+i*100,image_sha256='same',reference_targets={}) for i,(k,n) in enumerate(names.items())}
        records = {k:dict(entry=p['name'],rva=100+i*100,image_sha256='same',reference_targets={}) for i,(k,p) in enumerate(self.pins.items())}
        for role,record in records.items():
            if role.startswith('enter'): callees = [external['zero'],external['update'+role[-3:]],records['finalize'+role[-3:]]]
            else:
                keys = ('copy','mask','xor','zero','permutation') if role.startswith('finalize') else ('copy','copy_bytes','zero','permutation')
                callees = [external[k] for k in keys]
            record['reference_targets'] = {c['entry']:c['rva'] for c in callees}
        anchors = [dict(image_sha256='same',reference_targets={v['entry']:v['rva'] for k,v in records.items() if not k.startswith('finalize')})]
        r.connections(records,anchors,external,self.pins)
        for role,record in records.items():
            for name in record['reference_targets']:
                bad = copy.deepcopy(records);bad[role]['reference_targets'][name] += 1
                with self.assertRaises(ValueError): r.connections(bad,anchors,external,self.pins)
        with self.assertRaises(ValueError): r.connections(records,[],external,self.pins)
        bad = copy.deepcopy(external);bad['zero']['image_sha256'] = 'other'
        with self.assertRaises(ValueError): r.connections(records,anchors,bad,self.pins)


if __name__=='__main__': unittest.main()
