"""Regress saved terminal adapters, without asserting whole-image qualification."""
import copy
import unittest

import windows_enclave_sha3_terminal as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())['functions']
        self.helpers = r.t.specification(r.t.SPEC.read_bytes())['functions']

    def test_all_bytes_and_relocations(self):
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

    def test_semantics_and_erasure_without_hashes(self):
        for rate in (136,168):
            seqs = (*r.sequences(rate,self.helpers,'squeeze'),r.wipe_epilogue())
            text = '\n'.join(s.replace('|','\n') for s in seqs)
            text += '\ncallq '+r.PERMUTE+'\n'+'\n'.join(r.erasure())
            r.landmarks(rate,text,self.helpers,'squeeze')
            for seq in seqs:
                with self.assertRaises(ValueError):
                    r.landmarks(rate,text.replace(seq.replace('|','\n'),'int3'),self.helpers,'squeeze')
            for instruction in r.erasure():
                with self.assertRaises(ValueError):
                    r.landmarks(rate,text.replace(instruction,'int3'),self.helpers,'squeeze')
            with self.assertRaises(ValueError):
                r.landmarks(rate,text+'\ncallq '+r.PERMUTE,self.helpers,'squeeze')

    def test_canonical_success_and_phase_rejection(self):
        for length in range(1025):
            for valid in (range(1,9) if length else (0,)):
                value = r.disposition(1,length,valid,0)
                self.assertIsNone(value['error']);self.assertTrue(value['publish'])
                self.assertTrue(value['wipe_owner']);self.assertEqual(value['phase'],2)
                self.assertEqual(value['clear_destination'],length)
                self.assertEqual(value['complete_bytes'],length-int(length>0 and valid!=8))
                for phase in (0,2):
                    value = r.disposition(phase,length,valid,0)
                    self.assertEqual(value,dict(error='StateConsumed',phase=phase,
                        clear_destination=0,wipe_owner=False,publish=False))

    def test_overflow_and_empty_terminal(self):
        maximum = (1<<128)-1
        for length,valid,total in ((1,8,maximum),(2,1,maximum),(1024,8,maximum-1023)):
            value = r.disposition(1,length,valid,total)
            self.assertEqual(value['error'],'OutputTooLong');self.assertFalse(value['publish'])
            self.assertTrue(value['wipe_owner']);self.assertEqual(value['clear_failed_output_again'],length)
        for valid in range(1,8):
            self.assertIsNone(r.disposition(1,1,valid,maximum)['error'])
        value = r.disposition(1,0,0,maximum,complete_error=True,tail_error=True)
        self.assertIsNone(value['error']);self.assertTrue(value['wipe_owner'])
        self.assertEqual((value['clear_destination'],value['complete_bytes']),(0,0))

    def test_failures_and_incomplete_initialization(self):
        for length in (1,135,136,168,169,1024):
            for valid in range(1,9):
                for kw in ({'complete_error':True},{'initialized':length-1},{'initialized':length+1}):
                    value = r.disposition(1,length,valid,7,**kw)
                    self.assertIsNotNone(value['error']);self.assertTrue(value['wipe_owner'])
                    self.assertFalse(value['publish']);self.assertEqual(value['clear_failed_output_again'],length)
                value = r.disposition(1,length,valid,7,tail_error=True)
                self.assertEqual(value['error'] is None,valid==8)
        for args in ((1,0,8,0),(1,1,0,0),(1,1,9,0),(1,1025,8,0),(3,1,8,0)):
            with self.assertRaises(ValueError): r.disposition(*args)

    def test_partial_mask_against_bit_list(self):
        for valid in range(1,8):
            mask = r.disposition(1,1,valid,0)['tail_mask']
            for byte in range(256):
                expected = sum(((byte>>bit)&1)<<bit for bit in range(valid))
                self.assertEqual(byte & mask,expected)
                self.assertEqual((byte & mask)>>valid,0)

    def test_only_reviewed_rate_differences_normalize(self):
        shapes = []
        for rate in (136,168):
            body = f'name:\ncmpb ${rate-256}, %r12b\ncallq squeeze\nmovl $168, %edx\n.LBB12_30:'
            shape = r.common_shape(rate,body,'name','squeeze');shapes.append(shape)
            self.assertIn('movl $168, %edx',shape)
            self.assertNotEqual(shape,r.common_shape(rate,body.replace('$168','$136'),'name','squeeze'))
        self.assertEqual(*shapes)

    def test_actual_connections_and_frames(self):
        callees = {key:dict(entry=key,rva=10000+i*100,image_sha256='same',reference_targets={})
                   for i,key in enumerate(('zero','wipe','copy','copy_bytes','mask','permutation','squeeze136','squeeze168'))}
        records = {rate:dict(entry=pin['name'],rva=100+i*100,image_sha256='same',reference_targets={})
                   for i,(rate,pin) in enumerate(self.pins.items())}
        for rate,record in records.items():
            keys = ('zero','wipe','copy','copy_bytes','mask','permutation','squeeze'+rate)
            record['reference_targets'] = {callees[k]['entry']:callees[k]['rva'] for k in keys}
        owners = dict(image_sha256='same',records={'squeeze':dict(image_sha256='same',reference_targets={
            record['entry']:record['rva'] for record in records.values()})})
        r.connections(records,owners,callees,self.pins)
        for rate,record in records.items():
            for name in record['reference_targets']:
                bad = copy.deepcopy(records);bad[rate]['reference_targets'][name] += 1
                with self.assertRaises(ValueError): r.connections(bad,owners,callees,self.pins)
            bad = copy.deepcopy(owners);del bad['records']['squeeze']['reference_targets'][record['entry']]
            with self.assertRaises(ValueError): r.connections(records,bad,callees,self.pins)
        bad = copy.deepcopy(callees);bad['wipe']['image_sha256'] = 'other'
        with self.assertRaises(ValueError): r.connections(records,owners,bad,self.pins)
        for record in records.values():
            record['unwind'] = [dict(stack_bytes=136,saved_registers=[],chain=None,frame=0)]
        r.ops.frames(records,self.pins)
        for rate in records:
            for field,value in (('stack_bytes',128),('saved_registers',['xmm6']),('chain',1),('frame',1)):
                bad = copy.deepcopy(records);bad[rate]['unwind'][0][field] = value
                with self.assertRaises(ValueError): r.ops.frames(bad,self.pins)

    def test_selected_geometry_not_whole_image_depth(self):
        owners = {'geometry':{'paths':{'squeeze':{'rsp_from_high':-2768}}}}
        result = r.geometry(r.life.bounded.Window(0,65536),owners)
        self.assertEqual((result['adapter_rsp'],result['squeeze_rsp']),(-2912,-3088))
        self.assertFalse(result['maximum_whole_image_depth_qualified'])
        self.assertTrue(result['outer_window_clearing_required'])
        with self.assertRaises(ValueError): r.geometry(r.life.bounded.Window(0,2800),owners)


if __name__=='__main__': unittest.main()
