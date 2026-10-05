"""Regress saved setup bindings and public metadata/fragment models."""
import copy
import random
import unittest

import windows_enclave_sha3_setup as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins=r.specification(r.SPEC.read_bytes())['functions']
        self.helpers=r.t.specification(r.t.SPEC.read_bytes())['functions']

    def test_body_bytes_and_relocations(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for pin in self.pins.values():
            raw=bytes.fromhex(pin['code_hex']);refs=pin['references'];r.t.instructions(raw,refs,pin)
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.t.instructions(bad,refs,pin)
            for at in range(len(refs)):
                for field in ('symbol','offset','addend','trailing'):
                    bad=copy.deepcopy(refs);bad[at][field]='wrong' if field=='symbol' else bad[at][field]+1
                    with self.assertRaises(ValueError): r.t.instructions(raw,bad,pin)

    def test_semantic_mutants_without_identity_hashes(self):
        for kind in ('push','bits','advance'):
            for rate in (136,168):
                seqs=r.sequences(kind,rate,self.helpers);extra=[]
                if kind=='advance':
                    offset=32 if rate==136 else 64
                    vector,store=('%xmm0','movaps') if rate==136 else ('%xmm1','movdqa')
                    extra=[f'{store} {vector}, {at}(%rsp)' for at in range(offset,offset+160,16)]
                    extra.append(f'movq $0, {offset+160}(%rsp)')
                text='\n'.join(s.replace('|','\n') for s in (*seqs,*extra))
                r.landmarks(kind,rate,text,self.helpers)
                for seq in (*seqs,*extra):
                    with self.assertRaises(ValueError):
                        r.landmarks(kind,rate,text.replace(seq.replace('|','\n'),'int3'),self.helpers)

    def test_u128_remainder_against_integer_oracle(self):
        rng=random.Random(0x504850)
        values=list(range(4096))+[rng.getrandbits(128) for _ in range(100000)]
        for bit in range(128):
            for delta in (-1,0,1):
                value=(1<<bit)+delta
                if 0<=value<1<<128: values.append(value)
        values.extend([(1<<128)-1,(1<<128)-136,(1<<64)-1,1<<64])
        for value in values: self.assertEqual(r.remainder136(value),value%136)

    def test_fragment_packing_against_bit_concatenation(self):
        for used in range(8):
            for valid in range(1,9):
                for source in range(256):
                    pending=0xa5 & ((1<<used)-1)
                    bits=[(pending>>i)&1 for i in range(used)]+[(source>>i)&1 for i in range(valid)]
                    expected=[sum(bits[i+j]<<j for j in range(8)) for i in range(0,len(bits)-7,8)]
                    tail=bits[len(expected)*8:]
                    value=r.push_bits(pending,used,123,source,valid)
                    self.assertIsNone(value['error']);self.assertEqual(value['calls'],expected)
                    self.assertEqual(value['pending'],sum(bit<<i for i,bit in enumerate(tail)))
                    self.assertEqual(value['used'],len(tail));self.assertEqual(value['clears'],len(expected))
                    self.assertEqual(value['emitted'],123+len(expected))

    def test_fragment_failures_retain_pending_until_outer_cleanup(self):
        maximum=(1<<128)-1
        for extra,error,calls in (({},'MessageTooLong',[]),({'owner':False},'StateConsumed',[]),
                                  ({'fail_update':True},'MessageTooLong',[255])):
            count=maximum if not extra else 99
            value=r.push_bits(127,7,count,1,1,**extra)
            self.assertEqual(value,dict(error=error,pending=255,used=8,emitted=count,calls=calls,clears=0))
        value=r.push_bits(1,1,maximum,1,1,owner=False)
        self.assertIsNone(value['error']);self.assertEqual(value['pending'],3)
        for used,valid in ((8,1),(255,1),(0,0),(0,9),(0,255)):
            value=r.push_bits(42,used,0,128,valid)
            self.assertEqual((value['error'],value['pending'],value['clears']),('StateConsumed',42,0))

    def test_pair_normalization_is_narrow(self):
        shapes=[]
        for rate in (136,168):
            body=f'{r.name("bits",rate)}:\ncallq {r.name("push",rate)}\nmovb $0, 65(%rbx)\n.LBB35_1:'
            shapes.append(r.common_shape(rate,body))
            self.assertNotEqual(shapes[-1],r.common_shape(rate,body.replace('65','66')))
        self.assertEqual(*shapes)

    def test_actual_connections_and_frames(self):
        external=('zero','wipe','xor','encode','update136','update168')
        callees={k:dict(entry=k,rva=10000+i*100,image_sha256='same',reference_targets={}) for i,k in enumerate(external)}
        records={k:dict(entry=p['name'],rva=100+i*100,image_sha256='same',reference_targets={},
                       unwind=[dict(stack_bytes=p['stack_bytes'],saved_registers=[],chain=None,frame=0)])
                 for i,(k,p) in enumerate(self.pins.items())}
        owners=dict(image_sha256='same',runtime_boundaries_pending={'__umodti3':99999},
            records={k:dict(reference_targets={}) for k in ('setup','setup_chunk')})
        for role,record in records.items():
            kind,rate=role[:-3],role[-3:]
            keys=('zero','wipe','update'+rate) if kind=='push' else ('zero','xor','update'+rate) if kind=='bits' else ('zero','encode','update'+rate)
            targets={callees[k]['entry']:callees[k]['rva'] for k in keys}
            if kind!='bits': targets[records['bits'+rate]['entry']]=records['bits'+rate]['rva']
            if kind=='push': targets[records['advance'+rate]['entry']]=records['advance'+rate]['rva']
            if role=='advance168': targets['__umodti3']=99999
            record['reference_targets']=targets
            owners['records']['setup_chunk' if kind=='push' else 'setup']['reference_targets'][record['entry']]=record['rva']
        result=r.connections(records,owners,callees,self.pins)
        self.assertFalse(result['internals_qualified']);r.ops.frames(records,self.pins)
        for role,record in records.items():
            for symbol in record['reference_targets']:
                bad=copy.deepcopy(records);bad[role]['reference_targets'][symbol] += 1
                with self.assertRaises(ValueError): r.connections(bad,owners,callees,self.pins)
            bad=copy.deepcopy(records);bad[role]['unwind'][0]['stack_bytes'] += 8
            with self.assertRaises(ValueError): r.ops.frames(bad,self.pins)
        bad=copy.deepcopy(callees);bad['wipe']['image_sha256']='other'
        with self.assertRaises(ValueError): r.connections(records,owners,bad,self.pins)

    def test_geometry_separates_public_slots_and_deeper_callees(self):
        owners={'geometry':{'paths':{'setup_chunk':{'rsp_from_high':-2000}}}}
        value=r.geometry(r.life.bounded.Window(0,65536),owners)
        for rate,frame in (('136',344),('168',376)):
            path=value['paths'][rate]
            self.assertEqual(path['push_rsp'],-2128)
            self.assertEqual(path['advance_rsp'],-2128-8-frame)
            self.assertEqual(path['update_rsp'],path['advance_rsp']-112-144)
            self.assertEqual(path['public_encoded_length']['bytes'],258)
            self.assertEqual(path['public_zero_padding']['bytes'],168)
        self.assertFalse(value['maximum_whole_image_depth_qualified'])
        with self.assertRaises(ValueError): r.geometry(r.life.bounded.Window(0,2000),owners)


if __name__=='__main__': unittest.main()
