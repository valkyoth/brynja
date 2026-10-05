"""Focused regressions for the saved scalar prefix review and branch model."""
import copy
import unittest

import windows_enclave_sha3_prefix as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())['functions']
        self.helpers = r.t.specification(r.t.SPEC.read_bytes())['functions']

    def test_complete_identity_and_relocations(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for p in self.pins.values():
            raw = bytes.fromhex(p['code_hex']);refs = p['references'];r.t.instructions(raw,refs,p)
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.t.instructions(bad,refs,p)
            for index in range(len(refs)):
                for field in ('offset','addend','trailing','symbol'):
                    bad = copy.deepcopy(refs)
                    bad[index][field] = 'wrong' if field=='symbol' else bad[index][field]+1
                    with self.assertRaises(ValueError): r.t.instructions(raw,bad,p)

    def test_each_semantic_sequence_without_hash_identity(self):
        for role in r.ROLES:
            items = r.sequences(role,self.pins,self.helpers)
            text = '\n'.join(item.replace('|','\n') for item in items)
            r.landmarks(role,text,self.pins,self.helpers)
            for item in items:
                with self.assertRaises(ValueError):
                    r.landmarks(role,text.replace(item.replace('|','\n'),'int3'),self.pins,self.helpers)

    def test_all_source_values_offsets_and_widths(self):
        for used in range(8):
            pending = 0x55 & ((1<<used)-1)
            for valid in range(1,9):
                for source in range(256):
                    value = r.push_bits(pending,used,17,source,valid)
                    bits = [(pending>>i)&1 for i in range(used)]+[(source>>i)&1 for i in range(valid)]
                    complete = len(bits)//8
                    expected = [sum(bits[i*8+j]<<j for j in range(8)) for i in range(complete)]
                    tail = sum(bit<<i for i,bit in enumerate(bits[complete*8:]))
                    self.assertEqual(value,dict(ok=True,pending=tail,used=len(bits)%8,
                        emitted=17+complete,calls=expected,clears=complete))

    def test_invalid_admission_preserves_state(self):
        for used in range(256):
            for valid in range(256):
                if used<8 and 1<=valid<=8: continue
                self.assertEqual(r.push_bits(0xa5,used,19,0x96,valid),
                    dict(ok=False,pending=0xa5,used=used,emitted=19,calls=[],clears=0))

    def test_overflow_and_rejection_require_outer_cleanup(self):
        maximum = (1<<64)-1
        for used in range(8):
            for valid in range(1,9):
                pending = (1<<used)-1
                for reject in (False,True):
                    emitted = 10 if reject else maximum
                    value = r.push_bits(pending,used,emitted,0x96,valid,reject)
                    self.assertEqual(value['ok'],used+valid<8)
                    self.assertEqual(value['emitted'],emitted)
                    self.assertEqual(value['clears'],0)
                    if used+valid>=8:
                        take = 8-used
                        self.assertEqual(value['used'],8)
                        self.assertEqual(value['pending'],pending|((0x96 & ((1<<take)-1))<<used))
                        self.assertEqual(value['calls'],[value['pending']] if reject else [])
                    else: self.assertEqual(value['calls'],[])
        # A successful flush at the maximum admissible boundary still clears.
        self.assertEqual(r.push_bits(0,0,maximum-1,0x96,8),
            dict(ok=True,pending=0,used=0,emitted=maximum,calls=[0x96],clears=1))

    def graph(self):
        records = {k:dict(entry=p['name'],rva=100+i*100,image_sha256='same',reference_targets={})
                   for i,(k,p) in enumerate(self.pins.items())}
        helpers = {k:dict(entry=p['name'],rva=2000+i*100,image_sha256='same',reference_targets={})
                   for i,(k,p) in enumerate(self.helpers.items()) if k in ('encode','xor')}
        helpers['zero'] = dict(entry=r.state.s.ZERO,rva=4000,image_sha256='same',reference_targets={})
        updates = {k:dict(entry=n,rva=5000+i*100,image_sha256='same',reference_targets={}) for i,(k,n) in enumerate(r.UPDATE.items())}
        for role,record in records.items():
            rate = role[-3:]
            callees = [updates[rate],helpers['encode'],records['bits'+rate]] if role.startswith('string') else [
                updates[rate],helpers['xor'],helpers['zero']]
            record['reference_targets'] = {c['entry']:c['rva'] for c in callees}
        parent = dict(image_sha256='same',records=dict(new=dict(image_sha256='same',reference_targets={
            self.pins['string'+rate]['name']:records['string'+rate]['rva'] for rate in r.UPDATE})))
        return records,parent,helpers,updates

    def test_actual_rate_specific_connections(self):
        records,parent,helpers,updates = self.graph()
        r.connections(records,parent,helpers,updates,self.pins)
        for role,rec in records.items():
            for name in rec['reference_targets']:
                for remove in (True,False):
                    bad = copy.deepcopy(records)
                    if remove: del bad[role]['reference_targets'][name]
                    else: bad[role]['reference_targets'][name] += 1
                    with self.assertRaises(ValueError): r.connections(bad,parent,helpers,updates,self.pins)
        for rate in r.UPDATE:
            bad = copy.deepcopy(parent);del bad['records']['new']['reference_targets'][self.pins['string'+rate]['name']]
            with self.assertRaises(ValueError): r.connections(records,bad,helpers,updates,self.pins)
            bad = copy.deepcopy(updates);bad[rate]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.connections(records,parent,helpers,bad,self.pins)
        bad = copy.deepcopy(records);bad['bits128']['reference_targets'][r.UPDATE['128']] = updates['256']['rva']
        with self.assertRaises(ValueError): r.connections(bad,parent,helpers,updates,self.pins)

    def test_frame_metadata_rejects_changed_allocation(self):
        records = {k:dict(unwind=[dict(stack_bytes=p['stack_bytes'],saved_registers=[],chain=None,frame=0)]) for k,p in self.pins.items()}
        r.ops.frames(records,self.pins)
        for role in records:
            for key,value in (('stack_bytes',8),('saved_registers',[{}]),('chain',[]),('frame',1)):
                bad = copy.deepcopy(records);bad[role]['unwind'][0][key] = value
                with self.assertRaises(ValueError): r.ops.frames(bad,self.pins)

    def test_selected_depth_not_full_sponge_depth(self):
        parent = dict(geometry=dict(paths={k:dict(rsp_from_high=v) for k,v in
            (('begin -> new',-6672),('rehash -> new',-7744))}))
        value = r.geometry(r.life.bounded.Window(0,65536),parent)
        self.assertFalse(value['maximum_whole_image_depth_qualified'])
        self.assertTrue(value['outer_window_clearing_required'])
        path = value['paths']['rehash -> new']
        self.assertEqual((path['string_rsp'],path['bits_rsp'],path['encode_rsp'],path['xor_leaf_entry']),
            (-8112,-8240,-8464,-8312))
        self.assertIsNone(path['update_entry']['callee_frame_bytes'])
        self.assertEqual(value,r.geometry(r.life.bounded.Window(4096,69632),parent))


if __name__=='__main__': unittest.main()
