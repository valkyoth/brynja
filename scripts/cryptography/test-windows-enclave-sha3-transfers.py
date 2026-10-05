"""Focused tests for helper identity, actual connections and reviewed contracts."""
import copy
import random
import unittest
from unittest.mock import patch

import windows_enclave_sha3_transfers as r


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())['functions']

    def test_spec_and_all_instruction_bytes(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for p in self.pins.values():
            code = bytes.fromhex(p['code_hex']);refs = p['references'];r.instructions(code,refs,p)
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(bad,refs,p)
            with self.assertRaises(ValueError): r.instructions(code+b'\0',refs,p)
            for at in range(len(refs)):
                for field in ('offset','addend','trailing'):
                    bad = copy.deepcopy(refs);bad[at][field] += 1
                    with self.assertRaises(ValueError): r.instructions(code,bad,p)

    def test_semantic_landmarks_without_identity_hashes(self):
        bodies = {k:'\n'.join(v.replace('|','\n') for v in items) for k,items in r.sequences(self.pins).items()}
        for role,marker,erase in r.ERASURES: bodies[role] = '# BRYNJA_'+marker+'_ERASE\n'+erase.replace('|','\n')
        r.landmarks(bodies,self.pins)
        for role,items in r.sequences(self.pins).items():
            for item in items:
                bad = dict(bodies);bad[role] = bad[role].replace(item.replace('|','\n'),'int3')
                with self.assertRaises(ValueError): r.landmarks(bad,self.pins)
        for role,marker,erase in r.ERASURES:
            for token in ('BRYNJA_'+marker+'_ERASE',*erase.split('|')):
                bad = dict(bodies);bad[role] = bad[role].replace(token,'int3')
                with self.assertRaises(ValueError): r.landmarks(bad,self.pins)

    def test_typed_completion_rejects_every_incomplete_boundary(self):
        maximum = (1<<64)-1
        for present in (False,True):
            for region in (False,True):
                for length in (0,1,28,32,48,64,1024,maximum):
                    for initialized in {0,length,max(0,length-1),min(maximum,length+1)}:
                        value = r.output_contract(present,region,length,initialized)
                        complete = present and region and length==initialized
                        self.assertEqual(value['publish'],complete)
                        self.assertEqual(value['tag'],0 if not present else 1 if complete else 2)
                        self.assertEqual(value['clear_bytes'],length if present and region and not complete else 0)
        for length in (-1,1<<64):
            with self.assertRaises(ValueError): r.output_contract(True,True,length,0)

    def test_copy_loop_covers_exact_range_without_overread(self):
        for length in range(1025):
            accesses = r.copy_accesses(length);cursor = 0
            for at,size in accesses:
                self.assertEqual(at,cursor);self.assertIn(size,(1,8));self.assertLessEqual(at+size,length)
                cursor += size
            self.assertEqual(cursor,length)
            self.assertEqual(sum(n==8 for _,n in accesses),length//8)
            self.assertEqual(sum(n==1 for _,n in accesses),length%8)
        for n in (-1,1025):
            with self.assertRaises(ValueError): r.copy_accesses(n)

    def test_xor_every_source_byte_and_public_bit_range(self):
        for source in range(256):
            for right in (*range(10),255):
                for count in range(9):
                    for left in range(9):
                        value = r.xor_contract(source,right,count,left)
                        valid = count>0 and right+count<=8 and left+count<=8
                        expected = sum(((source>>(right+i)) & 1)<<(left+i) for i in range(count)) if valid else None
                        self.assertEqual(value,expected)
        with self.assertRaises(ValueError): r.xor_contract(0,0,9,0)

    def test_public_u128_encoding_all_byte_boundaries(self):
        values = {0,(1<<128)-1}
        for bit in range(128): values.update(((1<<bit)-1,1<<bit,min((1<<128)-1,(1<<bit)+1)))
        generator = random.Random(0x53484133)
        values.update(generator.getrandbits(128) for _ in range(256))
        for value in values:
            raw = r.encoded_layout(value);width = max(1,(value.bit_length()+7)//8)
            expected = bytes([width])+value.to_bytes(width,'big')
            self.assertEqual(len(raw),258);self.assertEqual(raw[:width+1],expected)
            self.assertEqual(raw[width+1:256],bytes(255-width))
            self.assertEqual(int.from_bytes(raw[256:],'little'),width+1)
        for value in (-1,1<<128):
            with self.assertRaises(ValueError): r.encoded_layout(value)

    def test_private_compiler_contracts(self):
        tokens = dict(copy='range(i64 0, 1025)',copy_bytes='range(i64 0, 1025)',
                      xor='range(i8 0, 9), range(i8 0, 9)',xor_bits='range(i32 0, 9)',
                      output='dereferenceable(32)',encode='dereferenceable(258)')
        text = '\n'.join('define internal fastcc void @'+self.pins[k]['name']+'('+v+')' for k,v in tokens.items())
        with patch.object(r.ops.s,'IR_HASH',r.digest(text.encode())):
            value = r.preconditions(text.encode(),self.pins)
            self.assertFalse(value['standalone_arbitrary_abi_calls_qualified'])
        for token in set(tokens.values()):
            bad = text.replace(token,'unbounded').encode()
            with patch.object(r.ops.s,'IR_HASH',r.digest(bad)):
                with self.assertRaises(ValueError): r.preconditions(bad,self.pins)

    def test_complete_reached_edges_and_frames(self):
        records = {k:dict(rva=100+i*100,image_sha256='same',reference_targets={}) for i,k in enumerate(self.pins)}
        external = dict(zero=10000,memcpy=11000,memset=12000)
        for role,record in records.items():
            if role in r.FRAMES:
                record['unwind'] = [dict(stack_bytes=r.FRAMES[role],saved_registers=[],frame=0,chain=None)]
            for edge in r.EDGES[role]:
                name = self.pins[edge]['name'] if edge in self.pins else r.state.s.ZERO if edge=='zero' else edge
                record['reference_targets'][name] = records[edge]['rva'] if edge in records else external[edge]
        anchor = dict(image_sha256='same',reference_targets={self.pins[k]['name']:records[k]['rva'] for k in ('copy','xor','mask','predicate','output','encode')})
        r.reconcile(records,[anchor],self.pins,external)
        for role,record in records.items():
            for edge in record['reference_targets']:
                for remove in (False,True):
                    bad = copy.deepcopy(records)
                    if remove: del bad[role]['reference_targets'][edge]
                    else: bad[role]['reference_targets'][edge] += 1
                    with self.assertRaises(ValueError): r.reconcile(bad,[anchor],self.pins,external)
            bad = copy.deepcopy(records);bad[role]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.reconcile(bad,[anchor],self.pins,external)
        with self.assertRaises(ValueError): r.reconcile(records,[],self.pins,external)
        for role in r.FRAMES:
            bad = copy.deepcopy(records);bad[role]['unwind'][0]['stack_bytes'] += 8
            with self.assertRaises(ValueError): r.reconcile(bad,[anchor],self.pins,external)

    def test_selected_geometry_not_whole_image(self):
        parent = dict(geometry=dict(paths={'rehash -> finish_fixed':dict(rsp_from_high=-8320)}))
        g = r.geometry(r.life.bounded.Window(0,65536),parent)
        self.assertEqual(g['xor_leaf_entry_from_high'],-8392)
        self.assertEqual(g['copy_leaf_entry_from_high'],-8376)
        self.assertTrue(g['outer_window_clearing_required'])
        self.assertFalse(g['maximum_whole_image_depth_qualified'])
        self.assertEqual(g,r.geometry(r.life.bounded.Window(4096,69632),parent))


if __name__=='__main__': unittest.main()
