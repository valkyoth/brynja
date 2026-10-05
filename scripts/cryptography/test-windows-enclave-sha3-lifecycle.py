"""Focused regressions for selected scalar SHA-3 cleanup, not crypto correctness."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha3_lifecycle as r

s = r.s


class Tests(unittest.TestCase):
    def test_bodies_and_complete_reference_identity(self):
        for name in s.PINS:
            code,refs = s.wipe_shape() if name==s.WIPE else (bytes.fromhex(s.EXACT[name]),[])
            self.assertEqual(r.digest(code),s.PINS[name][1])
            if name==s.WIPE or name==s.ZERO: r.body_check(name,code,refs)
            with self.assertRaises(ValueError): r.body_check(name,code+b'\0',refs)
        code,refs = s.wipe_shape()
        for bad in (refs[:-1],refs*2,[refs[0] | {'addend':1}]+refs[1:]):
            with self.assertRaises(ValueError): r.body_check(s.WIPE,code,bad)

    def test_instruction_mutants_without_hash_checks(self):
        for name in s.PINS:
            code,refs = s.wipe_shape() if name==s.WIPE else (bytes.fromhex(s.EXACT[name]),[])
            r.instructions(name,code,refs)
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,bad,refs)
        code,refs = s.wipe_shape()
        for at in range(len(refs)):
            bad = copy.deepcopy(refs);bad[at]['symbol'] = 'not_clear'
            with self.assertRaises(ValueError): r.instructions(s.WIPE,code,bad)

    def test_complete_thirteen_region_coverage(self):
        r.coverage(s.REGIONS)
        for i,(start,length) in enumerate(s.REGIONS):
            for altered in ((start+1,length),(start,length-1),(start,length+1)):
                bad = list(s.REGIONS);bad[i] = altered
                with self.assertRaises(ValueError): r.coverage(bad)
        for bad in (s.REGIONS[:-1],s.REGIONS+((1040,1),)):
            with self.assertRaises(ValueError): r.coverage(bad)

    def test_cancellation_phase_sequence_and_overflow_model(self):
        maximum = (1<<64)-1
        for phase in range(8):
            for stored in (0,1,maximum-1,maximum):
                for requested in (0,1,2,maximum-1,maximum):
                    result = r.cancellation(phase,stored,requested)
                    valid = 1<=phase<=6
                    ok = valid and requested!=0 and stored<maximum and stored+1==requested
                    self.assertEqual(result['error'],None if ok else 'Sequence' if valid else 'State')
                    self.assertEqual(result['phase'],0 if ok else 7)
                    self.assertEqual(result['sequence'],requested if ok else stored)
                    self.assertTrue(result['active_state_dropped'] and result['retained_output_erased'])
        for bad in ((8,0,1),(0,-1,0),(0,0,1<<64)):
            with self.assertRaises(ValueError): r.cancellation(*bad)

    def test_all_initialized_state_destructor_variants(self):
        for tag in range(9):
            for present in (False,True) if tag>=7 else (False,):
                result = r.state_writes(tag,present)
                ranges = result['volatile']+result['ordinary_zero']
                self.assertTrue(all(1024<=at<at+n<=2160 for at,n in ranges))
                expected = 0 if tag==0 else 1040 if tag<7 else 1+2080*present
                self.assertEqual(sum(n for _,n in result['volatile']),expected)
                if tag>=7:
                    self.assertEqual(result['ordinary_markers'],[(1106,3)])
                    self.assertIn((1040,64),result['ordinary_zero'])
                    self.assertNotIn((1040,64),result['volatile'])
        for tag in (-1,9):
            with self.assertRaises(ValueError): r.state_writes(tag)
        with self.assertRaises(ValueError): r.state_writes(1,True)

    def test_linked_table_all_destinations_and_bytes(self):
        address,start = 10000,2000
        raw = b''.join((start+v-address).to_bytes(4,'little',signed=True) for v in s.DESTINATIONS)
        self.assertEqual(r.table_destinations(raw,address,start),s.DESTINATIONS)
        for at in range(32):
            bad = bytearray(raw);bad[at] ^= 1
            with self.assertRaises(ValueError): r.table_destinations(bad,address,start)
        for bad in (raw[:-4],raw+bytes(4)):
            with self.assertRaises(ValueError): r.table_destinations(bad,address,start)
        with self.assertRaises(ValueError): r.table_destinations(raw,address+4,start)

    def test_readonly_table_and_relocation_closure(self):
        address,start = 10000,2000
        raw = b''.join((start+v-address).to_bytes(4,'little',signed=True) for v in s.DESTINATIONS)
        section = dict(code=s.TABLE,flags=0x40000000)
        symbols = {1:dict(value=0,section=1),2:dict(value=0,section=2,name='.text')}
        refs = [dict(symbol='.rdata',offset=19,addend=0,trailing=0,symbol_index=1)]
        relocs = {at:dict(symbol=2,kind=4) for at in range(0,32,4)}
        linked = [dict(code=raw,rva=address,virtual_size=32,flags=0x40000000)]
        record = dict(rva=start,reference_targets={'.rdata':address})
        with patch.object(r.obj,'select',return_value=([section],symbols,dict(section=2),b'',refs)),\
             patch.object(r.obj,'relocations',return_value=relocs),\
             patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])):
            r.table(b'',b'',record)
            for at in relocs:
                bad = dict(relocs);del bad[at]
                with patch.object(r.obj,'relocations',return_value=bad):
                    with self.assertRaises(ValueError): r.table(b'',b'',record)
            for flags in (0xc0000000,0x60000000):
                linked[0]['flags'] = flags
                with self.assertRaises(ValueError): r.table(b'',b'',record)
            linked[0]['flags'] = 0x40000000;symbols[2]['section'] = 3
            with self.assertRaises(ValueError): r.table(b'',b'',record)

    def test_incoming_edges_and_frames(self):
        records = {n:dict(rva=100+i*100,image_sha256='same',reference_targets={},
                         unwind=[dict(stack_bytes=s.FRAMES.get(n,0),chain=None,saved_registers=[])]) for i,n in enumerate(s.PINS)}
        anchors = {n:dict(rva=2000+i*100,image_sha256='same',reference_targets={}) for i,n in enumerate(('RetainedWork',s.RECEIVE))}
        for n in (s.QUARANTINE,s.CLEAR_OWNER,s.DROP,s.ZERO,s.RECEIVE):
            anchors['RetainedWork']['reference_targets'][n] = (records | anchors)[n]['rva']
        anchors[s.RECEIVE]['reference_targets'][s.CANCEL] = records[s.CANCEL]['rva']
        for n in (s.QUARANTINE,s.CLEAR_OWNER,s.CANCEL):
            records[n]['reference_targets'] = {k:records[k]['rva'] for k in (s.DROP,s.ZERO)}
        records[s.DROP]['reference_targets'] = {k:records[k]['rva'] for k in (s.WIPE,s.ZERO)}
        records[s.WIPE]['reference_targets'][s.ZERO] = records[s.ZERO]['rva']
        jump = dict(rva=10000);records[s.DROP]['reference_targets']['.rdata'] = jump['rva']
        r.reconcile(records,anchors,jump)
        for n,rec in records.items():
            bad = copy.deepcopy(records);bad[n]['image_sha256'] = 'different'
            with self.assertRaises(ValueError): r.reconcile(bad,anchors,jump)
            if n!=s.ZERO:
                bad = copy.deepcopy(records);bad[n]['unwind'][0]['stack_bytes'] += 8
                with self.assertRaises(ValueError): r.reconcile(bad,anchors,jump)
            for edge in rec['reference_targets']:
                for remove in (True,False):
                    bad = copy.deepcopy(records)
                    if remove: del bad[n]['reference_targets'][edge]
                    else: bad[n]['reference_targets'][edge] += 1
                    with self.assertRaises(ValueError): r.reconcile(bad,anchors,jump)
        for caller,rec in anchors.items():
            for edge in rec['reference_targets']:
                bad = copy.deepcopy(anchors);del bad[caller]['reference_targets'][edge]
                with self.assertRaises(ValueError): r.reconcile(records,bad,jump)

    def test_typed_drop_before_complete_page_loop(self):
        sequences = [
            'callq '+s.CLEAR_OWNER+'\naddq $1024, %rsi\nmovq %rsi, %rcx\ncallq '+s.DROP,
            'movq $0, _RNvCsgzEJPm6isiJ_18sha3_stream_worker4LIVE.0(%rip)',
            '\n'.join('movb $0, '+('' if i==0 else str(i))+'(%rcx,%rdx)' for i in range(8)),
            'addq $8, %rdx\ncmpq $4096, %rdx\njne .LBB0_7',
        ]
        text = '\nRetainedWork:\n'+'\n'.join(sequences)+'\n.seh_endproc\n'
        with patch.object(r,'ASM_HASH',r.digest(text.encode())):
            r.teardown_assembly(text.encode())
            with self.assertRaises(ValueError): r.teardown_assembly(text.encode()+b' ')
        for sequence in sequences:
            bad = text.replace(sequence,'.int3').encode()
            with patch.object(r,'ASM_HASH',r.digest(bad)):
                with self.assertRaises(ValueError): r.teardown_assembly(bad)
        bad = (text+text).encode()
        with patch.object(r,'ASM_HASH',r.digest(bad)):
            with self.assertRaises(ValueError): r.teardown_assembly(bad)

    def test_geometry_and_scope_limits(self):
        g = r.geometry(r.bounded.Window(0,65536))
        self.assertEqual(g['cancel_rsp_from_high'],-1584)
        self.assertEqual(g['setup_wipe_rsp_from_high'],-1696)
        self.assertEqual(g['clearing_leaf_entry_from_high'],-1704)
        self.assertTrue(g['saved_registers_require_window_clearing'])
        self.assertTrue(g['inactive_owner_bytes_require_page_clearing'])
        self.assertFalse(g['maximum_whole_image_depth_qualified'])
        self.assertFalse(g['other_owner_operation_paths_qualified'])
        self.assertEqual(g,r.geometry(r.bounded.Window(4096,69632)))


if __name__=='__main__': unittest.main()
