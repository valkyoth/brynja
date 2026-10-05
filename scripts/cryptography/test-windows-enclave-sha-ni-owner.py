"""Regression tests for the saved SHA-NI owner/decoder author review."""
import copy
import json
import unittest
from unittest.mock import patch

import windows_enclave_sha_ni_owner as r

s = r.shapes


class Tests(unittest.TestCase):
    def test_spec_and_complete_population(self):
        raw = r.SPEC.read_bytes();self.assertEqual(set(r.specification(raw)),set(s.NAMES))
        with self.assertRaises(ValueError): r.specification(raw+b' ')
        value = json.loads(raw);del value['functions'][s.DECODE];raw = json.dumps(value).encode()
        with patch.object(r,'SPEC_HASH',r.digest(raw)):
            with self.assertRaises(ValueError): r.specification(raw)

    def test_complete_body_and_reference_pins(self):
        code = b'123456';refs = [dict(offset=1,symbol='callee',addend=0,trailing=0)]
        pins = {s.BEGIN:dict(bytes=6,sha256=r.digest(code),references_sha256=r.digest(r.shared.encoded(refs)))}
        r.body_check(s.BEGIN,code,refs,pins)
        for at in range(len(code)):
            bad = bytearray(code);bad[at] ^= 1
            with self.assertRaises(ValueError): r.body_check(s.BEGIN,bad,refs,pins)
        for key,value in (('offset',2),('symbol','different'),('trailing',1),('addend',1)):
            with self.assertRaises(ValueError): r.body_check(s.BEGIN,code,[refs[0] | {key:value}],pins)
        for bad in ([],refs*2):
            with self.assertRaises(ValueError): r.body_check(s.BEGIN,code,bad,pins)
        r.body_check(s.BEGIN,code,[refs[0] | {'symbol_index':77}],pins)

    def test_semantic_sequences_independent_of_identity_hashes(self):
        count = 0
        for name,sequences in s.SEQUENCES.items():
            text = '\n.int3\n'.join(q.replace('|','\n') for q in sequences)
            r.instructions(name,text)
            for sequence in sequences:
                before = sequence.replace('|','\n')
                with self.assertRaises(ValueError): r.instructions(name,text.replace(before,'.int3'))
                count += 1
        self.assertGreater(count,35)

    def test_function_labels_not_cpp_metadata_suffixes(self):
        text = '\n'
        for name,sequences in s.SEQUENCES.items():
            label = '"'+name+'":' if name.startswith('?') else name+':'
            end = '.Lfunc_end18:' if name==s.PREDICATE else '.seh_endproc'
            text += label+'\n'+'\n'.join(q.replace('|','\n') for q in sequences)+'\n'+end+'\n'
        text += '$cppxdata$'+s.FINISH+':\n'
        raw = text.encode()
        with patch.object(r.engine.shapes,'ASM_HASH',r.digest(raw)):
            self.assertEqual(set(r.assembly(raw)),set(s.NAMES))
            with self.assertRaises(ValueError): r.assembly(raw+b' ')
        for bad in (text+'\n'+s.BEGIN+':\n.seh_endproc\n',text.replace(s.DECODE+':','bad:')):
            raw = bad.encode()
            with patch.object(r.engine.shapes,'ASM_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.assembly(raw)

    def linked_table(self,name,address=10000,start=2000):
        source = bytes.fromhex(s.TABLES[name][0])
        targets = [int.from_bytes(source[i:i+4],'little')-i%28-4 for i in range(0,len(source),4)]
        raw = b''.join((start+v-address-(i//7)*28).to_bytes(4,'little',signed=True) for i,v in enumerate(targets))
        return raw,tuple(targets)

    def test_all_subtable_destinations(self):
        for name in s.TABLES:
            raw,expected = self.linked_table(name)
            self.assertEqual(r.table_targets(name,raw,10000,2000),expected)
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.table_targets(name,bad,10000,2000)
            for bad in (raw[:-4],raw+bytes(4)):
                with self.assertRaises(ValueError): r.table_targets(name,bad,10000,2000)
            with self.assertRaises(ValueError): r.table_targets(name,raw,10004,2000)

    def test_table_object_relocations_and_readonly_mapping(self):
        for name,(h,operands) in s.TABLES.items():
            section = dict(code=bytes.fromhex(h),flags=0x40000000)
            symbols = {1:dict(value=0,section=1),2:dict(value=0,section=2,name='.text')}
            refs = [dict(symbol='.rdata',offset=at,addend=add,trailing=0,symbol_index=1) for at,add in operands]
            relocs = {i:dict(symbol=2,kind=4) for i in range(0,len(section['code']),4)}
            raw,_ = self.linked_table(name)
            linked = [dict(code=raw,rva=10000,virtual_size=len(raw),flags=0x40000000)]
            rec = dict(rva=2000,reference_targets={'.rdata':10000})
            with patch.object(r.obj,'select',return_value=([section],symbols,dict(section=2),b'',refs)),\
                 patch.object(r.obj,'relocations',return_value=relocs),\
                 patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])):
                r.table(b'',b'',name,rec)
                for at in relocs:
                    bad = copy.deepcopy(relocs);del bad[at]
                    with patch.object(r.obj,'relocations',return_value=bad):
                        with self.assertRaises(ValueError): r.table(b'',b'',name,rec)
                section['flags'] = 0xc0000000
                with self.assertRaises(ValueError): r.table(b'',b'',name,rec)
                section['flags'] = 0x40000000;symbols[2]['section'] = 3
                with self.assertRaises(ValueError): r.table(b'',b'',name,rec)

    def fixture(self):
        pins = {n:dict(bytes=20) for n in s.NAMES}
        records = {n:dict(rva=100+i*100,size=20,image_sha256='same',reference_targets={}) for i,n in enumerate(s.NAMES)}
        targets = {s.PREDICATE:records[s.PREDICATE]['rva'],r.state.NEW:1001,r.state.FINISH:1002,
                   r.engine.shapes.UPDATE:1003,r.life.GUARD:1004}
        for name,edge in ((s.BEGIN,r.state.NEW),(s.UPDATE,r.engine.shapes.UPDATE),
                          (s.FINISH,r.state.FINISH),(s.REHASH,r.state.NEW),(s.REHASH,r.state.FINISH),
                          (s.FINISH,s.PREDICATE),(s.FINISH_DROP,r.life.GUARD),(s.REHASH_DROP,r.life.GUARD)):
            records[name]['reference_targets'][edge] = targets[edge]
        tables = {n:dict(rva=3000+i*100) for i,n in enumerate(s.TABLES)}
        for n,t in tables.items(): records[n]['reference_targets']['.rdata'] = t['rva']
        receiver = dict(image_sha256='same',reference_targets={n:records[n]['rva'] for n in
                         (s.BEGIN,s.FINISH,s.REHASH,s.UPDATE,s.DECODE)})
        return records,receiver,targets,tables,pins

    def test_receiver_owner_state_and_cleanup_edges(self):
        args = self.fixture();r.reconcile(*args)
        for name,record in args[0].items():
            for change in ('image','size','extra'):
                bad = copy.deepcopy(args)
                if change=='image': bad[0][name]['image_sha256'] = 'other'
                elif change=='size': bad[0][name]['size'] = 21
                else: bad[0][name]['reference_targets']['unknown'] = 2000
                with self.assertRaises(ValueError): r.reconcile(*bad)
            for edge in record['reference_targets']:
                bad = copy.deepcopy(args);bad[0][name]['reference_targets'][edge] += 1
                with self.assertRaises(ValueError): r.reconcile(*bad)
        for name in args[1]['reference_targets']:
            bad = copy.deepcopy(args);del bad[1]['reference_targets'][name]
            with self.assertRaises(ValueError): r.reconcile(*bad)

    def test_frame_geometry_and_no_unwind_overclaim(self):
        value = r.geometry(r.life.Window(0,65536))
        self.assertEqual(list(value['rsp_from_high'].values()),[-5552,-3648,-5696,-3568,-1520])
        self.assertTrue(value['outer_window_cleanup_required'])
        self.assertFalse(value['individual_copied_enums_erased'])
        self.assertFalse(value['arbitrary_handler_invocation_qualified'])
        self.assertFalse(value['maximum_whole_image_depth_qualified'])
        self.assertEqual(value,r.geometry(r.life.Window(4096,69632)))


if __name__=='__main__': unittest.main()
