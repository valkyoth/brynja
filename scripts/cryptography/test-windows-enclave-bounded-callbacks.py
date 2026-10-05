"""Offline callback binding and metadata regressions, not native enclave tests."""
import copy
import struct
import unittest
from unittest.mock import patch

import windows_enclave_bounded_callbacks as r


class Tests(unittest.TestCase):
    def test_full_body_and_reference_pins(self):
        for name,(size,_,_) in r.SPECS.items():
            code = bytes(size);refs = [dict(offset=2,symbol='active',trailing=0,addend=0)]
            with patch.dict(r.SPECS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.check_body(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.check_body(name,changed,refs)
                for changed in ([],refs*2,[refs[0] | {'addend':8}],[refs[0] | {'symbol':'other'}]):
                    with self.assertRaises(ValueError): r.check_body(name,code,changed)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.check_body(name,changed,refs)

    def test_copy_admission_status_and_counter_paths(self):
        code = bytearray(182);sites = set()
        for offset,text in r.COPY_LANDMARKS:
            raw = bytes.fromhex(text);code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
        for offset,text,target in r.COPY_BRANCHES:
            op = bytes.fromhex(text);width = 4 if len(op) == 2 else 1
            raw = op+(target-offset-len(op)-width).to_bytes(width,'little',signed=True)
            code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
        r.copy_instructions(code)
        for i in sites:
            changed = code.copy();changed[i] ^= 1
            with self.assertRaises(ValueError): r.copy_instructions(changed)

    def test_observers_copy_exact_metadata_words_and_offsets(self):
        for name,count,start,base,symbol in (('PublicInputObserve',7,49,32,'input_report'),
                                             ('PublicRehashObserve',8,53,0,'rehash_report')):
            code = bytearray(start);refs = []
            for i in range(count):
                load = bytes.fromhex('488b01') if not i else bytes.fromhex('488b41')+bytes([i*8])
                refs.append(dict(offset=len(code)+len(load)+3,symbol=symbol,trailing=0,addend=base+8*i))
                code += load+bytes.fromhex('488905')+(base+8*i).to_bytes(4,'little')
            code += bytes.fromhex('b801000000c333c0c3')
            self.assertEqual(r.report_plan(name,code,refs),[dict(source=i*8,destination=base+8*i,bytes=8) for i in range(count)])
            for i in range(start,len(code)):
                changed = code.copy();changed[i] ^= 1
                with self.assertRaises(ValueError): r.report_plan(name,changed,refs)
            for i in range(count):
                for key,value in (('symbol','other'),('addend',-1),('trailing',1),('offset',0)):
                    changed = copy.deepcopy(refs);changed[i][key] = value
                    with self.assertRaises(ValueError): r.report_plan(name,code,changed)
            with self.assertRaises(ValueError): r.report_plan(name,code,refs[:-1])

    def source_fixture(self):
        code = bytes.fromhex('8b050000000085c07411833d00000000007408488b0500000000c333c0c3')
        refs = [dict(offset=o,symbol=s,trailing=t,addend=0) for o,s,t in
                ((2,'active',0),(12,'retained_call',1),(22,'input_source',0))]
        linked = bytearray(code)
        for ref,target in zip(refs,(512,516,520)):
            at = ref['offset'];linked[at:at+4] = (target-100-at-4-ref['trailing']).to_bytes(4,'little',signed=True)
        return code,refs,[dict(code=bytes(linked),rva=100,virtual_size=30,flags=0x60000020)]

    def test_pinned_data_leaf_binding_rejects_shape_mapping_and_unwind_changes(self):
        code,refs,rows = self.source_fixture()
        def run(rows,functions=()):
            with patch.object(r.shared.caller,'function',return_value=(code,refs)),patch.object(r.shared.caller.pe,'linked',return_value=(rows,functions)):
                return r.bind_leaf(b'object',b'image','PublicInputSource')
        result = run(rows)
        self.assertEqual(result['reference_targets'],dict(active=512,retained_call=516,input_source=520))
        for bad in ([],rows*2,[rows[0] | {'flags':0xe0000020}],[rows[0] | {'virtual_size':29}],
                    [rows[0] | {'code':b'\0'+rows[0]['code'][1:]}]):
            with self.assertRaises(ValueError): run(bad)
        with self.assertRaises(ValueError): run(rows,[(100,130,0)])
        with self.assertRaises(ValueError): r.bind_leaf(b'',b'','PublicInputCopy')
        for field,value in (('trailing',0),('symbol','call'),('offset',13),('addend',1)):
            changed = copy.deepcopy(refs);changed[1][field] = value
            with patch.object(r.shared.caller,'function',return_value=(code,changed)):
                with self.assertRaises(ValueError): r.bind_leaf(b'object',b'image','PublicInputSource')

    def callback_fixture(self):
        identities = {name:500+i*128 for i,name in enumerate(r.GLOBALS)}
        identities['EnclaveCopyIntoEnclave'] = 400
        records = {n:dict(rva=200+i*10,image_sha256='same',reference_targets=identities.copy()) for i,n in enumerate(r.SPECS)}
        incoming = {r.sha.owner.borrowed.RECEIVE:('PublicInputCopy',),r.sha.owner.borrowed.HASH:('PublicInputSource','PublicInputObserve'),
                    r.sha.rehash.REHASH:('PublicRehashObserve',)}
        anchors = {n:dict(image_sha256='same',reference_targets={e:records[e]['rva'] for e in es}) for n,es in incoming.items()}
        parent = dict(image_sha256='same',reference_targets=identities.copy())
        return records,anchors,parent

    def test_cross_language_edges_exports_and_nonoverlapping_metadata(self):
        records,anchors,parent = self.callback_fixture()
        rows = [dict(rva=500,virtual_size=4096,flags=0xc0000040)]
        with patch.object(r,'exported',side_effect=lambda _,n:records[n]['rva']),patch.object(r.shared.caller.pe,'linked',return_value=(rows,[])):
            _,spans = r.reconcile(records,anchors,parent,b'image');self.assertEqual(len(spans),9)
            for name in records:
                wrong = copy.deepcopy(records);wrong[name]['image_sha256'] = 'other'
                with self.assertRaises(ValueError): r.reconcile(wrong,anchors,parent,b'image')
                wrong = copy.deepcopy(records);wrong[name]['reference_targets']['active'] += 1
                with self.assertRaises(ValueError): r.reconcile(wrong,anchors,parent,b'image')
            for name,anchor in anchors.items():
                for edge in anchor['reference_targets']:
                    wrong = copy.deepcopy(anchors);del wrong[name]['reference_targets'][edge]
                    with self.assertRaises(ValueError): r.reconcile(records,wrong,parent,b'image')
            with patch.object(r,'exported',return_value=1):
                with self.assertRaises(ValueError): r.reconcile(records,anchors,parent,b'image')
            for flags in (0x40000040,0xe0000040):
                with patch.object(r.shared.caller.pe,'linked',return_value=([rows[0] | {'flags':flags}],[])):
                    with self.assertRaises(ValueError): r.reconcile(records,anchors,parent,b'image')
            overlap = copy.deepcopy(records);p = copy.deepcopy(parent)
            for rec in [p,*overlap.values()]: rec['reference_targets']['input_report'] = rec['reference_targets']['rehash_report']
            with self.assertRaises(ValueError): r.reconcile(overlap,anchors,p,b'image')

    def test_three_copy_fragments_share_one_frame_and_conditional_spill(self):
        root = (100,224,900)
        frames = [dict(start=100,end=224,unwind_rva=900,stack_bytes=40,chain=None,saved_registers=[]),
                  dict(start=224,end=271,stack_bytes=0,chain=root,saved_registers=[dict(register_class='gpr',register=7,offset=48)]),
                  dict(start=271,end=282,stack_bytes=0,chain=root,saved_registers=[])]
        record = dict(rva=100,unwind=frames);r.copy_frames(record)
        for i in range(3):
            for key,value in (('stack_bytes',8),('end',999),('chain',(1,2,3)),('saved_registers',[{}])):
                wrong = copy.deepcopy(record);wrong['unwind'][i][key] = value
                with self.assertRaises(ValueError): r.copy_frames(wrong)
        with self.assertRaises(ValueError): r.copy_frames(dict(rva=100,unwind=frames[:1]))

    def test_geometry_stops_before_kernel_or_unreviewed_runtime_depth(self):
        result = r.geometry(r.dispatch.Window(0,65536))
        self.assertEqual(result['copy_rsp_from_high'],-3408)
        self.assertEqual(result['sdk_copy_rsp_from_high'],-3456)
        for key in ('exported_control_frames_included','maximum_transitive_depth_qualified','kernel_storage_qualified','sdk_self_erasure_claimed'):
            self.assertFalse(result[key])
        self.assertIsNone(result['unknown_callee']['callee_frame_bytes'])
        for low in (4096,0x700000000000): self.assertEqual(r.geometry(r.dispatch.Window(low,low+65536)),result)

    def test_actual_sdk_inbound_flag_syscall_and_tail(self):
        code = bytes.fromhex(r.shared.sdk.status.sdk.BODIES['EnclaveCopyIntoEnclave'][1])
        r.inbound_edges(code)
        for i in range(len(code)):
            changed = bytearray(code);changed[i] ^= 1
            with self.assertRaises(ValueError): r.inbound_edges(changed)
        for changed in (code[:-1],code+bytes(1)):
            with self.assertRaises(ValueError): r.inbound_edges(changed)

    def test_export_parser_rejects_forwarders_duplicates_and_bad_ordinals(self):
        data = bytearray(512)
        struct.pack_into('<IIHHIIIIIII',data,0,0,0,0,0,0,1,1,1,0x2100,0x2120,0x2130)
        struct.pack_into('<I',data,0x100,0x1000);struct.pack_into('<I',data,0x120,0x2140)
        name = b'PublicInputControl\0';data[0x140:0x140+len(name)] = name
        def run(raw,name='PublicInputControl',flags=0x60000020):
            rows = [dict(rva=0x1000,virtual_size=1,code=b'\xc3',flags=flags),
                    dict(rva=0x2000,virtual_size=len(raw),code=bytes(raw),flags=0x40000040)]
            with patch.object(r.shared.caller.pe,'linked',return_value=(rows,[])),patch.object(r.shared.sdk,'directory',return_value=(0x2000,40)):
                return r.exported(b'image',name)
        self.assertEqual(run(data),0x1000)
        for offset,fmt,value in ((20,'I',0),(20,'I',8193),(24,'I',2),(0x100,'I',0x2001),
                                 (0x100,'I',0),(0x100,'I',0x2100),(0x120,'I',0x9000),(0x130,'H',1)):
            changed = data.copy();struct.pack_into('<'+fmt,changed,offset,value)
            with self.assertRaises(ValueError): run(changed)
        with self.assertRaises(ValueError): run(data,'missing')
        with self.assertRaises(ValueError): run(data,flags=0xe0000020)
        duplicate = data.copy();struct.pack_into('<II',duplicate,20,2,2);struct.pack_into('<I',duplicate,0x124,0x2140)
        with self.assertRaises(ValueError): run(duplicate)


if __name__ == '__main__': unittest.main()
