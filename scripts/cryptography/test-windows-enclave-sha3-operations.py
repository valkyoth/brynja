"""Owner-review regressions independent of the saved private artifact directory."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha3_operations as r


def linked_table(pin,address,start):
    source = bytes.fromhex(pin['object_hex']);out = bytearray();base = 0
    for size in pin['subtable_bytes']:
        for at in range(base,base+size,4):
            destination = base+int.from_bytes(source[at:at+4],'little')-at-4
            out.extend((start+destination-address-base).to_bytes(4,'little',signed=True))
        base += size
    return bytes(out)


class Tests(unittest.TestCase):
    def setUp(self):
        self.spec = r.specification(r.SPEC.read_bytes())

    def test_spec_identity_and_population(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for key in ('functions','tables'):
            bad = copy.deepcopy(self.spec);bad[key].pop(next(iter(bad[key])))
            raw = r.shared.encoded(bad)
            with patch.object(r,'SPEC_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.specification(raw)

    def test_body_and_reference_identity(self):
        code = b'\x90\xc3';refs = [dict(offset=0,symbol='callee')]
        pin = dict(bytes=2,sha256=r.digest(code),references_sha256=r.digest(r.shared.encoded(refs)))
        r.body_check(code,refs,pin)
        for bad in (code[:-1],code+b'\0',b'\x91\xc3'):
            with self.assertRaises(ValueError): r.body_check(bad,refs,pin)
        for bad in ([],refs*2,[dict(offset=1,symbol='callee')],[dict(offset=0,symbol='other')]):
            with self.assertRaises(ValueError): r.body_check(code,bad,pin)

    def test_semantic_sequences_without_body_hashes(self):
        for role,sequences in r.s.SEQUENCES.items():
            body = '\n'.join(v.replace('|','\n') for v in sequences)
            if role not in ('receive','export'):
                body += '\ntestq %rdx, %rdx\nmovq %rdx, 2160(%rsi)'
            if role!='receive': body += '\ncallq '+r.s.DROP+'\ncallq '+r.s.ZERO
            r.semantic_sequences(role,body)
            for sequence in sequences:
                bad = body.replace(sequence.replace('|','\n'),'int3')
                with self.subTest(role=role,sequence=sequence):
                    with self.assertRaises(ValueError): r.semantic_sequences(role,bad)
            if role!='receive':
                for name in (r.s.DROP,r.s.ZERO):
                    with self.assertRaises(ValueError):
                        r.semantic_sequences(role,body.replace('callq '+name,'callq other'))

    def test_private_ir_preconditions(self):
        pins = self.spec['functions']
        lines = [f'define void @{pins[k]["name"]}(i64 noundef range(i64 1, 0) %sequence, i8 noundef range(i8 0, 9) %last)'
                 for k in ('export','finish','setup_chunk','squeeze')]
        text = '\n'.join(lines)
        with patch.object(r.s,'IR_HASH',r.digest(text.encode())):
            value = r.preconditions(text.encode(),pins)
            self.assertFalse(value['standalone_unbounded_private_calls_claimed'])
        for bad in (text.replace('range(i8 0, 9)','range(i8 0, 10)'),
                    text.replace('range(i64 1, 0)','range(i64 0, 0)'),text+'\n'+lines[0]):
            with patch.object(r.s,'IR_HASH',r.digest(bad.encode())):
                with self.assertRaises(ValueError): r.preconditions(bad.encode(),pins)

    def test_all_subtable_destinations(self):
        for pin in self.spec['tables'].values():
            raw = linked_table(pin,10000,2000)
            r.table_destinations(raw,10000,2000,pin)
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.table_destinations(bad,10000,2000,pin)
            for bad in (raw[:-4],raw+b'\0'*4):
                with self.assertRaises(ValueError): r.table_destinations(bad,10000,2000,pin)
            with self.assertRaises(ValueError): r.table_destinations(raw,10004,2000,pin)
        pin = copy.deepcopy(self.spec['tables']['receive']);pin['subtable_bytes'] = [76]
        raw = linked_table(self.spec['tables']['receive'],10000,2000)
        actual = r.table_destinations(raw,10000,2000,self.spec['tables']['receive'])
        self.assertEqual(actual,[323,354,354,323,347,354,354,323,781,809,673,702,644,830,860,733,546,546,845])
        self.assertNotEqual(actual,r.table_destinations(raw,10000,2000,pin))

    def test_readonly_tables_and_relocation_closure(self):
        for role,pin in self.spec['tables'].items():
            raw = linked_table(pin,10000,2000)
            section = dict(code=bytes.fromhex(pin['object_hex']),flags=0x40000000)
            symbols = {1:dict(value=0,section=1),2:dict(value=0,section=2,name='.text')}
            refs = [dict(symbol='.rdata',offset=a,addend=b,trailing=0,symbol_index=1) for a,b in pin['operands']]
            relocs = {at:dict(symbol=2,kind=4) for at in range(0,len(raw),4)}
            record = dict(entry='entry',rva=2000,reference_targets={'.rdata':10000})
            linked = [dict(code=raw,rva=10000,virtual_size=len(raw),flags=0x40000000)]
            with patch.object(r.obj,'select',return_value=([section],symbols,dict(section=2),b'',refs)),\
                 patch.object(r.obj,'relocations',return_value=relocs),\
                 patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])):
                r.table(b'',b'',record,pin)
                for at in relocs:
                    bad = dict(relocs);del bad[at]
                    with patch.object(r.obj,'relocations',return_value=bad):
                        with self.assertRaises(ValueError): r.table(b'',b'',record,pin)
                for flags in (0xc0000000,0x60000000):
                    linked[0]['flags'] = flags
                    with self.assertRaises(ValueError): r.table(b'',b'',record,pin)
                linked[0]['flags'] = 0x40000000;symbols[2]['section'] = 3
                with self.assertRaises(ValueError): r.table(b'',b'',record,pin)

    def test_width_constants(self):
        names = ['switch.table.rehash','switch.table.rehash.123']
        raw = b''.join(n.to_bytes(8,'little') for n in (28,32,48,64))
        rows = [dict(code=raw,flags=0x40000000,nrelocs=0) for _ in names]
        symbols = {i:dict(name=n,value=0,section=i+1) for i,n in enumerate(names)}
        record = dict(entry='rehash',reference_targets={n:10000+32*i for i,n in enumerate(names)})
        with patch.object(r.obj,'tables',return_value=(rows,symbols)),patch.object(r,'readonly',return_value=raw):
            r.widths(b'',b'',record)
            for row in rows:
                for at in range(32):
                    bad = bytearray(raw);bad[at] ^= 1;row['code'] = bytes(bad)
                    with self.assertRaises(ValueError): r.widths(b'',b'',record)
                row['code'] = raw
            with patch.object(r,'readonly',return_value=raw[:-1]+b'\1'):
                with self.assertRaises(ValueError): r.widths(b'',b'',record)

    def test_frame_identity(self):
        pins = self.spec['functions']
        records = {k:dict(unwind=[dict(stack_bytes=p['stack_bytes'],saved_registers=p['saved_registers'],chain=None,frame=0)])
                   for k,p in pins.items()}
        r.frames(records,pins)
        for k in records:
            for field,value in (('stack_bytes',0),('saved_registers',['xmm15']),('chain',1),('frame',1)):
                bad = copy.deepcopy(records);bad[k]['unwind'][0][field] = value
                with self.assertRaises(ValueError): r.frames(bad,pins)
            bad = copy.deepcopy(records);bad[k]['unwind'] *= 2
            with self.assertRaises(ValueError): r.frames(bad,pins)

    def test_geometry_and_limits(self):
        pins = self.spec['functions'];g = r.geometry(r.life.bounded.Window(0,65536),pins)
        self.assertEqual(g['paths']['setup']['rsp_from_high'],-7600)
        self.assertEqual(g['paths']['finish_setup']['rsp_from_high'],-7024)
        self.assertFalse(g['copied_states_individually_erased'])
        self.assertTrue(g['outer_window_clearing_required'])
        self.assertFalse(g['maximum_whole_image_depth_qualified'])
        self.assertEqual(g,r.geometry(r.life.bounded.Window(4096,69632),pins))
        with self.assertRaises(ValueError): r.geometry(r.life.bounded.Window(0,4096),pins)

    def test_exact_incoming_and_outgoing_connections(self):
        pins = self.spec['functions']
        records = {k:dict(rva=100+20*i,reference_targets={'cleanup':1000}) for i,k in enumerate(pins)}
        targets = {'cleanup':1000} | {p['name']:records[k]['rva'] for k,p in pins.items()}
        records['receive']['reference_targets'].update({p['name']:records[k]['rva'] for k,p in pins.items() if k!='receive'})
        tables = {k:dict(rva=2000+40*i) for i,k in enumerate(self.spec['tables'])}
        for k in tables: records[k]['reference_targets']['.rdata'] = tables[k]['rva']
        runtime = {n:3000+20*i for i,n in enumerate(sorted(r.s.RUNTIME_BOUNDARIES))}
        records['setup']['reference_targets'].update(runtime)
        r.connections(records,pins,targets,tables,runtime)
        for k,record in records.items():
            for edge in record['reference_targets']:
                bad = copy.deepcopy(records);bad[k]['reference_targets'][edge] += 1
                with self.assertRaises(ValueError): r.connections(bad,pins,targets,tables,runtime)
        for role,pin in pins.items():
            if role=='receive': continue
            bad = copy.deepcopy(records);del bad['receive']['reference_targets'][pin['name']]
            with self.assertRaises(ValueError): r.connections(bad,pins,targets,tables,runtime)
        with self.assertRaises(ValueError): r.connections(records,pins,targets,tables,{})


if __name__=='__main__': unittest.main()
