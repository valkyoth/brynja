"""Focused regressions for the saved SHA-NI normal-path author review."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha_ni_engine as r

s = r.shapes


class Tests(unittest.TestCase):
    def test_review_identity_and_population(self):
        raw = r.SPEC.read_bytes();self.assertEqual(set(r.specification(raw)),set(s.NAMES))
        with self.assertRaises(ValueError): r.specification(raw+b' ')
        import json
        bad = json.loads(raw);del bad['functions'][s.KAT];raw = json.dumps(bad).encode()
        with patch.object(r,'SPEC_HASH',r.digest(raw)):
            with self.assertRaises(ValueError): r.specification(raw)

    def test_body_and_every_reference_field_are_bound(self):
        code = b'123456';refs = [dict(offset=1,symbol='target',trailing=0,addend=0)]
        pins = {s.UPDATE:dict(bytes=6,sha256=r.digest(code),references=refs)}
        r.body_check(s.UPDATE,code,refs,pins)
        for at in range(len(code)):
            bad = bytearray(code);bad[at] ^= 1
            with self.assertRaises(ValueError): r.body_check(s.UPDATE,bad,refs,pins)
        for key,val in (('offset',2),('symbol','other'),('trailing',1),('addend',1)):
            with self.assertRaises(ValueError): r.body_check(s.UPDATE,code,[refs[0] | {key:val}],pins)
        for bad in ([],refs*2):
            with self.assertRaises(ValueError): r.body_check(s.UPDATE,code,bad,pins)

    def test_instruction_landmarks_independent_of_body_hashes(self):
        count = 0
        for name,sequences in s.SEQUENCES.items():
            code = b'\xcc'*8
            # Spacers make a synthetic layout; these checks do not use body pins.
            positions = []
            for h in sequences:
                raw = bytes.fromhex(h);positions.append((len(code),len(raw)));code += raw+b'\xcc'*8
            r.instructions(name,code)
            for start,size in positions:
                for at in range(start,start+size):
                    bad = bytearray(code);bad[at] ^= 1
                    with self.assertRaises(ValueError): r.instructions(name,bad)
                    count += 1
            with self.assertRaises(ValueError): r.instructions(name,code+bytes.fromhex(sequences[0]))
        self.assertGreater(count,800)

    def test_dispatch_destinations_not_just_table_size(self):
        start,address = 1000,8000
        raw = b''.join((start+v-address).to_bytes(4,'little',signed=True) for v in s.DESTINATIONS)
        self.assertEqual(r.dispatch_targets(raw,address,start),s.DESTINATIONS)
        for at in range(20):
            bad = bytearray(raw);bad[at] ^= 1
            with self.assertRaises(ValueError): r.dispatch_targets(bad,address,start)
        for bad in (raw[:-4],raw+bytes(4)):
            with self.assertRaises(ValueError): r.dispatch_targets(bad,address,start)
        with self.assertRaises(ValueError): r.dispatch_targets(raw,address+4,start)

    def fixture(self):
        records = {}
        for i,name in enumerate(s.NAMES):
            records[name] = dict(rva=100+i*100,image_sha256='same',reference_targets={})
            if name in s.FRAMES:
                saved = [dict(register_class='xmm',register=6,offset=48)] if name == s.UPDATE else []
                records[name]['unwind'] = [dict(stack_bytes=s.FRAMES[name],saved_registers=saved,chain=None)]
        records[s.KAT]['reference_targets'][s.SESSION] = records[s.SESSION]['rva']
        records[s.SESSION]['reference_targets'][s.KERNEL] = records[s.KERNEL]['rva']
        records[s.FINISH]['reference_targets']['memcpy'] = 5000
        pins = {n:dict(references=[dict(symbol=v) for v in r['reference_targets']]) for n,r in records.items()}
        anchors = {n:dict(image_sha256='same',reference_targets={c:records[c]['rva']}) for n,c in
                   ((r.state.NEW,s.KAT),(r.state.FINISH,s.FINISH))}
        return records,anchors,{'memcpy':5000},'same',pins

    def test_readonly_constant_identity_in_object_and_image(self):
        names = ['__ymm@'+format(i,'064x') for i in range(1,7)]+[s.TABLE]
        raw = [i.to_bytes(32,'little') for i in range(1,7)]+[bytes(256)]
        rows = [dict(code=b,flags=0x40000000,nrelocs=0) for b in raw]
        symbols = {i:dict(name=n,value=0,section=i+1) for i,n in enumerate(names)}
        linked = [dict(code=b,rva=1000+i*512,virtual_size=len(b),flags=0x40000000) for i,b in enumerate(raw)]
        records = {s.KAT:dict(reference_targets={n:1000+i*512 for i,n in enumerate(names[:-1])}),
                   s.KERNEL:dict(reference_targets={s.TABLE:4072})}
        with patch.object(r.obj,'tables',return_value=(rows,symbols)),\
             patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])),\
             patch.object(s,'TABLE_HASH',r.digest(raw[-1])):
            self.assertEqual(len(r.constants(b'',b'',records)),7)
            for i in range(7):
                for key,value in (('flags',0xc0000000),('nrelocs',1),('code',b'invalid')):
                    bad = copy.deepcopy(rows);bad[i][key] = value
                    with patch.object(r.obj,'tables',return_value=(bad,symbols)):
                        with self.assertRaises(ValueError): r.constants(b'',b'',records)
                for at in range(len(raw[i])):
                    bad = copy.deepcopy(linked);changed = bytearray(raw[i]);changed[at] ^= 1;bad[i]['code'] = bytes(changed)
                    with patch.object(r.shared.caller.pe,'linked',return_value=(bad,[])):
                        with self.assertRaises(ValueError): r.constants(b'',b'',records)

    def test_object_dispatch_relocations_are_session_local(self):
        section = dict(code=s.DISPATCH,flags=0x40000000)
        symbols = {1:dict(value=0,section=1),2:dict(value=0,section=2,name='.text')}
        refs = [dict(symbol='.rdata',offset=117,addend=0,trailing=0,symbol_index=1)]
        rows = [section];selected = dict(section=2)
        relocations = {i:dict(symbol=2,kind=4) for i in range(0,20,4)}
        start,address = 1000,8000
        raw = b''.join((start+v-address).to_bytes(4,'little',signed=True) for v in s.DESTINATIONS)
        linked = [dict(code=raw,rva=address,virtual_size=20,flags=0x40000000)]
        rec = dict(rva=start,reference_targets={'.rdata':address})
        with patch.object(r.obj,'select',return_value=(rows,symbols,selected,b'',refs)),\
             patch.object(r.obj,'relocations',return_value=relocations),\
             patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])):
            r.dispatch(b'',b'',rec)
            for at in relocations:
                for change in ('kind','missing'):
                    bad = copy.deepcopy(relocations)
                    if change == 'kind': bad[at]['kind'] = 3
                    else: del bad[at]
                    with patch.object(r.obj,'relocations',return_value=bad):
                        with self.assertRaises(ValueError): r.dispatch(b'',b'',rec)
            symbols[2]['section'] = 3
            with self.assertRaises(ValueError): r.dispatch(b'',b'',rec)

    def test_exact_edges_and_frame_saves(self):
        args = self.fixture();r.reconcile(*args)
        for n,rec in args[0].items():
            bad = copy.deepcopy(args);bad[0][n]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.reconcile(*bad)
            for edge in rec['reference_targets']:
                for value in (0,rec['reference_targets'][edge]+1):
                    bad = copy.deepcopy(args);bad[0][n]['reference_targets'][edge] = value
                    with self.assertRaises(ValueError): r.reconcile(*bad)
            if n in s.FRAMES:
                for change in ({'stack_bytes':0},{'chain':{}},{'saved_registers':[dict(register_class='xmm',register=7,offset=48)]}):
                    bad = copy.deepcopy(args);bad[0][n]['unwind'][0].update(change)
                    with self.assertRaises(ValueError): r.reconcile(*bad)
        for n in args[1]:
            bad = copy.deepcopy(args);bad[1][n]['reference_targets'] = {}
            with self.assertRaises(ValueError): r.reconcile(*bad)

    def test_unknown_targets_cannot_be_dropped_or_added_silently(self):
        args = self.fixture()
        for change in ('missing','extra','unbound'):
            bad = copy.deepcopy(args)
            if change == 'missing': bad[0][s.FINISH]['reference_targets'] = {}
            elif change == 'extra': bad[0][s.FINISH]['reference_targets']['new'] = 9000
            else: bad[2].clear()
            with self.assertRaises(ValueError): r.reconcile(*bad)

    def compiler_fixture(self):
        asm = (s.KERNEL+':\n# BRYNJA_SECRET_BEGIN\n xorl %eax, %eax\n'
               '# BRYNJA_REGISTER_ERASE\n# BRYNJA_SECRET_END\n.seh_endproc\n').encode()
        params = {s.FINISH:'dereferenceable(1984) range(i64 28, 33)',
                  s.UPDATE:'dereferenceable(1984) range(i64 0, -9223372036854775808)',
                  s.PADDING:'dereferenceable(1984) range(i64 64, 129)',
                  s.KAT:'dereferenceable(720) range(i8 0, 4)',
                  s.SESSION:'dereferenceable(720) dereferenceable(64) dereferenceable(128)'}
        ir = '\n'.join('define internal fastcc void @'+n+'('+v+') {' for n,v in params.items()).encode()
        return asm,ir

    def test_compiler_limits_and_opaque_stack_traffic(self):
        asm,ir = self.compiler_fixture()
        def check(a,b):
            with patch.object(s,'ASM_HASH',r.digest(a)),patch.object(r.state.receiver,'IR_HASH',r.digest(b)):
                return r.compiler(a,b)
        self.assertFalse(check(asm,ir)['caller_registers_or_spills_erased'])
        for instruction in ('movq %rax, 8(%rsp)','pushq %rax','callq target','movq (%rbp), %rax'):
            bad = asm.replace(b' xorl %eax, %eax',instruction.encode())
            with self.assertRaises(ValueError): check(bad,ir)
        for bad in (ir.replace(b'28, 33',b'0, 65'),ir.replace(b'64, 129',b'0, 129'),ir+ir,
                    ir.replace(b'internal ',b''),ir.replace(b'dereferenceable(720)',b'dereferenceable(719)')):
            with self.assertRaises(ValueError): check(asm,bad)
        with self.assertRaises(ValueError): check(asm.replace(b'# BRYNJA_REGISTER_ERASE',b''),ir)

    def test_selected_stack_geometry_and_residuals(self):
        value = r.geometry(r.life.Window(0,65536))
        self.assertEqual(value['rsp_from_high'],dict(kat=-13808,kat_kernel=-13912,
                         kat_scratch_clear=-13928,finish_update_scratch_clear=-8216))
        self.assertFalse(value['maximum_transitive_depth_qualified'])
        self.assertFalse(value['individual_length_spills_erased'])
        self.assertFalse(value['caller_saved_xmm6_erased'])
        self.assertTrue(value['outer_window_cleanup_required'])
        self.assertEqual(value,r.geometry(r.life.Window(4096,4096+65536)))


if __name__ == '__main__': unittest.main()
