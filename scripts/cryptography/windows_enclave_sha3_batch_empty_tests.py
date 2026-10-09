"""Empty constructor regression paths bound to actual scalar COFF/LLVM/assembly."""
import copy
import struct
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.empty


class EmptyTests:
    def empty_fixture(self):
        data,_,asm,ir,_,bodies=self.routes['scalar']
        construction=c.start.inspect(*self.start_fixture('scalar'))
        return data,bodies,asm,ir,construction

    def test_empty_all_reachable_helper_instructions_are_required(self):
        _,bodies,_,ir,_=self.empty_fixture();count=0
        for bits,name in t.NAMES.items():
            result=t.check_helper(bodies,ir,bits);lines=c.lifecycle.code(bodies[name])
            positions=[*range(len(t.PREFIX)),*range(len(lines)-len(t.RETURN),len(lines))]
            self.assertEqual(len(positions),result['reachable_instruction_positions'])
            for at in positions:
                for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                    with self.assertRaises(ValueError):
                        t.check_helper(bodies|{name:name+':\n'+'\n'.join(bad)},ir,bits)
                    count+=1
        self.assertEqual(count,172)
        print('SHA-3 empty constructor: 172 reachable instruction mutants rejected')

    def test_empty_caller_slices_and_all_secondary_table_targets_required(self):
        _,bodies,asm,_,_=self.empty_fixture();name,result=t.check_caller(bodies,asm)
        lines=c.lifecycle.code(bodies[name]);positions=set()
        for entry in result.values():positions.update(entry['caller_instruction_positions'])
        self.assertEqual(len(positions),22)
        for at in positions:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_caller(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
        for label in t.DISPATCH:
            old=f'.long\t.LBB46_{label}-.LJTI46_1';self.assertIn(old,asm)
            with self.assertRaises(ValueError):
                t.check_caller(bodies,asm.replace(old,'.long\t.LBB46_26-.LJTI46_1'))
        with self.assertRaises(ValueError):t.check_caller(bodies,asm.replace('.LJTI46_1:', '.MISSING:'))

    def test_empty_descriptor_dominance_rejects_bypass_and_fallthrough(self):
        _,bodies,asm,_,_=self.empty_fixture();name,_=t.check_caller(bodies,asm)
        lines=c.lifecycle.code(bodies[name])
        for label in (33,40):
            # Remove the predecessor's terminal jump, creating unreviewed fallthrough.
            at=lines.index(f'.B{label}:')-1
            self.assertTrue(lines[at].startswith('jmp'))
            bad=lines[:at]+['nop']+lines[at+1:]
            with self.assertRaises(ValueError):t.check_caller(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
            # A new entry from a different constructor may skip the empty descriptor.
            at=lines.index('movaps %xmm0, 1008(%rsp)')
            for transfer in (f'jmp .B{label}',f'jne .B{label}','jmpq *%r10'):
                bad=lines[:at]+[transfer]+lines[at+1:]
                with self.assertRaises(ValueError):t.check_caller(bodies|{name:name+':\n'+'\n'.join(bad)},asm)

    def test_empty_actual_coff_references_reject_interior_and_extra_callers(self):
        data,bodies,_,_,_=self.empty_fixture();caller=c.lifecycle.s.one(bodies,'Owner5start$')
        self.assertEqual(len(t.incoming(data,caller)),2)
        rows,syms=t.object_review.obj.tables(data)
        targets={v['section'] for v in syms.values() if v['name'] in t.NAMES.values()}
        symbol_index=next(k for k,v in syms.items() if v['name']==t.NAMES[128])
        count=0;extra=None
        for row in rows:
            for index,(offset,ref) in enumerate(t.object_review.obj.relocations(data,row,syms).items()):
                if syms[ref['symbol']]['section'] in targets:
                    for field,fmt,value in ((row['raw']+offset,'<I',1),
                                            (row['relocs']+index*10+8,'<H',1)):
                        bad=bytearray(data);struct.pack_into(fmt,bad,field,value)
                        with self.assertRaises(ValueError):t.incoming(bytes(bad),caller)
                        count+=1
                elif extra is None:extra=row['relocs']+index*10+4
        self.assertEqual(count,12)
        self.assertIsNotNone(extra)
        bad=bytearray(data);struct.pack_into('<I',bad,extra,symbol_index)
        with self.assertRaises(ValueError):t.incoming(bytes(bad),caller)

    def test_empty_abis_admission_and_incomplete_scope(self):
        data,bodies,asm,ir,construction=self.empty_fixture()
        result=t.inspect(data,bodies,asm,ir,construction)
        self.assertTrue(result['empty_constructor_paths_qualified'])
        for key in ('inlined_cshake_constructors_qualified','retained_state_lifetime_composition_qualified',
                    'private_frame_erasure_qualified'):
            self.assertFalse(result[key])
        for bits,name in t.NAMES.items():
            declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('internal ','noalias ','readonly ','nonnull ','nofree ',
                          'dereferenceable(1041)','dereferenceable(32)','captures(none)'):
                self.assertIn(token,declaration)
                with self.assertRaises(ValueError):
                    t.check_helper(bodies,ir.replace(declaration,declaration.replace(token,'')),bits)
        for key in ('function','non_cshake_requires_zero_name_and_customization_lengths',
                    'slot_equality_before_indexed_plan_read'):
            with self.assertRaises(ValueError):t.inspect(data,bodies,asm,ir,construction|{key:False})
        with patch.object(c.empty,'inspect',side_effect=ValueError('empty constructor failed')) as check:
            with self.assertRaisesRegex(ValueError,'empty constructor failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
