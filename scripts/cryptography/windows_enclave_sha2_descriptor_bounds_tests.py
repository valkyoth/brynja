"""Typed destination construction and width-origin regressions."""
from unittest.mock import patch
import windows_enclave_sha2_descriptor_bounds as d


class DescriptorBoundsTests:
    def test_descriptor_shift_and_mask_widths_and_carry(self):
        from windows_enclave_sha2_simd_indices_tests import run
        r=run(['movq $-1, %rax','shrq $56, %rax','andl $1, %eax'])
        self.assertEqual(r['registers']['rax'],1)
        r=run(['movq $2, %rax','shrq $1, %rax','ja done','callq unexpected'])
        self.assertEqual(r['registers']['rax'],1)
        r=run(['movq $3, %rax','shrq $1, %rax','jbe done','callq unexpected'])
        self.assertEqual(r['registers']['rax'],1)
        for line in ('shrq $0, %rax','shrq $64, %rax','andl $1, %rax'):
            with self.assertRaises(ValueError):run(['movq $1, %rax',line])


class DescriptorBoundsSavedTests:
    def reject_origin_mutant(self,bodies,lane):
        # Exercise the origin model itself, not rejection by earlier literal
        # staging checks. A separate test keeps those checks mandatory.
        with patch.object(d.digest,'staging'), patch.object(d.digest,'wide_widths'):
            with self.assertRaises(ValueError):d.inspect(bodies,lane)

    def test_descriptor_construction_rejects_every_store_offset_and_width_change(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            name=d.s.one(bodies,r'Resident6digest$');body='\n'.join(d.s.lines(bodies[name]))
            offset=864 if lane=='simd256' else 352;capacity=8 if lane=='simd256' else 4
            for i in range(2*capacity):
                old=f', {offset+8*i}(%rbx)';self.assertIn(old,body)
                for shift in (-1,1,8):
                    bad=body.replace(old,f', {offset+8*i+shift}(%rbx)')
                    self.reject_origin_mutant(bodies|{name:bad},lane)
                    count+=1
            if lane=='simd256':
                for old,new in (('leaq 28(,%rax,4), %rax','leaq 29(,%rax,4), %rax'),
                                ('shrq $48, %rax','shrq $40, %rax'),
                                ('andl $1, %eax','andl $0, %eax')):
                    self.assertIn(old,body)
                    self.reject_origin_mutant(bodies|{name:body.replace(old,new)},lane)
                    count+=1
            else:
                old='movq %rax, 360(%rbx)'
                for new in ('movq %rcx, 360(%rbx)',old+'\naddq %rax, %rcx'):
                    self.reject_origin_mutant(bodies|{name:body.replace(old,new)},lane)
                    count+=1
        self.assertEqual(count,77)
        print('SIMD descriptor origin/offset/width mutations rejected: '+str(count))

    def test_descriptor_origin_review_is_required_and_rechecks_input_contracts(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane,pin,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            with patch.object(d.digest,'staging',side_effect=ValueError('staging failed')):
                with self.assertRaisesRegex(ValueError,'staging failed'):d.inspect(bodies,lane)
            if lane=='simd512':
                with patch.object(d.digest,'wide_widths',side_effect=ValueError('width admission failed')):
                    with self.assertRaisesRegex(ValueError,'width admission failed'):d.inspect(bodies,lane)
            with patch.object(d,'inspect',side_effect=ValueError('origin failed')) as check:
                with self.assertRaisesRegex(ValueError,'origin failed'):
                    chains.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
            values=[0]*8 if lane=='simd256' else [64]*4
            for bad in (-1,True,2 if lane=='simd256' else 65):
                with self.assertRaises(ValueError):d.evaluate(bodies,lane,[bad]+values[1:])
