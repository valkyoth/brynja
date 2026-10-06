"""Direct frame-cell overlap and alias regressions, not indirect-effect proof."""
from unittest.mock import patch
import windows_enclave_sha2_frame_cell as f


class FrameCellTests:
    def test_frame_byte_ranges_include_alignment_aliases_and_overlapping_writes(self):
        bases={'rbx':(0,0),'rsp':(0,0),'rbp':(128,159)}
        self.assertEqual(f.frame_span('56(%rbp)',bases,8),(184,223))
        self.assertEqual(f.frame_span('184(%rsp)',bases,8),(184,192))
        self.assertFalse(f.overlaps((176,184),(184,192)))
        self.assertTrue(f.overlaps((177,185),(184,192)))
        with self.assertRaises(ValueError):f.frame_span('(%rbx,%rax)',bases,8)
        init='movq %rax, 184(%rbx)'
        good=[init,'movq %rax, 192(%rbx)','.B1:','movq $0, 184(%rbx)']
        f.inspect_region(good,bases,(184,192),init,'.B1')
        for bad in ('movb $0, 184(%rbx)','movq $0, 180(%rbx)',
                    'vmovaps %xmm0, 176(%rbx)','movq $0, 56(%rbp)',
                    'movq $0, 184(%rsp)','leaq 184(%rbx), %rcx',
                    'movq %rbx, %rcx','movq %rax, %rbx','movl %eax, %ebx',
                    'movb $0, %bpl','stosq'):
            with self.assertRaises(ValueError):f.inspect_region(good[:1]+[bad]+good[1:],bases,(184,192),init,'.B1')


class FrameCellSavedTests:
    def test_first_output_pointer_rejects_partial_alias_overwrites_and_address_exposure(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            report=f.inspect(bodies,lane);name=report['function'];lines=f.s.lines(bodies[name])
            base='rbx' if lane=='simd256' else 'rbp';slot=report['cell'][0]
            init=f'movq %rax, {slot}(%{base})'
            at=lines.index(init,lines.index(report['begin']+':'))+1
            variants=[f'movb $0, {slot+i}(%{base})' for i in range(8)]
            variants += [f'movq $0, {slot-i}(%{base})' for i in range(1,8)]
            variants += [f'vmovups %ymm0, {slot-16}(%{base})',f'leaq {slot}(%{base}), %rcx',
                         f'movq %{base}, %rcx',f'movq %rax, %{base}']
            variants += [f'movq $0, {slot if lane=="simd256" else slot+128}(%rsp)']
            variants += ['movq $0, 56(%rbp)'] if lane=='simd256' else []
            for code in variants:
                changed=lines[:at]+[code]+lines[at:]
                with patch.object(f.finish,'inspect'),patch.object(f.commit,'narrow'),patch.object(f.commit,'wide'):
                    with self.assertRaises(ValueError):f.inspect(bodies|{name:'\n'.join(changed)},lane)
                count+=1
        self.assertEqual(count,41)
        print('SIMD saved output-pointer overlap/base/exposure mutations rejected: '+str(count))

    def test_cell_review_keeps_indirect_effects_pending_and_is_required(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,pin,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            result=f.inspect(bodies,lane)
            self.assertFalse(result['all_indirect_effects_and_frame_lifetimes_qualified'])
            self.assertTrue(result['non_frame_stores_pending'])
            self.assertTrue(result['calls_pending_indirect_effect_composition'])
            with patch.object(f,'inspect',side_effect=ValueError('cell review failed')) as check:
                with self.assertRaisesRegex(ValueError,'cell review failed'):c.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
