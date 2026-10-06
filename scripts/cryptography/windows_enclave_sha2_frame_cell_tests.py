"""Direct frame-cell overlap and alias regressions, not indirect-effect proof."""
from unittest.mock import patch
import windows_enclave_sha2_frame_cell as f
import windows_enclave_sha2_store_effects as e
from windows_enclave_sha2_call_effects_tests import CallEffectTests, CallEffectSavedTests


class FrameCellTests(CallEffectTests):
    def test_indirect_effect_ranges_do_not_wrap_or_combine_pointer_objects(self):
        integer=e.Value(None,0,63);pointer=e.Value('pad',10,10)
        self.assertEqual(e.add(pointer,integer),e.Value('pad',10,73))
        for left,right in ((pointer,pointer),(e.Value(None,0,(1<<64)-1),e.Value(None,1,1))):
            with self.assertRaises(ValueError):e.add(left,right)
        self.assertEqual(e.address('8(%rbx,%rsi,4)',{'rbx':pointer,'rsi':integer}),e.Value('pad',18,270))
        for code in ('(%eax)','(%rbx,%rsi,16)','(%rax)','(%rbx,%rcx)'):
            with self.assertRaises(ValueError):e.address(code,{'rbx':pointer,'rcx':pointer})

    def test_indirect_effect_copy_forgets_volatile_registers(self):
        for reg in ('rax','rcx','rdx','r8','r9','r10','r11'):
            with self.assertRaises(ValueError):
                e.evaluate(['callq copy',f'movb $0, (%{reg})'],{reg:e.Value('pad',0,0)},{},'copy')
        for reg in ('rbx','rbp','rsi','rdi','r12','r13','r14','r15'):
            result=e.evaluate(['callq copy',f'movb $0, (%{reg})'],{reg:e.Value('pad',0,0)},{},'copy')
            self.assertEqual(result[0]['span'],[0,1])
        for code in ('callq unknown','stosq','movl %ebx, %ecx','andl $63, %ebx'):
            with self.assertRaises(ValueError):e.evaluate([code],{'rbx':e.Value('pad',0,0)},{},'copy')

    def test_indirect_effect_slices_require_unique_ordered_endpoints(self):
        self.assertEqual(e.slice_to(['a','b','c'],'a','c'),['a','b','c'])
        for code in (['a','a','c'],['c','a'],['a']):
            with self.assertRaises(ValueError):e.slice_to(code,'a','c')

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


class FrameCellSavedTests(CallEffectSavedTests):
    def test_seven_indirect_store_footprints_reject_address_mutations(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            report=f.inspect(bodies,lane);lines=f.s.lines(bodies[report['function']])
            lines=lines[lines.index(report['begin']+':'):lines.index(report['end']+':')]
            inventory=report['non_frame_stores_pending'];copy=f.s.one(bodies,r'secret_memory18copy_secret_region$')
            variants=(
                [('andl $63, %edx','andl $127, %edx'),
                 ('andl $63, %edx','andl $31, %edx'),
                 ('leaq 11688(%rbx), %rax','leaq 11687(%rbx), %rax'),
                 ('leaq (%rax,%rsi), %r15','leaq (%rax,%rsi,2), %r15'),
                 ('movq %rdx, %rsi','movq %rdx, %r10'),
                 ('movq 88(%rbx), %rax','movq 80(%rbx), %rax')]
                if lane=='simd256' else
                [('andl $127, %r13d','andl $255, %r13d'),
                 ('andl $127, %r13d','andl $63, %r13d'),
                 ('movq 928(%rbp), %rbx','movq 936(%rbp), %rbx'),
                 ('leaq (%rbx,%r13), %r10','leaq (%rbx,%r13,2), %r10'),
                 ('movq 1176(%rbp), %rdx','movq 1168(%rbp), %rdx'),
                 ('movq %rax, 16(%rdx)','movq %rax, 17(%rdx)'),
                 ('movq %rcx, 24(%rdx)','movq %rcx, 25(%rdx)'),
                 ('movq %r12, 5596(%rdi)','movq %r12, 5597(%rdi)'),
                 ('movq $0, 5588(%rdi)','movq $0, 5587(%rdi)')])
            for old,new in variants:
                self.assertIn(old,lines)
                changed=[new if line==old else line for line in lines]
                with self.assertRaises(ValueError):e.inspect(changed,lane,inventory,copy)
                count+=1
            for entry in inventory:
                # Store widths and pointer destinations cannot silently drift.
                old=entry['instruction'];new=old.replace('movb','movq') if old.startswith('movb') else old.replace('movq','movl')
                with self.assertRaises(ValueError):
                    e.inspect([new if line==old else line for line in lines],lane,inventory,copy)
                count+=1
            with self.assertRaises(ValueError):e.inspect(lines,lane,inventory[:-1],copy)
            with patch.object(e,'inspect',side_effect=ValueError('effect check failed')) as check:
                with self.assertRaisesRegex(ValueError,'effect check failed'):f.inspect(bodies,lane)
                check.assert_called_once()
            result=report['conditional_indirect_store_effects']
            self.assertEqual(result['store_count'],len(inventory))
            self.assertTrue(result['caller_object_placement_and_aliasing_pending'])
            self.assertFalse(result['whole_frame_qualified'])
        self.assertEqual(count,22)
        print('SIMD indirect-store address/mask/width mutations rejected: '+str(count))

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
