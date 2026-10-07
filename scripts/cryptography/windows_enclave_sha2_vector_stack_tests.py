"""Vector spill bounds, nested stacks and early callback-origin regressions."""
from unittest.mock import patch
import windows_enclave_sha2_vector_stack as p


class VectorStackTests:
    def test_vector_stack_width_direction_and_live_allocation(self):
        for opcode,reg,width in (('movaps','xmm6',16),('vmovups','ymm15',32),
                                 ('vmovdqa','xmm14',16),('movdqu','xmm8',16)):
            body=f'f:\nsubq $40, %rsp\n{opcode} %{reg}, (%rsp)\n{opcode} (%rsp), %{reg}\naddq $40, %rsp\nretq'
            result=p.stack.inspect_body(body,'f',{'f'}, {})
            self.assertEqual(result['direct_stack_accesses'],[[2,'write',-40,-40+width],[3,'read',-40,-40+width]])
            for offset in (-1,41-width,40,48):
                with self.assertRaises(ValueError):p.stack.inspect_body(body.replace('(%rsp)',f'{offset}(%rsp)'),
                    'f',{'f'}, {})

    def test_vector_stack_rejects_unsupported_forms_and_partial_base_aliases(self):
        for instruction in ('movaps %ymm6, (%rsp)','vmovups %zmm6, (%rsp)',
                            'vmovaps %xmm16, (%rsp)','vmovups %ymm0, (%rsp,%rax)',
                            'vmovaps %xmm0, (%esp)','vaddps (%rsp), %ymm0, %ymm1',
                            'vmovaps (%rsp), (%rbp)'):
            with self.assertRaises(ValueError):p.stack.inspect_body(
                'f:\nsubq $40, %rsp\n'+instruction+'\naddq $40, %rsp\nretq','f',{'f'}, {})

    def test_vector_stack_tail_callee_is_included_not_assumed_a_leaf(self):
        bodies={'f':'f:\nsubq $40, %rsp\ncallq g\naddq $40, %rsp\nretq',
                'g':'g:\njmp h','h':'h:\nsubq $168, %rsp\nvmovaps %xmm6, (%rsp)\naddq $168, %rsp\nretq'}
        frames,depths=p.closure(bodies,{'f'}, {})
        self.assertEqual(len(frames),3);self.assertEqual(depths,{'f':-216})
        for changed in (bodies|{'h':'h:\njmp f'},{k:v for k,v in bodies.items() if k!='h'}):
            with self.assertRaises(ValueError):p.closure(changed,{'f'}, {})


class VectorStackSavedTests:
    def vector_stack_fixture(self,row):
        import windows_enclave_sha2_batch_chains as parent
        lane,pin,_,_,_,_,bodies=row
        return parent.load(self.saved,self.root,pin)[3],lane,self.stack_fixture(row)[-1]

    def test_actual_vector_stack_closure_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.routes:
            lane,pin,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            result=p.inspect(bodies,*self.vector_stack_fixture(row))
            self.assertEqual(result['normal_callee_count'],12)
            self.assertEqual(result['caller_frame_relative_stack_span'],[-288,0] if lane=='simd256' else [-416,-128])
            self.assertTrue(result['normal_stack_effects_disjoint'])
            self.assertFalse(result['whole_frame_qualified']);self.assertFalse(result['individual_stack_erasure_qualified'])
            if lane=='simd512':
                self.assertEqual(len(result['early_calls']['calls']),6)
                self.assertEqual(result['early_calls']['state_pointer_uses'],[517,965,1092])
            with patch.object(p,'inspect',side_effect=ValueError('vector stack failed')) as check:
                with self.assertRaisesRegex(ValueError,'vector stack failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_vector_frames_reject_escape_bad_calls_and_vector_store_overlap(self):
        count=0
        for row in self.routes:
            lane,_,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            args=self.vector_stack_fixture(row);result=p.inspect(bodies,*args)
            for name,review in result['functions'].items():
                lines=p.s.lines(bodies[name]);entry=lines.index(name+':')+1
                for instruction in ('vmovaps %xmm6, (%rsp)','movq %rsp, %r11','pushq %rsi'):
                    changed=lines[:entry]+[instruction]+lines[entry:]
                    with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},*args)
                    count+=1
                for at,_,_ in review['calls']+review['tail_calls']:
                    changed=lines[:];changed[at]='callq unassigned'
                    with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},*args)
                    count+=1
            kernel=p.s.one(bodies,r'x866secret8compress$');lines=p.s.lines(bodies[kernel])
            for before,after in (('vmovaps %xmm15, 144(%rsp)','vmovaps %ymm15, 144(%rsp)'),
                                 ('vmovaps %xmm6, (%rsp)','vmovaps %xmm6, -1(%rsp)'),
                                 ('vmovaps (%rsp), %xmm6','vmovaps 168(%rsp), %xmm6')):
                self.assertIn(before,lines);changed=lines[:];changed[lines.index(before)]=after
                with self.assertRaises(ValueError):p.inspect(bodies|{kernel:'\n'.join(changed)},*args)
                count+=1
        print('Vector callee stack/alias/call/spill mutations rejected: '+str(count))
        self.assertGreaterEqual(count,90)

    def test_actual_early_callback_definitions_and_saved_state_pointer_mutants(self):
        row=next(v for v in self.routes if v[0]=='simd512');bodies=row[-1]
        asm,_,review=self.vector_stack_fixture(row);callback=review['leaf_targets']['callback']
        result=p.early_callbacks(bodies,asm,callback);name=p.authority.role(bodies,'executor')
        lines=p.s.lines(bodies[name]);changes=[]
        for slot in (920,960):
            for at in result['callback_sites']:
                changes.append(lines[:at-2]+[f'movb $0, {slot+7}(%rbp)']+lines[at-2:])
                changes.append(lines[:at-2]+[f'movq %rax, {slot-1}(%rbp)']+lines[at-2:])
        for at in result['state_pointer_uses']:
            changes.append(lines[:at]+['movb $0, 991(%rbp)']+lines[at:])
        for before,after in (('movq 1176(%rbp), %rax','movq 1168(%rbp), %rax'),
                             ('movq 32(%rax), %rax','movq 24(%rax), %rax')):
            at=lines.index(before,lines.index('.B98:'));changed=lines[:];changed[at]=after;changes.append(changed)
        for site in result['calls']:
            changed=lines[:];changed[site['line']]='callq unassigned';changes.append(changed)
        changes.append(lines[:result['begin']]+['callq surprise']+lines[result['begin']:])
        for changed in changes:
            with self.assertRaises(ValueError):p.early_callbacks(bodies|{name:'\n'.join(changed)},asm,callback)
        self.assertEqual(len(changes),20)
        print('Early vector callback/state-slot/call-population mutations rejected: '+str(len(changes)))
