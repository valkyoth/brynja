"""Conditional transfer geometry, precise arithmetic and saved-call regressions."""
import re
from unittest.mock import patch
import windows_enclave_sha2_transfer_effects as t
from windows_enclave_sha2_control_effects_tests import ControlEffectTests, ControlEffectSavedTests


class TransferEffectTests(ControlEffectTests):
    def test_transfer_empty_capacity_overlap_and_pointer_bounds(self):
        for size in (0,1,63,128,1024):
            args={'rcx':t.val(2048,'w'),'r8':t.val(0,'w'),'rdx':t.val(size),'r9':t.val(size)}
            result=t.effects('copy',args)
            self.assertEqual(bool(result['writes']),size!=0)
            with self.assertRaises(ValueError):t.effects('copy',args|{'r9':t.val(size+1)})
            if size:
                with self.assertRaises(ValueError):t.effects('copy',args|{'rcx':t.val(size-1,'w')})
        for pointer,size in ((None,1),(t.val(0),1),(t.e.Value('w',0,1),1),
                             (t.val((1<<64)-1,'w'),1),(t.val(0,'w'),-1)):
            with self.assertRaises(ValueError):t.span(pointer,size)
        self.assertEqual(t.effects('mask',{'rcx':t.val(17,'w')})['writes'][0]['span'],[17,18])

    def test_precise_mask_shift_decrement_and_zero_extension(self):
        for mask in (31,63,127):
            for n in (0,1,63,64,127,128,1023,1024):
                seen=[]
                t.e.evaluate([f'andl ${mask}, %edx','callq c'],{'rdx':t.val(n)},{},'c',seen,precise=True)
                self.assertEqual(seen[0][1]['rdx'],t.val(n&mask))
        seen=[]
        t.e.evaluate(['shlq $5, %rcx','leaq 28(,%rcx,4), %rax','decq %r8',
                      'movzwl %dx, %edx','movzbl (%rbx), %ecx','callq c'],
                     {'rcx':t.val(7),'r8':t.val(128,'input'),'rdx':t.val(0x10001),'rbx':t.val(0,'frame')},
                     {('frame',0):t.val(257)},'c',seen,precise=True)
        self.assertEqual(seen[0][1]['rax'],t.val(924))
        self.assertEqual(seen[0][1]['r8'],t.val(127,'input'))
        self.assertEqual(seen[0][1]['rdx'],t.val(1));self.assertEqual(seen[0][1]['rcx'],t.val(1))
        for code,regs in ((['decq %rax'],{'rax':t.val(0,'input')}),
                          (['shlq $1, %rax'],{'rax':t.val(1<<63)}),
                          (['shlq $5, %rax'],{'rax':t.val(1,'pointer')})):
            with self.assertRaises(ValueError):t.e.evaluate(code,regs,{},'c',precise=True)

    def test_partial_register_write_never_invents_unknown_upper_bits(self):
        seen=[]
        t.e.evaluate(['movb $-1, %dl','callq c'],{}, {},'c',seen,precise=True)
        self.assertNotIn('rdx',seen[0][1])
        seen=[]
        t.e.evaluate(['movb $-1, %dl','callq c'],{'rdx':t.val(0x123400)}, {},'c',seen,precise=True)
        self.assertEqual(seen[0][1]['rdx'],t.val(0x1234ff))


class TransferEffectSavedTests(ControlEffectSavedTests):
    def test_thirteen_transfers_reject_pointer_capacity_and_call_mutations(self):
        import windows_enclave_sha2_frame_cell as f
        import windows_enclave_sha2_call_effects as c
        total=0;case_count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            frame=f.inspect(bodies,lane);prior=c.inspect(bodies,lane,frame)
            result=t.inspect(bodies,lane,frame,prior)
            self.assertEqual(result['conditional_transfer_call_count'],6 if lane=='simd256' else 7)
            self.assertEqual(len(result['remaining_call_effects']),6 if lane=='simd256' else 5)
            self.assertTrue(result['original_live_slot_and_physical_alias_preconditions_required'])
            self.assertFalse(result['whole_frame_qualified'])
            case_count+=sum(v['cases'] for v in result['calls'])
            lines=t.s.lines(bodies[frame['function']]);lines=lines[lines.index(frame['begin']+':'):lines.index(frame['end']+':')]
            names={role:t.s.one(bodies,pattern) for role,pattern in (
                ('copy',r'secret_memory18copy_secret_region$'),('mask',r'secret_memory22apply_secret_byte_mask$'))}
            full=t.s.lines(bodies[frame['function']])
            first=full.index('callq '+names['copy'],full.index(frame['begin']+':'))
            for changed in (full[:first]+full[first+1:],full[:first]+[full[first]]+full[first:]):
                with self.assertRaises(ValueError):
                    t.inspect(bodies|{frame['function']:'\n'.join(changed)},lane,frame,prior)
            for job in t.layout(lines,lane,names):
                changes={(job['line'],'callq unassigned')}
                for i in range(job['begin'],job['line']):
                    line=lines[i]
                    m=re.search(r'(-?\d+)\(',line)
                    if m:changes.add((i,line[:m.start(1)]+str(int(m[1])+1)+line[m.end(1):]))
                    m=re.match(r'(?:movl|andl|andq|shlq) \$(-?\d+)',line)
                    if m:changes.add((i,line[:m.start(1)]+str(int(m[1])+1)+line[m.end(1):]))
                    if line.startswith('movq ') and line.endswith(('%rcx','%r8','%r9')):
                        changes.add((i,'movq %r11, '+line.rsplit(', ',1)[1]))
                    if line.startswith('decq '):changes.add((i,line.replace('decq','incq')))
                for i,line in changes:
                    changed=lines[:];changed[i]=line
                    # Invoke the replay directly, bypassing earlier literal checks.
                    with self.assertRaises(ValueError):t.replay(changed,lane,names,job)
                    total+=1
                with self.assertRaises(ValueError):t.replay(lines,lane,names,job,[])
            with patch.object(t,'inspect',side_effect=ValueError('transfer check failed')) as check:
                import windows_enclave_sha2_batch_chains as parent
                pin=next(row[1] for row in self.routes if row[0]==lane)
                with self.assertRaisesRegex(ValueError,'transfer check failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
        self.assertEqual(case_count,6654)
        self.assertEqual(total,79)
        print('SIMD transfer pointer/capacity/call mutations rejected: '+str(total))
