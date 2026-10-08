"""Final-message caller, output span and selected-unwind regressions."""
import copy
import random
import re
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c


class FinishModelTests:
    def test_finish_output_spans_match_unbounded_reference(self):
        def check(widths,slot):
            start=sum(widths[:slot]);end=start+widths[slot]
            want=(start,end) if end<=1024 else None
            self.assertEqual(c.finish.output_span(widths,slot),want)
        for slot in range(8):
            for width in range(1026):
                widths=[0]*8;widths[slot]=width;check(widths,slot)
            for at in range(slot+1):
                for value in (1,1023,1024,1025,(1<<64)-1):
                    widths=[1]*8;widths[at]=value;check(widths,slot)
        rng=random.Random(0x53484133)
        for _ in range(4096):
            widths=[rng.choice((0,1,28,32,48,64,128,1024,(1<<64)-1,rng.getrandbits(64))) for _ in range(8)]
            for slot in range(8):check(widths,slot)
        self.assertEqual(c.finish.output_span([1024]+[0]*7,7),(1024,1024))
        for slot in (8,255,(1<<64)-1):self.assertIsNone(c.finish.output_span([0]*8,slot))
        for widths,slot in (([0]*7,0),([-1]+[0]*7,0),([1<<64]+[0]*7,0),([0]*8,-1),([0]*8,1<<64)):
            with self.assertRaises(ValueError):c.finish.output_span(widths,slot)


class FinishTests:
    def test_finish_every_caller_funclet_and_guard_instruction_rejected(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies=self.routes[lane][-1];_,shapes=c.finish.check_shapes(bodies,lane)
            for name,lines in shapes.items():
                for at in range(len(lines)):
                    for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                        with self.assertRaises(ValueError):
                            c.finish.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},lane)
                        count+=1
        self.assertEqual(count,1056)
        print('SHA-3 batch finish caller/funclet/guard instruction mutants rejected:',count)

    def test_finish_offsets_input_and_success_cleanup_mutations(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies=self.routes[lane][-1];n,_=c.finish.check_shapes(bodies,lane);name=n['finish']
            body='\n'.join(c.lifecycle.s.lines(bodies[name]));scalar=lane=='scalar'
            changes=[('movb $3, %r9b','movb $2, %r9b'),('cmpb $8, %cl','cmpb $9, %cl'),
                ('subb $1, %cl','subb $2, %cl'),('cmovel %eax, %edx','cmovnel %eax, %edx'),
                ('decq %rcx','incq %rcx'),('cmpq $7, %rsi','cmpq $8, %rsi'),
                ('jb .B5','ja .B5'),('callq '+n['mask'],'nop'),('callq '+n['finish_xof'],'nop'),
                ('callq '+n['finish_fixed'],'nop'),('callq '+n['squeeze'],'nop'),
                ('callq '+c.lifecycle.ZERO,'nop'),('callq '+c.lifecycle.DROP[lane],'nop'),
                ('cmpb $-1, %al','cmpb $0, %al'),('shlb %cl, %al','shrb %cl, %al')]
            changes+=([('movq %r9, %rdi','movq %r8, %rdi'),('movq 176(%rsp), %r14','movq 168(%rsp), %r14'),
                ('cmpq $1025, %rax','cmpq $1026, %rax'),('addq $1344, %r14','addq $1345, %r14'),
                ('leaq 32(%rsp), %rdx','leaq 40(%rsp), %rdx'),('setae %dl','setb %dl'),
                ('movb $1, 2384(%r12)','movb $4, 2384(%r12)'),('orb %al, 2385(%r12)','movb %al, 2385(%r12)')]
                if scalar else [('movq %r9, %rbx','movq %r8, %rbx'),('movq 112(%rbp), %r15','movq 104(%rbp), %r15'),
                ('cmpq $1025, %rcx','cmpq $1026, %rcx'),('addq %r13, %r15','addq %r12, %r15'),
                ('leaq -48(%rbp), %rdx','leaq -40(%rbp), %rdx'),('jae .B47','jb .B47'),
                ('movb $1, 2249(%r13)','movb $4, 2249(%r13)'),('orb %al, 2248(%r13)','movb %al, 2248(%r13)')])
            for old,new in changes:
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.finish.check_shapes(bodies|{name:body.replace(old,new)},lane)
                count+=1
        self.assertEqual(count,46)

    def test_finish_unwind_metadata_and_all_three_intervals(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];n,_=c.finish.check_shapes(bodies,'avx2')
        result=c.finish.unwind(asm,bodies,n);count=0
        for label,want in result['expected_tables'].items():
            match=re.search(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
            lines=match[1].splitlines(keepends=True)
            for at in range(len(want)):
                bad=lines.copy();bad[at]='\t.long\tUNREVIEWED\n'
                with self.assertRaises(ValueError):c.finish.unwind(asm[:match.start(1)]+''.join(bad)+asm[match.end(1):],bodies,n)
                count+=1
            for bad in (asm.replace(label+':',label+'_absent:'),asm+'\n'+match[0]):
                with self.assertRaises(ValueError):c.finish.unwind(bad,bodies,n)
                count+=1
        self.assertEqual(count,24)
        name=n['finish'];body='\n'.join(c.lifecycle.s.lines(bodies[name]))
        changes=[(f'.Ltmp{i}:','') for i in range(12,18)]+[(f'.Ltmp{i}:',f'.Ltmp{i}:\n.Ltmp{i}:') for i in range(12,18)]
        changes += [('callq '+n[k],'nop') for k in ('finish_xof','finish_fixed','squeeze')]
        changes += [('.seh_handler __CxxFrameHandler3, @unwind, @except','.seh_handler UNREVIEWED, @unwind, @except'),
                    ('.long $cppxdata$'+name+'@IMGREL','.long 0')]
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):c.finish.unwind(asm,bodies|{name:body.replace(old,new)},n)
        self.assertEqual(len(changes),17)

    def test_finish_argument_alias_bounds_and_capture_regressions(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,_,ir,_,bodies=self.routes[lane];n=c.finish.names(bodies,lane)
            changes=[('finish','range(i64 0, 1025)','range(i64 0, 1026)'),('finish','readonly ',' '),
                ('mask','dereferenceable(1)','dereferenceable(0)')]
            for key in ('finish_xof','finish_fixed','squeeze'):
                changes += [(key,'noalias ',' '),(key,'dereferenceable('+('1136' if lane=='scalar' else '992')+')','dereferenceable(1)')]
            for key in ('finish_xof','finish_fixed'):
                changes += [(key,'dereferenceable(32)','dereferenceable(31)'),(key,'captures(none)','captures(address)'),
                            (key,'readonly ',' ')]
            for key in ('finish_fixed','squeeze'):
                changes += [(key,'range(i64 0, -9223372036854775808)','range(i64 0, -1)')]
            if lane=='avx2':changes += [('glue','nonnull ',' '),('glue','range(i8 0, 2)','range(i8 0, 3)')]
            for key,old,new in changes:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):c.finish.arguments(ir.replace(row,row.replace(old,new)),bodies,lane)
                count+=1
        self.assertEqual(count,36)

    def test_finish_integrated_prerequisites_and_lower_pending_scope(self):
        for lane in ('scalar','avx2'):
            args=self.update_fixture(lane);result=c.finish.inspect(*args)
            for index,path in [(4,('prior_semantics_replayed',)),(5,('state_destructor','typed_payload_cleanup_composed')),
                (5,('state_pointer_inside_owner',)),(6,('checked_next_sequence',)),(6,('phase_match_before_admission',)),
                (6,('unfinished_guard_clears_and_quarantines',)),(7,('payload_pointer_retained_from_worker_buffer',))]:
                bad=list(args);bad[index]=copy.deepcopy(args[index]);value=bad[index]
                for key in path[:-1]:value=value[key]
                value[path[-1]]=False
                with self.assertRaises(ValueError):c.finish.inspect(*bad)
            for helper in result['lower_helpers_replayed_and_exact']:
                bad=list(args);bad[4]=copy.deepcopy(args[4]);del bad[4]['exact_body_reference_extent_and_abi'][helper]
                with self.assertRaises(ValueError):c.finish.inspect(*bad)
            for index,key in ((6,'operation'),(7,'finish')):
                bad=list(args);bad[index]=copy.deepcopy(args[index]);bad[index]['functions'][key]='wrong'
                with self.assertRaises(ValueError):c.finish.inspect(*bad)
            bad=list(args);bad[7]=copy.deepcopy(args[7]);bad[7]['payload_limit']=1025
            with self.assertRaises(ValueError):c.finish.inspect(*bad)
            self.assertEqual(len(result['lower_finalizer_review_pending']),3 if lane=='scalar' else 0)
            self.assertEqual(result['all_lower_finalizers_normal_paths_composed'],lane=='avx2')
            for key in ('all_lower_finalizers_composed','start_establishes_state_invariant_qualified',
                        'private_frame_erasure_qualified','all_unwind_paths_qualified','whole_image_qualified'):
                self.assertFalse(result[key])
            with patch.object(c.finish,'inspect',side_effect=ValueError('finish failed')) as check:
                with self.assertRaisesRegex(ValueError,'finish failed'):c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()
