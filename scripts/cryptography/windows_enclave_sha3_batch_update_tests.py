"""Saved sequential update caller mutations; no new native qualification."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c


class UpdateTests:
    def update_fixture(self,lane):
        bodies,asm,ir,prior=self.storage_fixture(lane)
        storage=c.storage.inspect(bodies,asm,ir,lane,prior)
        retained=c.worker.inspect(bodies,ir,lane,prior,storage)
        transitions=c.lifecycle.inspect(bodies,ir,lane)
        admission=c.plan.inspect(bodies,asm,ir)
        receiver=c.receive.inspect(bodies,asm,ir,lane,retained,storage,transitions,admission)
        return bodies,asm,ir,lane,prior,storage,transitions,receiver

    def test_update_complete_instructions_and_labels_are_load_bearing(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,asm,_,_,bodies=self.routes[lane]
            n,_=c.update.check_shapes(bodies,asm,lane);name=n['update']
            lines=c.lifecycle.code(bodies[name])
            for at in range(len(lines)):
                for bad in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                    with self.assertRaises(ValueError):
                        c.update.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm,lane)
                    count+=1
        self.assertEqual(count,492)
        print('SHA-3 sequential update instruction/label mutants rejected:',count)

    def test_update_dispatch_rejects_all_changed_cases(self):
        _,_,asm,_,_,bodies=self.routes['scalar']
        n,_=c.update.check_shapes(bodies,asm,'scalar')
        table=re.findall(r'\.LJTI\d+_\d+',bodies[n['update']])[0]
        match=re.search(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',asm,re.M)
        self.assertIsNotNone(match);lines=match[1].splitlines(keepends=True)
        self.assertEqual(len(lines),9)
        for at in range(9):
            bad=lines.copy();bad[at]='\t.long\t0\n'
            with self.assertRaises(ValueError):
                c.update.check_shapes(bodies,asm[:match.start(1)]+''.join(bad)+asm[match.end(1):],'scalar')
        with self.assertRaises(ValueError):c.update.check_shapes(bodies,asm.replace(table+':',table+'_absent:'),'scalar')

    def test_update_pointer_budget_authority_and_cleanup_mutants(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,asm,_,_,bodies=self.routes[lane];n,_=c.update.check_shapes(bodies,asm,lane)
            name=n['update'];body='\n'.join(c.lifecycle.s.lines(bodies[name]))
            scalar=lane=='scalar';reg='rbx' if scalar else 'rsi';source='rsi' if scalar else 'rdi'
            changes=[('movq %r9, %'+source,'movq %r8, %'+source),
                ('movq %'+source+', %rdx','movq %rsp, %rdx'),
                ('movq 128(%rsp), %r8','movq 120(%rsp), %r8'),
                ('movb $3, %r9b','movb $2, %r9b'),
                ('jb .B'+('17' if scalar else '18'),'ja .B'+('17' if scalar else '18')),
                ('callq '+c.lifecycle.DROP[lane],'nop'),('callq '+c.lifecycle.ZERO,'nop'),
                ('movb $5, '+str(c.lifecycle.LAYOUT[lane]['phase'])+'(%'+reg+')','nop')]
            if scalar:changes += [('cmpq %rdi, 8(%rbx)','cmpq %rdi, %rdi'),
                ('leaq 18(%rbx), %rcx','leaq 17(%rbx), %rcx'),('testb %cl, %cl','testb %al, %al')]
            else:changes += [('cmpq %rbx, 2240(%rsi)','cmpq %rbx, %rbx'),
                ('cmpq 1800(%rsi), %rcx','cmpq %rcx, %rcx'),('cmpb $4, 9(%rax)','cmpb $3, 9(%rax)'),
                ('leaq 1216(%rsi), %rcx','leaq 1217(%rsi), %rcx'),('callq '+n['wipe'],'nop'),
                ('cmpb $-1, %al','testb %al, %al')]
            for old,new in changes:
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.update.check_shapes(bodies|{name:body.replace(old,new)},asm,lane)
                count+=1
        self.assertEqual(count,25)

    def test_update_lower_and_caller_argument_abi_drift_rejected(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,_,ir,_,bodies=self.routes[lane];n=c.update.names(bodies,lane)
            mutations=[('update','range(i64 0, 1025)','range(i64 0, 1026)'),
                       ('update','readonly ',' '),('update','noalias ',' ')]
            targets=('48','68','88','90','a8') if lane=='scalar' else ('absorb',)
            for target in targets:
                mutations += [(target,'noalias ',' '),(target,'readonly ',' '),
                              (target,'dereferenceable('+('1040' if lane=='scalar' else '864')+')','dereferenceable(1)'),
                              (target,'range(i64 0, -9223372036854775808)','range(i64 0, -1)')]
            if lane=='avx2':mutations += [('absorb','align 32','align 16'),('wipe','dereferenceable(234)','dereferenceable(233)')]
            for key,old,new in mutations:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):c.update.arguments(ir.replace(row,row.replace(old,new)),bodies,lane)
                count+=1
        self.assertEqual(count,32)

    def test_update_composes_actual_helpers_and_preserves_pending_scope(self):
        for lane in ('scalar','avx2'):
            args=self.update_fixture(lane);result=c.update.inspect(*args)
            self.assertEqual(result['instructions_and_labels_checked'],122 if lane=='scalar' else 124)
            for index,path in [(4,('prior_semantics_replayed',)),(5,('state_destructor','typed_payload_cleanup_composed')),
                (5,('state_pointer_inside_owner',)),(6,('checked_next_sequence',)),
                (6,('phase_match_before_admission',)),(6,('unfinished_guard_clears_and_quarantines',)),
                (7,('payload_pointer_retained_from_worker_buffer',))]:
                bad=list(args);bad[index]=copy.deepcopy(args[index]);value=bad[index]
                for key in path[:-1]:value=value[key]
                value[path[-1]]=False
                with self.assertRaises(ValueError):c.update.inspect(*bad)
            for helper in result['absorption_helpers']+[c.lifecycle.ZERO]:
                bad=list(args);bad[4]=copy.deepcopy(args[4]);del bad[4]['exact_body_reference_extent_and_abi'][helper]
                with self.assertRaises(ValueError):c.update.inspect(*bad)
            for index,key in ((6,'operation'),(7,'update')):
                bad=list(args);bad[index]=copy.deepcopy(args[index]);bad[index]['functions'][key]='different'
                with self.assertRaises(ValueError):c.update.inspect(*bad)
            bad=list(args);bad[7]=copy.deepcopy(args[7]);bad[7]['payload_limit']=1025
            with self.assertRaises(ValueError):c.update.inspect(*bad)
            for key in ('start_establishes_state_invariant_qualified','caller_input_erasure_claimed',
                        'private_frame_erasure_qualified','all_unwind_paths_qualified','whole_image_qualified'):
                self.assertFalse(result[key])
            with patch.object(c.update,'inspect',side_effect=ValueError('update failed')) as check:
                with self.assertRaisesRegex(ValueError,'update failed'):c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()

    def test_update_lower_unwind_contract_cannot_be_removed(self):
        for lane in ('scalar','avx2'):
            _,_,_,ir,_,bodies=self.routes[lane];n=c.update.names(bodies,lane)
            for key in (('48','68','88','90','a8') if lane=='scalar' else ('absorb','wipe')):
                original=c.update.life.reuse.abi
                def changed(text,name):
                    abi=original(text,name)
                    return abi.replace('nounwind','') if name==n[key] else abi
                with patch.object(c.update.life.reuse,'abi',side_effect=changed):
                    with self.assertRaises(ValueError):c.update.arguments(ir,bodies,lane)
