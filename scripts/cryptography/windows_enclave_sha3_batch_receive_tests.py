"""Receiver decode/copy/export mutations against saved emitted Windows bodies."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c


class ReceiverTests:
    def receive_fixture(self,lane):
        bodies,asm,ir,prior=self.storage_fixture(lane)
        storage=c.storage.inspect(bodies,asm,ir,lane,prior)
        retained=c.worker.inspect(bodies,ir,lane,prior,storage)
        transitions=c.lifecycle.inspect(bodies,ir,lane)
        admission=c.plan.inspect(bodies,asm,ir)
        return bodies,asm,ir,lane,retained,storage,transitions,admission

    def test_receiver_complete_instruction_contracts_are_load_bearing(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,*_=self.receive_fixture(lane)
            _,shapes=c.receive.check_shapes(bodies,asm,lane)
            for name in shapes:
                lines=c.lifecycle.code(bodies[name])
                for at in range(len(lines)):
                    for bad in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                        with self.assertRaises(ValueError):
                            c.receive.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm,lane)
                        count+=1
        self.assertEqual(count,2782)
        print('SHA-3 receiver/decoder/equality/authority instruction mutants rejected:',count)

    def test_receiver_every_dispatch_entry_and_missing_table_rejected(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,*_=self.receive_fixture(lane)
            _,shapes=c.receive.contracts(bodies,lane)
            for name in shapes:
                tables=set(re.findall(r'\.LJTI\d+_\d+',bodies[name]))
                for table in sorted(tables):
                    match=re.search(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',asm,re.M)
                    self.assertIsNotNone(match);lines=match[1].splitlines(keepends=True)
                    for at in range(len(lines)):
                        bad=list(lines);bad[at]='\t.long\t0\n'
                        altered=asm[:match.start(1)]+''.join(bad)+asm[match.end(1):]
                        with self.assertRaises(ValueError):c.receive.check_shapes(bodies,altered,lane)
                        count+=1
                    with self.assertRaises(ValueError):c.receive.check_shapes(bodies,asm.replace(table+':',table+'_missing:'),lane)
                    count+=1
        self.assertEqual(count,42)

    def test_receiver_export_requires_all_plan_fields_and_lifecycle(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,*_=self.receive_fixture(lane)
            n,_=c.receive.check_shapes(bodies,asm,lane);name=n['receive'];lines=c.lifecycle.code(bodies[name])
            base=1152 if lane=='scalar' else 1024;reg='rdi' if lane=='scalar' else 'rcx'
            for i in range(8):
                for field in (0,8,16):
                    token=('cmpb' if field==16 else 'cmpq')+f' {base+24*i+field}(%{reg}), '
                    at=next(i for i,l in enumerate(lines) if l.startswith(token))
                    self.assertTrue(lines[at+1].startswith('jne '))
                    bad=lines.copy();bad[at+1]='nop'
                    with self.assertRaises(ValueError):
                        c.receive.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm,lane)
                    count+=1
            for old,new in [('movb $4, %r9b','movb $3, %r9b'),
                            ('callq '+n['guard'],'nop'),('callq '+n['clear'],'nop'),
                            ('callq PublicSha3BatchOutput','callq PublicSha3BatchInput')]:
                body='\n'.join(c.lifecycle.s.lines(bodies[name]))
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.receive.check_shapes(bodies|{name:body.replace(old,new)},asm,lane)
                count+=1
        self.assertEqual(count,56)

    def test_receiver_input_copy_and_decode_cannot_be_weakened(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,*_=self.receive_fixture(lane)
            n,_=c.receive.check_shapes(bodies,asm,lane);name=n['receive']
            header=288 if lane=='scalar' else 304
            changes=[(name,f'movl ${header}, %r9d',f'movl ${header+1}, %r9d'),
                     (name,'leaq 1024(', 'leaq 1023('),(name,'movl $1, %ecx','xorl %ecx, %ecx')]
            if lane=='scalar':changes += [(name,'cmpq $1024, %r13','cmpq $1025, %r13'),
                (name,'movq %rbx, %rdx','movq %rsi, %rdx'),(name,'addq %r13, %rcx','addq %r15, %rcx')]
            else:changes += [(name,'cmpq $1024, %rbx','cmpq $1025, %rbx'),
                (name,'cmpq 632(%rsp), %rbx','cmpq %rbx, %rbx'),
                (n['decode'],'cmpq $1, 760(%rsp)','cmpq $0, 760(%rsp)'),
                (n['decode'],'cmpq $0, 768(%rsp)','cmpq $1, 768(%rsp)'),
                (n['decode'],'addq %r12, %rcx','addq %rbx, %rcx'),
                (n['authority'],'cmpb $1, 8(%rcx)','cmpb $2, 8(%rcx)')]
            for target,old,new in changes:
                body='\n'.join(c.lifecycle.s.lines(bodies[target]))
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.receive.check_shapes(bodies|{target:body.replace(old,new)},asm,lane)
                count+=1
        self.assertEqual(count,15)

    def test_receiver_and_nested_argument_abis_reject_drift(self):
        count=0
        for lane in ('scalar','avx2'):
            args=self.receive_fixture(lane);bodies,asm,ir=args[:3];n=c.receive.names(bodies,lane)
            mutations=[('receive','noalias ',' '),('receive','dereferenceable('+str(1312 if lane=='scalar' else 1328)+')','dereferenceable(1024)'),
                ('equal','captures(none)','captures(address)'),('start','i128 noundef %3','i64 noundef %3'),
                ('setup_chunk','zeroext ',' '),('finish_setup','nonnull ',' '),
                ('update','range(i64 0, 1025)','range(i64 0, 1026)'),('finish','readonly ',' ')]
            if lane=='avx2':mutations += [('decode','noalias ',' '),('decode','readonly ',' '),
                ('decode','align 16','align 8'),('decode','dereferenceable(304)','dereferenceable(303)'),
                ('authority','readonly ',' ')]
            for key,old,new in mutations:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):c.receive.arguments(ir.replace(row,row.replace(old,new)),n,lane)
                count+=1
        self.assertEqual(count,21)

    def test_receiver_composition_prerequisites_and_pending_scope(self):
        for lane in ('scalar','avx2'):
            args=self.receive_fixture(lane);result=c.receive.inspect(*args)
            for index,path in [(4,('initialization_precedes_live_publication',)),(4,('exact_page_identity_before_receive',)),
                (4,('resident','complete_buffer_destructor_checked')),(5,('state_destructor','typed_payload_cleanup_composed')),
                (5,('begin','source_destination_disjoint_by_abi')),(6,('unfinished_guard_clears_and_quarantines',)),
                (6,('phase_match_before_admission',)),(6,('checked_next_sequence',)),(7,('all_instructions_and_dispatch_cases_checked',))]:
                bad=list(args);bad[index]=copy.deepcopy(args[index]);value=bad[index]
                for key in path[:-1]:value=value[key]
                value[path[-1]]=False
                with self.assertRaises(ValueError):c.receive.inspect(*bad)
            for key in ('nested_crypto_operation_bodies_and_pointer_preservation_qualified',
                        'decoder_copies_and_frame_padding_individually_erased','all_unwind_paths_qualified',
                        'whole_image_qualified','export_host_bytes_rollback_claimed'):
                self.assertFalse(result[key])
            with patch.object(c.receive,'inspect',side_effect=ValueError('receive failed')) as check:
                with self.assertRaisesRegex(ValueError,'receive failed'):c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()


class ReceiverModelTests:
    def test_decoder_public_selector_arithmetic(self):
        for operation in list(range(1024))+[(1<<64)-i for i in range(1,257)]:
            self.assertEqual(c.receive.selectors(operation),dict(admitted=90<=operation<=99,
                payload=operation in (92,93,95,96),planned=operation in (90,98)))
        for operation in (-1,1<<64):
            with self.assertRaises(ValueError):c.receive.selectors(operation)
