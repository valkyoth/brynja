"""Saved worker admission, pointer identity, buffer cleanup and retirement tests."""
import copy
from unittest.mock import patch

import windows_enclave_sha3_batch_chains as c


class WorkerTests:
    def worker_fixture(self,lane):
        bodies,asm,ir,prior=self.storage_fixture(lane)
        storage=c.storage.inspect(bodies,asm,ir,lane,prior)
        return bodies,ir,prior,storage

    def test_retained_worker_every_instruction_is_load_bearing(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            result=c.worker.inspect(bodies,ir,lane,prior,storage);n=result['resident']['functions']
            selected={'RetainedWork',n['buffers'],n['quarantine']}
            if lane=='avx2':selected.update(n[k] for k in ('new','drop','buffers_clear'))
            for name in sorted(selected):
                lines=c.lifecycle.code(bodies[name])
                for at in range(len(lines)):
                    for bad in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                        with self.assertRaises(ValueError):
                            c.worker.inspect(bodies|{name:name+':\n'+'\n'.join(bad)},ir,lane,prior,storage)
                        count+=1
        # 246 scalar and 562 AVX2 instructions/labels, each deleted and replaced.
        self.assertEqual(count,1616)
        print('Sequential SHA-3 retained worker/resident instruction mutants rejected:',count)

    def test_retained_worker_admission_pointer_identity_and_erase_extents(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            result=c.worker.inspect(bodies,ir,lane,prior,storage);n=result['resident']['functions']
            root='\n'.join(c.lifecycle.s.lines(bodies['RetainedWork']))
            changes=[('testl $4095, %edx','testl $2047, %edx'),
                     ('cmpq $65536,','cmpq $65535,'),('cmpq $3, %rcx','cmpq $2, %rcx'),
                     ('cmpl $1, %eax','cmpl $0, %eax')]
            changes += ([('cmpq %rdx, %rsi','cmpq %rsi, %rsi'),('cmpq $4096, %rdx','cmpq $4088, %rdx')]
                if lane=='scalar' else [(f'cmpq %rdx, {result["page_identity_metadata"]}(%rip)','cmpq %rdx, %rdx'),
                                       ('cmpq $-4097, %rdx','cmpq $-4096, %rdx')])
            for old,new in changes:
                self.assertIn(old,root)
                with self.assertRaises(ValueError):
                    c.worker.inspect(bodies|{'RetainedWork':root.replace(old,new,1)},ir,lane,prior,storage)
                count+=1
            if lane=='avx2':
                for kind,old,new in [('new','movq %rdi, 2256(%rdi)','movq %r15, 2256(%rdi)'),
                     ('new','leaq 32(%rdi), %r15','leaq 16(%rdi), %r15'),
                     ('new','testb %al, %al','testb %cl, %cl'),
                     ('drop','cmpq $4096, %rax','cmpq $4088, %rax')]:
                    body='\n'.join(c.lifecycle.s.lines(bodies[n[kind]]));self.assertIn(old,body)
                    with self.assertRaises(ValueError):
                        c.worker.inspect(bodies|{n[kind]:body.replace(old,new,1)},ir,lane,prior,storage)
                    count+=1
        self.assertEqual(count,16)

    def test_worker_normal_cfg_rejects_return_before_buffer_drop(self):
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            result=c.worker.inspect(bodies,ir,lane,prior,storage)
            body='\n'.join(c.lifecycle.s.lines(bodies['RetainedWork']))
            start='.B11' if lane=='scalar' else '.B27';drop=result['resident']['functions']['buffers']
            self.assertEqual(c.lifecycle.s.normal_returns(body,start,['callq '+drop]),1)
            for bad in (body.replace(start+':',start+':\nretq'),body.replace('callq '+drop,'nop')):
                with self.assertRaises(ValueError):c.lifecycle.s.normal_returns(bad,start,['callq '+drop])

    def test_worker_resident_and_buffer_abis_remain_bound(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            n=c.worker.resident.names(bodies,lane)
            specs=[(n['buffers'],'dereferenceable('+str(1312 if lane=='scalar' else 1328)+')','dereferenceable(1024)'),
                (n['quarantine'],'nonnull ',' '),('RetainedWork','i64 noundef %low','i64 noundef %other')]
            if lane=='avx2':
                specs += [(n['new'],'align 4096','align 32'),(n['new'],'noalias ',' '),
                    (n['new'],'dereferenceable(24)','dereferenceable(16)'),
                    (n['new'],'dereferenceable(4096)','dereferenceable(4095)'),
                    (n['drop'],'%.16.val','%.8.val')]
            for name,old,new in specs:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):
                    c.worker.inspect(bodies,ir.replace(row,row.replace(old,new)),lane,prior,storage)
                count+=1
        self.assertEqual(count,11)

    def test_retained_worker_prerequisites_and_integration_are_required(self):
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            for key in ('state_pointer_inside_owner','state_destructor'):
                bad=copy.deepcopy(storage)
                if key=='state_destructor':bad[key]['typed_payload_cleanup_composed']=False
                else:bad[key]=False
                with self.assertRaises(ValueError):c.worker.inspect(bodies,ir,lane,prior,bad)
            if lane=='avx2':
                bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][c.worker.resident.KAT]
                with self.assertRaises(ValueError):c.worker.inspect(bodies,ir,lane,bad,storage)
            with patch.object(c.worker,'inspect',side_effect=ValueError('worker failed')) as check:
                with self.assertRaisesRegex(ValueError,'worker failed'):
                    c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()

    def test_retained_worker_does_not_promote_os_or_nested_lifetimes(self):
        for lane in ('scalar','avx2'):
            bodies,ir,prior,storage=self.worker_fixture(lane)
            result=c.worker.inspect(bodies,ir,lane,prior,storage)
            self.assertTrue(result['serialized_C_entry_required'])
            self.assertEqual(result['worker_checks_page_stack_nonoverlap'],lane=='avx2')
            self.assertEqual(result['scalar_page_stack_nonoverlap_requires_linked_C'],lane=='scalar')
            for key in ('receiver_nested_call_lifetimes_qualified','all_unwind_paths_qualified',
                        'whole_image_stack_residency_and_erasure_qualified'):
                self.assertFalse(result[key])


class WorkerModelTests:
    def test_complete_successful_readback_counters(self):
        for lane,start,header in [('scalar',32,288),('avx2',64,304)]:
            r=c.worker.readback_offsets(lane)
            self.assertEqual(r,dict(payload=[start,start+1024],header=[start+1024,start+1024+header],
                                    payload_reads=1024,header_reads=header))
