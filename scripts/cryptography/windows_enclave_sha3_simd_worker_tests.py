"""Retained SIMD worker boundary, cleanup and source-composition regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_worker as t


class SimdWorkerSavedTests:
    def simd_worker_fixture(self):
        bodies,asm,ir,construction,session=self.simd_owner_fixture()
        checked=t.owner.inspect(bodies,asm,ir,construction,session)
        return bodies,ir,construction,checked

    def test_simd_worker_instruction_extent_including_buffers(self):
        args=self.simd_worker_fixture();bodies,ir,construction,checked=args
        report=t.inspect(*args);count=0
        for name in ('RetainedWork',report['functions']['clear'],report['functions']['drop']):
            lines=t.life.code(bodies[name])
            for at in range(len(lines)):
                for replacement in ([],['ud2'],['retq',lines[at]]):
                    bad=lines[:at]+replacement+lines[at+1:]
                    with self.assertRaises(ValueError):
                        t.inspect(bodies|{name:name+':\n'+'\n'.join(bad)},ir,construction,checked)
                    count+=1
        self.assertEqual(count,864)
        print('Keccak retained-worker/buffer instruction mutations rejected:',count)

    def test_simd_worker_bounds_identity_pointers_and_erase_extents(self):
        args=self.simd_worker_fixture();bodies,ir,construction,checked=args
        n=t.names(bodies);body=bodies['RetainedWork'];count=0
        changes=[('testl\t$4095','testl\t$2047'),('cmpq\t$-4097','cmpq\t$-4096'),
            ('cmpq\t$65536','cmpq\t$65535'),('cmpq\t$-385','cmpq\t$-384'),
            ('setb\t%bpl','setae\t%bpl'),('leaq\t12736','leaq\t12735'),
            ('cmpl\t$1','cmpl\t$0'),('movl\t$12292','movl\t$12293'),
            ('cmpq\t$12291','cmpq\t$12287'),('cmpq\t$12672','cmpq\t$12667'),
            ('cmpq\t$4096','cmpq\t$4088'),('movl\t$12672','movl\t$12671'),
            ('leaq\t64(%rsp), %rdx','leaq\t65(%rsp), %rdx'),
            (f'cmpq\t%rdx, {n["identity"]}(%rip)','cmpq\t%rdx, %rdx'),
            (f'movq\t$0, {n["live"]}(%rip)','nop'),
            (f'movq\t%rax, {n["live"]}+16(%rip)',f'movq\t%rdi, {n["live"]}+16(%rip)')]
        # Use normalized spacing, so formatting differences between platforms do
        # not turn the test into an absent-token no-op.
        body='RetainedWork:\n'+'\n'.join(t.life.code(body))
        for old,new in changes:
            old=old.replace('\t',' ');new=new.replace('\t',' ')
            self.assertIn(old,body)
            with self.assertRaises(ValueError):
                t.inspect(bodies|{'RetainedWork':body.replace(old,new,1)},ir,construction,checked)
            count+=1
        self.assertEqual(count,16)

    def test_simd_worker_every_request_return_requires_buffer_drop(self):
        bodies,*_=self.simd_worker_fixture();n=t.names(bodies)
        code=t.life.code(bodies['RetainedWork'])
        body='RetainedWork:\n'+'\n'.join(code)
        self.assertEqual(t.s.normal_returns(body,'.B23',['callq '+n['drop']]),1)
        count=0
        # B45 is the sole common drop join. All error/observe/readback exits
        # before it must still pass through it; this check is independent of
        # the exact-body matcher.
        for label in ('.B23','.B31','.B32','.B48','.B45','.B37','.B38','.B43'):
            with self.assertRaises(ValueError):
                t.s.normal_returns(body.replace(label+':',label+':\nretq'),'.B23',['callq '+n['drop']])
            count+=1
        with self.assertRaises(ValueError):
            t.s.normal_returns(body.replace('callq '+n['drop'],'nop'),'.B23',['callq '+n['drop']])
        self.assertEqual(count,8)
        self.assertEqual(len(t.cleanup_paths(body,n)),5)
        for old in ('callq '+n['drop'],'callq '+n['clear'],'movb $0, 16(%rax)'):
            with self.assertRaises(ValueError):t.cleanup_paths(body.replace(old,'nop'),n)

    def test_simd_worker_abi_prerequisites_and_integration(self):
        args=self.simd_worker_fixture();bodies,ir,construction,checked=args
        report=t.inspect(*args);count=0
        for name in ('RetainedWork',report['functions']['clear'],report['functions']['drop']):
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('noundef','noalias','nofree','nonnull','dereferenceable(12672)','fastcc','%low','%high'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace(token,'')),construction,checked)
                count+=1
        self.assertEqual(count,15)
        for index,key in ((2,'function'),(2,'publication_after_authority_and_owner_initialization'),
            (2,'constructor_failure_clears_all_page_bytes'),(3,'owner_authority_offset'),
            (3,'rejected_operation_clears_output_and_quarantines')):
            bad=copy.deepcopy(list(args));bad[index][key]=None
            with self.assertRaises(ValueError):t.inspect(*bad)
        for key in ('owner_page_span','authority_page_span'):
            bad=copy.deepcopy(list(args));bad[2]['placement'][key]=None
            with self.assertRaises(ValueError):t.inspect(*bad)
        self.assertFalse(report['receiver_nested_call_lifetimes_qualified'])
        self.assertFalse(report['private_frame_erasure_qualified'])
        self.assertFalse(report['fatal_abort_cleanup_claimed'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('worker review failed')) as call:
            with self.assertRaisesRegex(ValueError,'worker review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()


class SimdWorkerModelTests:
    def test_simd_worker_readback_exact_buffer_population(self):
        self.assertEqual(t.readback_offsets(),dict(header=[12352,12736],payload=[64,12352],
            header_reads=384,payload_reads=12288))

    def test_simd_worker_unsigned_admission_boundaries(self):
        maximum=(1<<64)-1;low=0x100000;high=low+65536
        pages={0,1,4095,4096,low-4097,low-4096,low-1,low,low+4096,high-4096,
            high-1,high,high+1,high+4096,maximum-8191,maximum-4096,maximum-4095,maximum}
        windows={(low,high),(low,high-1),(low,high+1),(high,low),(0,65536),
            (maximum-65536,maximum),(0,0)}
        for page in pages:
            for lo,hi in windows:
                # Mathematical half-open intervals; no machine wraparound.
                expected=(page>0 and page%4096==0 and page+4096<=maximum and
                    hi-lo==65536 and (page+4096<=lo or page>=hi))
                self.assertEqual(t.entry_admits(page,lo,hi),expected,(page,lo,hi))
        self.assertTrue(t.entry_admits(low-4096,low,high))
        self.assertTrue(t.entry_admits(high,low,high))
        self.assertFalse(t.entry_admits(low,low,high))
