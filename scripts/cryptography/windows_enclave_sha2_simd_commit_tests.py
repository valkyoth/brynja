"""Bounded output preflight and symbolic descriptor-copy regressions."""
import re
from unittest.mock import patch
import windows_enclave_sha2_simd_commit as c
import windows_enclave_sha2_simd_moves as m


class CommitTests:
    def test_commit_widths_exclude_zero_and_match_each_family(self):
        for width in (*range(65536),(1<<32)-1,(1<<63),(1<<64)-1):
            self.assertEqual(c.width_allowed('simd256',width),width in (28,32))
            self.assertEqual(c.width_allowed('simd512',width),1<=width<=64)
        for lane,width in (('other',32),('simd256',True),('simd512',-1),('simd512',1<<64)):
            with self.assertRaises(ValueError): c.width_allowed(lane,width)

    def test_copy_gpr_aliases_preserve_low_writes_and_zero_high_dword(self):
        seed={('rbx',i):i+1 for i in range(8)}
        for op,reg,size in (('movb','%al',1),('movw','%ax',2),('movl','%eax',4)):
            code=['movq (%rbx), %rax',op+' 4(%rbx), '+reg,'movq %rax, 32(%rbx)']
            result=m.evaluate(code,seed)
            expected=list(range(5,5+size))+(list(range(size+1,9)) if size<4 else [0]*4)
            self.assertEqual([result['rbx',32+i] for i in range(8)],expected)
        for op,size in (('movzbl',1),('movzwl',2)):
            result=m.evaluate([op+' (%rbx), %eax','movq %rax, 32(%rbx)'],seed)
            self.assertEqual([result['rbx',32+i] for i in range(8)],list(range(1,size+1))+[0]*(8-size))

    def test_copy_vex_xmm_write_clears_upper_ymm(self):
        seed={('rbx',i):i+1 for i in range(64)}
        result=m.evaluate(['vmovups (%rbx), %ymm0','vmovups 32(%rbx), %xmm0',
                           'vmovups %ymm0, 64(%rbx)'],seed)
        self.assertEqual([result['rbx',64+i] for i in range(32)],list(range(33,49))+[0]*16)

    def test_copy_overlap_uses_original_loaded_bytes(self):
        seed={('rbx',i):i+1 for i in range(8)}
        result=m.evaluate(['movq (%rbx), %rax','movq %rax, 1(%rbx)'],seed)
        self.assertEqual([result['rbx',i] for i in range(9)],[1]+list(range(1,9)))

    def test_copy_unknown_origins_are_distinct_not_zero(self):
        result=m.evaluate(['movq (%rbx), %rax','movq %rax, 16(%rbx)',
                           'movq %rcx, 24(%rbx)'],{})
        self.assertEqual([result['rbx',16+i] for i in range(8)],[('memory','rbx',i) for i in range(8)])
        self.assertEqual([result['rbx',24+i] for i in range(8)],[('register','c',i) for i in range(8)])
        self.assertEqual(len(set(result.values())),16)

    def test_copy_unsupported_operations_and_address_rebinding_reject(self):
        for line in ('callq copy','jmp .B1','addq %rax, %rcx','movq (%rbx,%rax), %rcx',
                     'movq (%rdx), %rcx','movq (%rbx), (%rbp)','movq %eax, (%rbx)',
                     'movq (%rbx), %eax','movaps %xmm0, (%rbx)','vmovups %rax, (%rbx)',
                     'movq $0, %rax','movq %rax, %r16','vmovups %ymm16, (%rbx)'):
            with self.subTest(line=line),self.assertRaises(ValueError): m.evaluate([line],{})
        for reg in ('%rbx','%ebx','%bx','%bl','%rbp','%ebp','%rsi','%esi'):
            base='rbx' if reg.endswith(('bx','bl')) else 'rbp' if reg.endswith('bp') else 'rsi'
            _,width=m.register(reg);op='mov'+{8:'q',4:'l',2:'w',1:'b'}[width]
            source={8:'%rax',4:'%eax',2:'%ax',1:'%al'}[width]
            with self.assertRaises(ValueError):
                m.evaluate([f'{op} {source}, {reg}',f'movq (%{base}), %rax'],{})

    def test_copy_trace_requires_ordered_unique_complete_boundaries(self):
        first='movq (%rbx), %rax';last='movq %rax, 16(%rbx)'
        def check(lines): return m.trace('\n'.join(lines),first,last,('rbx',0),('rbx',16),8)
        self.assertEqual(check([first,last])['bytes'],8)
        for lines in ([last,first],[first,first,last],[first,last,last],[first],
                      [first,'movl 8(%rbx), %eax',last]):
            with self.assertRaises(ValueError): check(lines)
        with self.assertRaises(ValueError):
            m.trace(first+'\n'+last,first,last,('rbx',0),('rbx',16),9)


class CommitSavedTests:
    def test_saved_byte_provenance_check_is_required_with_exact_transfer_extents(self):
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            review=c.inspect(bodies,lane)
            self.assertEqual([(r['bytes'],r['moves']) for r in review['returned_descriptor_moves']],
                             [(136,34)] if lane=='simd256' else [(72,6),(72,15)])
            self.assertTrue(review['descriptor_integrity_across_inner_computation_pending'])
            self.assertFalse(review['whole_frame_qualified'])
            with patch.object(m,'trace',side_effect=ValueError('byte provenance failed')) as gate:
                with self.assertRaisesRegex(ValueError,'byte provenance failed'): c.inspect(bodies,lane)
                gate.assert_called_once()

    def test_output_commit_review_cannot_be_skipped(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            with patch.object(c,'inspect',side_effect=ValueError('commit review failed')) as gate:
                with self.assertRaisesRegex(ValueError,'commit review failed'):
                    chains.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()

    def test_saved_descriptor_trace_checks_every_returned_byte(self):
        count=0;actual=m.evaluate
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            traces=c.transfers(bodies,lane)
            for trace in traces:
                base,offset=trace['destination']
                for i in range(trace['bytes']):
                    def corrupt(code,seed):
                        result=actual(code,seed)
                        if (base,offset+i) in result: result[base,offset+i]=('corrupt',i)
                        return result
                    with patch.object(m,'evaluate',corrupt),self.assertRaises(ValueError):
                        c.transfers(bodies,lane)
                    count+=1
        self.assertEqual(count,280)
        print('SIMD returned descriptor-byte corruption rejected: '+str(count))

    def test_saved_descriptor_source_loads_cannot_shift_by_one_byte(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            for trace in c.transfers(bodies,lane):
                name=next(n for n,b in bodies.items() if trace['first'] in c.s.lines(b))
                lines=c.s.lines(bodies[name]);a=lines.index(trace['first']);b=lines.index(trace['last'])
                base,start=trace['source']
                for index in range(a,b+1):
                    match=re.fullmatch(r'(\w+) (-?\d*)\(%'+base+r'\), (%\w+)',lines[index])
                    if not match: continue
                    offset=int(match[2] or '0')
                    if not start<=offset<start+trace['bytes']: continue
                    bad=lines[:];bad[index]=f'{match[1]} {offset+1}(%{base}), {match[3]}'
                    with self.assertRaises(ValueError): c.transfers(bodies|{name:'\n'.join(bad)},lane)
                    count+=1
        self.assertEqual(count,13)
        print('SIMD descriptor source-load offset mutations rejected: '+str(count))
