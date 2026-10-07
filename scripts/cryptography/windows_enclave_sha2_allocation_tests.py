"""Physical extent, caller stack, pointer-origin and resident-lifetime regressions."""
from unittest.mock import patch
import windows_enclave_sha2_allocation_lifetimes as p
g=p.stack


class AllocationTests:
    def test_allocation_extent_checks_include_type_empty_and_overlap_boundaries(self):
        self.assertEqual(p.interval(24,288,4096),[24,312])
        p.disjoint([[0,24],[24,312],[312,4096]])
        for args in ((True,8,4096),(0,False,4096),(0,1,True),(-1,8,4096),(24,0,4096),
                     (24,4073,4096),(1<<64,1,(1<<64)-1)):
            with self.assertRaises(ValueError):p.interval(*args)
        for ranges in ([[0,24],[23,312]],[[4,4]],[[8,4]],[[False,4]]):
            with self.assertRaises(ValueError):p.disjoint(ranges)

    def test_allocation_guard_requires_real_dominating_edge(self):
        graph={0:[1],1:[2,4],2:[3],3:[],4:[]}
        g.require_edge(graph,0,3,(1,2))
        for changed in (graph|{0:[1,3]},graph|{4:[3]}):
            with self.assertRaises(ValueError):g.require_edge(changed,0,3,(1,2))
        with self.assertRaises(ValueError):g.require_edge(graph,0,99,(1,2))
        with self.assertRaises(ValueError):g.require_edge(graph,0,3,(0,3))

    def test_allocation_stack_requires_matched_live_frames_and_home_area(self):
        lines=['entry:','pushq %rbx','subq $32, %rsp','callq child','addq $32, %rsp','popq %rbx','retq']
        for residue in (8,24):
            result=g.inspect('\n'.join(lines),'',residue)
            self.assertEqual(result['low'],-40)
        mutations=[lines[:3]+[text]+lines[3:] for text in
                   ('movl $0, %esp','incq %rsp','xchgq %rsp, %rax','popq %rdi')]
        mutations += [lines[:1]+['jne entered']+lines[1:3]+['entered:']+lines[3:],
                      [v.replace('$32','$16') for v in lines],
                      [v.replace('popq %rbx','popq %rsi') for v in lines],
                      lines[:-1]+['retq $8']]
        for bad in mutations:
            with self.assertRaises(ValueError):g.inspect('\n'.join(bad),'',8)

    def test_allocation_probe_and_frame_restore_cannot_be_bypassed(self):
        lines=['entry:','pushq %rbp','pushq %rbx','movl $40, %eax','callq __chkstk',
               'subq %rax, %rsp','leaq 128(%rsp), %rbp','andq $-32, %rsp','movq %rsp, %rbx',
               'callq child','leaq -88(%rbp), %rsp','popq %rbx','popq %rbp','retq']
        # Actual selected resident allocations exceed the RBP offset; this
        # synthetic positive uses the same restore arithmetic with 168 bytes.
        lines[3]='movl $168, %eax';lines[10]='leaq 40(%rbp), %rsp'
        g.inspect('\n'.join(lines),'',8)
        for text in ('movb $0, %bpl','movl $0, %ebx','movq %rax, %rsp'):
            with self.assertRaises(ValueError):g.inspect('\n'.join(lines[:9]+[text]+lines[9:]),'',8)
        bad=lines[:1]+['jne allocation']+lines[1:5]+['allocation:']+lines[5:]
        with self.assertRaises(ValueError):g.inspect('\n'.join(bad),'',8)

    def test_allocation_pointer_origins_include_partial_and_call_clobbers(self):
        lines=['entry:','movq %rdx, %rsi','again:','leaq 1024(%rsi), %rdx',
               'callq copy','jne again','retq']
        g.pointer_origin(lines,g.edges(lines,''),4,'rdx','rdx',1024)
        for text in ('movb $0, %sil','movq %rax, %rsi','leaq 8(%rsi), %rsi',
                     'xchgq %rsi, %rax','lodsq'):
            bad=lines[:3]+[text]+lines[3:]
            with self.assertRaises(ValueError):g.pointer_origin(bad,g.edges(bad,''),5,'rdx','rdx',1024)
        bad=['entry:','movq %rdx, %r8','callq unknown','movq %r8, %rdx','callq copy','retq']
        with self.assertRaises(ValueError):g.pointer_origin(bad,g.edges(bad,''),4,'rdx','rdx')

    def test_allocation_pointer_origins_follow_all_branches_not_dead_predecessors(self):
        lines=['entry:','movq %rdx, %rsi','jmp use','dead:','movq %rax, %rsi',
               'use:','movq %rsi, %rdx','callq copy','retq']
        g.pointer_origin(lines,g.edges(lines,''),7,'rdx','rdx')
        bad=lines[:2]+['jne dead']+lines[2:]
        with self.assertRaises(ValueError):g.pointer_origin(bad,g.edges(bad,''),8,'rdx','rdx')

    def test_allocation_no_unassigned_fallthrough_or_extra_probe(self):
        for lines in (['entry:','jne escaped','retq','escaped:'],
                      ['entry:','callq __chkstk','retq'],
                      ['entry:','movl $32, %eax','callq __chkstk','retq']):
            with self.assertRaises(ValueError):g.inspect('\n'.join(lines),'',8)


class AllocationSavedTests:
    def allocation_rows(self):return [row for row in self.routes if row[0].startswith('simd')]

    def allocation_assembly(self,row):
        import windows_enclave_sha2_batch_chains as parent
        return parent.load(self.saved,self.root,row[1])[3]

    def test_actual_allocation_joins_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.allocation_rows():
            lane,pin,*_=row;bodies=row[-1];r=p.inspect(bodies,self.allocation_assembly(row),lane)
            self.assertEqual(r['publication']['metadata_references'],19)
            self.assertEqual(r['publication']['metadata_writes'],5)
            self.assertEqual(r['lifetime_edges']['admission_edges'],15)
            self.assertEqual(len(r['stack_geometry']['alignment_cases']),2)
            self.assertEqual(len(r['caller_bridge']['copy_destination_origins']),9 if lane=='simd256' else 5)
            self.assertTrue(r['conditional_physical_separation']);self.assertFalse(r['whole_frame_qualified'])
            with patch.object(p,'inspect',side_effect=ValueError('allocation composition failed')) as check:
                with self.assertRaisesRegex(ValueError,'allocation composition failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_allocation_stack_and_anchor_mutations_reject(self):
        count=0
        for row in self.allocation_rows():
            lane=row[0];bodies=row[-1];assembly=self.allocation_assembly(row)
            for name in ('RetainedWork',p.worker.role(bodies,'receive'),p.authority.role(bodies,'resident')):
                lines=p.s.lines(bodies[name]);end=lines.index('.seh_endprologue')
                for text in ('movl $0, %esp','incq %rsp','xchgq %rsp, %rax','popq %rbx'):
                    changed=lines[:end+1]+[text]+lines[end+1:]
                    with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},assembly,lane)
                    count+=1
            name=p.authority.role(bodies,'resident');lines=p.s.lines(bodies[name]);at=lines.index('movq %rsp, %rbx')
            for text in ('movb $0, %bpl','movl $0, %ebx','leaq 127(%rsp), %rbp'):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(lines[:at+1]+[text]+lines[at+1:])},assembly,lane)
                count+=1
        self.assertEqual(count,30);print('Physical allocation stack/anchor mutations rejected: '+str(count))

    def test_actual_allocation_global_publication_escape_and_retirement_mutations_reject(self):
        count=0
        for row in self.allocation_rows():
            lane=row[0];bodies=row[-1];assembly=self.allocation_assembly(row);live,page=p.live_symbols(bodies)
            name=p.worker.role(bodies,'receive');lines=p.s.lines(bodies[name])
            for text in (f'movq $0, {live}+16(%rip)',f'leaq {live}(%rip), %rax',
                         f'movb $1, {page}(%rip)',f'movq $0, {live}(%rip)'):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(lines[:22]+[text]+lines[22:])},assembly,lane)
                count+=1
            lines=p.s.lines(bodies['RetainedWork'])
            for old,new in (('movq 80(%rsp), %rax','movq 72(%rsp), %rax'),
                            ('vmovaps 64(%rsp), %xmm0','vmovaps 48(%rsp), %xmm0'),
                            (f'movq %rdi, {page}(%rip)',f'movq %rsi, {page}(%rip)'),
                            ('cmpq $3, %rcx','cmpq $2, %rcx')):
                self.assertIn(old,lines);bad='\n'.join(lines).replace(old,new,1)
                with self.assertRaises(ValueError):p.inspect(bodies|{'RetainedWork':bad},assembly,lane)
                count+=1
        self.assertEqual(count,16);print('Resident publication/retirement mutations rejected: '+str(count))

    def test_actual_allocation_guard_bypasses_reject(self):
        count=0
        for row in self.allocation_rows():
            lane=row[0];bodies=row[-1];assembly=self.allocation_assembly(row)
            lines=p.s.lines(bodies['RetainedWork']);consumer=lines.index('callq '+p.worker.role(bodies,'receive'))
            # Jump directly into a later guard, so earlier contiguous shape
            # checks still exist but no longer dominate the actual consumer.
            for label in ('.B23:',):
                at=lines.index('.seh_endprologue')+1
                bad=lines[:at]+['jne '+label[:-1]]+lines[at:]
                with self.assertRaises(ValueError):p.inspect(bodies|{'RetainedWork':'\n'.join(bad)},assembly,lane)
                count+=1
            for at in (lines.index('.B17:'),lines.index(f'movq $0, {p.live_symbols(bodies)[0]}(%rip)')):
                bad=lines[:at]+['jmp use']+lines[at:consumer]+['use:']+lines[consumer:]
                with self.assertRaises(ValueError):p.inspect(bodies|{'RetainedWork':'\n'.join(bad)},assembly,lane)
                count+=1
        self.assertEqual(count,6)

    def test_actual_allocation_payload_pointer_redefinitions_reject(self):
        count=0
        for row in self.allocation_rows():
            lane=row[0];bodies=row[-1];assembly=self.allocation_assembly(row)
            name=p.worker.role(bodies,'receive');lines=p.s.lines(bodies[name])
            prefix='PublicSha'+('256' if lane=='simd256' else '512')+'SimdSource'
            at=lines.index('callq '+prefix)
            for text in ('movb $0, %sil','leaq 1(%rsi), %rsi','movq %rax, %rsi','movq %r8, %rsi'):
                bad=lines[:at]+[text]+lines[at:]
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},assembly,lane)
                count+=1
            r=p.inspect(bodies,assembly,lane)
            for copy in r['caller_bridge']['copy_destination_origins']:
                at=copy['call'];bad=lines[:at]+['incq %rdx']+lines[at:]
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},assembly,lane)
                count+=1
        self.assertEqual(count,22);print('Worker payload pointer mutations rejected: '+str(count))
