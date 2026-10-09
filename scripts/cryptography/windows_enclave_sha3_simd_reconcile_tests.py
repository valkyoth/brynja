"""Nonvacuous whole-executor coverage and normal cleanup CFG regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_reconcile as t


class SimdReconcileModelTests:
    def test_simd_reconcile_loop_branch_and_cleanup_order(self):
        code=['work','branch','workspace','staging','retq','ud2']
        edges={0:[1],1:[0,2,5],2:[3],3:[4],4:[],5:[]}
        r=t.ordering(code,edges,{2},{3},{0})
        self.assertEqual(r['normal_returns'],[4]);self.assertEqual(r['terminal_traps'],[5])
        for at,targets in ((1,[4]),(2,[4]),(2,[0,4]),(1,[3]),(0,[]),(0,[99])):
            with self.assertRaises(ValueError):t.ordering(code,edges|{at:targets},{2},{3},{0})
        for workspace,staging,work in ((set(),{3},{0}),({2},set(),{0}),({2},{3},set()),
            ({2},{2},{0}),({2},{3},{0,2}),({2,99},{3},{0}),({2},{3},{0,4})):
            with self.assertRaises(ValueError):t.ordering(code,edges,workspace,staging,work)


class SimdReconcileSavedTests:
    def simd_reconcile_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
        mapping=dict(frame='public_framing',reject='admission_and_rejection',squeeze='lane_squeeze',
            absorb='lane_absorption',vector='vector_caller',scalar='scalar_fallback',output='output',terminal='terminal')
        reviews={key:r['simd_'+value] for key,value in mapping.items()}
        _,_,asm,_,_,b=self.routes['simd']
        return b,asm,reviews

    def test_simd_reconcile_complete_region_and_identity_mutations(self):
        b,asm,reviews=self.simd_reconcile_fixture();r=t.inspect(b,asm,reviews);count=0
        self.assertEqual(r['coverage']['positions'],1676)
        self.assertEqual(r['coverage']['region_count'],15)
        self.assertEqual(r['coverage']['uncovered_positions'],[])
        for key,field,lo,hi in t.REGIONS:
            for extent in ([lo+1,hi],[lo,hi-1],[lo-1,hi],[lo,hi+1]):
                bad=copy.deepcopy(reviews);bad[key][field]=extent
                with self.assertRaises(ValueError):t.inspect(b,asm,bad)
                count+=1
        for key in reviews:
            bad=copy.deepcopy(reviews)
            if key=='output':bad[key]['functions']['executor']='other'
            else:bad[key]['function']='other'
            with self.assertRaises(ValueError):t.inspect(b,asm,bad)
            with self.assertRaises(ValueError):t.inspect(b,asm,{k:v for k,v in reviews.items() if k!=key})
            count+=2
        with self.assertRaises(ValueError):t.inspect(b,asm,reviews|{'unknown':{}})
        self.assertEqual(count,76)
        print('Keccak executor coverage/identity mutations rejected: 77')

    def test_simd_reconcile_saved_tables_and_cfg_escape_mutations(self):
        b,asm,reviews=self.simd_reconcile_fixture();name=reviews['terminal']['function'];code=t.life.code(b[name])
        graph,tables=t.graph(code,asm)
        self.assertEqual(set(tables),{123,718,759});self.assertEqual(len(graph),1676)
        for at in tables:
            for line in ('jmpq *%rdx','jmp .B85','jmpq *%unassigned'):
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.graph(bad,asm)
        count=0
        for number,targets in ((0,t.TABLES[123][1]),(1,t.TABLES[718][1])):
            for label in set(targets):
                old=f'.long\t.LBB30_{label}-.LJTI30_{number}'
                self.assertIn(old,asm)
                with self.assertRaises(ValueError):t.graph(code,asm.replace(old,old.replace(f'_{label}-','_85-')))
                count+=1
        for at,line in ((32,'jmp .B999'),(32,'junknown .B75'),(0,'jmpq *%rax'),(587,'.B85:'),(1675,'nop')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.graph(bad,asm)
        self.assertEqual(count,12)
        print('Keccak assigned table/CFG mutations rejected: 26')

    def test_simd_reconcile_saved_cleanup_bypass_and_dirty_return(self):
        b,asm,reviews=self.simd_reconcile_fixture();name=reviews['terminal']['function'];code=t.life.code(b[name])
        edges,_=t.graph(code,asm);workspace={73,530,1588,1598};staging={533,1591,1601}
        work=set(range(74,510))|set(range(587,1586))
        r=t.ordering(code,edges,workspace,staging,work)
        self.assertEqual(r['reachable_states'],1676)
        self.assertEqual(r['reached_work_positions'],1435)
        # Skip each final wipe through the real CFG, not just a pin mismatch.
        for at in (530,533,1588,1591,1598,1601):
            incoming=[i for i,targets in edges.items() if at in targets]
            self.assertTrue(incoming)
            bad={i:[at+1 if x==at else x for x in targets] for i,targets in edges.items()}
            with self.assertRaises(ValueError):t.ordering(code,bad,workspace,staging,work)
        # A direct epilogue edge from each work position is always unsafe.
        for at in sorted(work):
            bad=code.copy();bad[at]='jmp .B85'
            with self.assertRaises(ValueError):t.ordering(bad,edges|{at:[575]},workspace,staging,work)
        # The trap is not a normal successful return or a wipe.
        bad=code.copy();bad[1467]='retq'
        with self.assertRaises(ValueError):t.ordering(bad,edges,workspace,staging,work)
        for at in (1602,1669):
            with self.assertRaises(ValueError):t.ordering(code,edges,workspace,staging,work|{at})
        print('Keccak cleanup bypass/dirty-return mutations rejected: 1444')

    def test_simd_reconcile_prerequisites_integration_and_scope(self):
        b,asm,reviews=self.simd_reconcile_fixture();r=t.inspect(b,asm,reviews)
        for key,field in (('reject','normal_rejection_clears_workspace_staging_then_destinations'),
            ('terminal','successful_report_after_workspace_and_staging_wipe'),
            ('output','all_four_source_extents_preflight_before_first_copy')):
            with patch.dict(reviews[key],{field:False}):
                with self.assertRaises(ValueError):t.inspect(b,asm,reviews)
        name=r['function'];code=t.life.code(b[name])
        for at in (73,530,533,1588,1591,1598,1601):
            bad=code.copy();bad[at]='nop'
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,reviews)
        for at in (531,1589,1599):
            bad=code.copy();bad[at]='movl $1023, %edx'
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,reviews)
        self.assertTrue(r['wipe_argument_provenance_still_required'])
        self.assertFalse(r['complete_machine_pointer_lifetimes_and_nonoverlap_qualified'])
        self.assertFalse(r['private_frame_and_exception_cleanup_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('reconciliation failed')) as check:
            with self.assertRaisesRegex(ValueError,'reconciliation failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
