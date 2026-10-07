"""Earlier indirect store origins, guards, complete inventory and placements."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_early_writes as p
from windows_enclave_sha2_early_calls_tests import EarlyCallTests, EarlyCallSavedTests


class EarlyWriteTests(EarlyCallTests):
    def test_origin_dominance_requires_reachability_and_rejects_side_entry(self):
        edges={0:[1],1:[2,3],2:[4],3:[4],4:[],5:[]}
        p.dominates(edges,0,1,4)
        for guard,target in ((2,4),(1,5)):
            with self.assertRaises(ValueError):p.dominates(edges,0,guard,target)
        with self.assertRaises(ValueError):p.dominates(edges|{0:[1,3]},0,1,4)

    def test_success_edge_is_not_just_presence_of_a_compare(self):
        edges={0:[1],1:[5,2],2:[3],3:[4],4:[],5:[]}
        p.success_edge(edges,0,1,4)
        for changed in (edges|{0:[1,4]},edges|{5:[4]},edges|{1:[5]}):
            with self.assertRaises(ValueError):p.success_edge(changed,0,1,4)

    def test_earlier_cfg_rejects_unknown_destinations_and_reachable_falloff(self):
        lines=['entry:','jne exit','jmp entry','exit:','retq','.seh_endproc']
        self.assertEqual(p.reachable(p.graph(lines,{}),0),set(range(5)))
        for changed,tables in ((['entry:','jmp missing'],{}),(['entry:','jmpq *%rax'],{}),
                               (['entry:','jmpq *%rax'],{1:['missing']})):
            with self.assertRaises(ValueError):p.graph(changed,tables)
        with self.assertRaises(ValueError):p.reachable(p.graph(['entry:','nop'],{}),0)

    def test_conditional_earlier_store_placement_rejects_overlap_and_bad_extents(self):
        layout={'frame':dict(root='resident-frame',offset=-1136,bounds=[-128,1064]),
                'workspace':dict(root='resident-frame',offset=7200,bounds=[0,5760])}
        rows=[dict(line=1,object='workspace',span=[512,768])]
        self.assertTrue(p.compose(rows,layout)['conditional_effects_disjoint'])
        for slot in (920,960,984,1040,1048,1168,1176):
            with self.assertRaises(ValueError):p.compose([dict(line=1,object='frame',span=[slot,slot+8])],layout)
        for span in ([-1,1],[0,5761],[5,4]):
            with self.assertRaises(ValueError):p.compose([dict(line=1,object='workspace',span=span)],layout)
        bad=copy.deepcopy(layout);bad['workspace']['offset']=-152
        with self.assertRaises(ValueError):p.compose([dict(line=1,object='workspace',span=[0,8])],bad)


class EarlyWriteSavedTests(EarlyCallSavedTests):
    def early_write_fixture(self):
        import windows_enclave_sha2_vector_stack as vector
        row,asm,_,place,_=self.helper_slot_fixture();bodies=row[-1]
        early=vector.early_callbacks(bodies,asm,p.s.one(bodies,r'^_RNC.*Owner6digests2_0'))
        return row,asm,early,place['placements']

    def test_actual_earlier_indirect_stores_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,*args=self.early_write_fixture();lane,pin,_,_,_,_,bodies=row
        result=p.inspect(bodies,*args);rows=result['indirect_stores']
        self.assertEqual(len(rows),34)
        self.assertEqual({root:sum(v['object']==root for v in rows) for root in ('frame','workspace','control')},
                         {'frame':21,'workspace':9,'control':4})
        self.assertEqual(result['initialization_index']['range'],[0,3])
        self.assertTrue(result['placement']['conditional_effects_disjoint'])
        self.assertTrue(result['callee_argument_effects_pending']);self.assertFalse(result['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('earlier stores failed')) as check:
            with self.assertRaisesRegex(ValueError,'earlier stores failed'):
                parent.inspect_route(self.saved,self.root,lane,pin,False)
            check.assert_called_once()

    def test_actual_earlier_store_origins_widths_and_induction_mutations(self):
        row,*args=self.early_write_fixture();bodies=row[-1];result=p.inspect(bodies,*args)
        name=result['function'];lines=p.s.lines(bodies[name]);changes=[]
        for row in result['indirect_stores']:
            at=row['line'];changed=lines[:];changed[at]='nop';changes.append(changed)
            changed=lines[:];changed[at]=changed[at].replace('%r13)', '%r14)').replace('%rcx)', '%r14)')
            changed[at]=changed[at].replace('%rdx)', '%r14)').replace('%rax,%r15,8)', '%rax,%r15,4)')
            self.assertNotEqual(changed[at],lines[at]);changes.append(changed)
        index=result['initialization_index']
        edits={index['entry']:'movl $1, %r12d',index['increment']:'addq $2, %r12',
               index['increment']+1:'cmpq $5, %r12',index['increment']+2:'jne .B126',
               index['save']:'movq %r13, 1024(%rbp)',index['load']:'movq 1016(%rbp), %r8',
               index['restore']:'movq %rax, %r12',index['load']+2:'shlq $5, %rcx'}
        for at,text in edits.items():
            changed=lines[:];changed[at]=text;changes.append(changed)
        for at,line in enumerate(lines):
            if line=='leaq -88(%rbp), %r13':
                changed=lines[:];changed[at]='leaq 920(%rbp), %r13';changes.append(changed)
        guard=p.o.unique(lines,'movzbl (%rax,%r13), %r15d')+2
        for at,text in ((guard-1,'cmpq $4, %r15'),(guard,'jb .B228')):
            changed=lines[:];changed[at]=text;changes.append(changed)
        for label in ('.B104:','.B102:','.B103:'):
            # Add a real alternate entry, not merely an unused label.
            changed=lines[:1]+['jne '+label[:-1]]+lines[1:];changes.append(changed)
        for changed in changes:
            # Insertions change interval positions; recalculate this public
            # boundary, without re-running parent checks that could mask ours.
            early=args[1]|{'begin':changed.index('leaq 512(%rdi), %rax')+2,
                           'end':changed.index('.B182:')}
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},args[0],early,args[2])
        self.assertEqual(len(changes),83)
        print('Earlier indirect store/origin/index/guard mutations rejected: '+str(len(changes)))

    def test_actual_earlier_writes_reject_unlisted_memory_effect_and_guard_bypass(self):
        row,*args=self.early_write_fixture();bodies=row[-1];result=p.inspect(bodies,*args)
        name=result['function'];lines=p.s.lines(bodies[name])
        at=p.o.unique(lines,'movq %r12, 4544(%rax,%r15,8)');changes=[]
        changes.append(lines[:at]+['movq %rcx, (%r11)']+lines[at:])
        changes.append(lines[:at]+['movb $0, %r15b']+lines[at:])
        # Reach the offset store without crossing the successful guard edge.
        changed=lines[:at]+['bypass:']+lines[at:]
        changes.append(changed[:1]+['jne bypass']+changed[1:])
        # A head that dominated the first iteration does not prove that a
        # later exhausted index cannot branch directly into the save path.
        at=result['initialization_index']['save']
        changed=lines[:at]+['bypass_save:']+lines[at:]
        exit_at=changed.index('.B126:')+1
        changes.append(changed[:exit_at]+['jne bypass_save']+changed[exit_at:])
        for changed in changes:
            early=args[1]|{'begin':changed.index('leaq 512(%rdi), %rax')+2,
                           'end':changed.index('.B182:')}
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},args[0],early,args[2])
        self.assertEqual(len(changes),4)
