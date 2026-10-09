"""Prefix byte origins, overlapping stores and retained constructor regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.avx2_cshake_moves


class Avx2CshakeMovesModelTests:
    def test_avx2_cshake_moves_origins_and_redundant_store_deletions(self):
        rejected=redundant=0
        # These stores are superseded by identical-origin writes. The byte model
        # accepts their removal; the emitted instruction contract still rejects it.
        overwritten={('copy','frame',a,'frame',b,n) for a,b,n in
            ((137,265,4),(141,269,1),(142,270,1),(143,271,8),(151,279,8),(159,287,1))}
        empty_overwritten={('copy','saved',a,'frame',b,n) for a,b,n in
            ((37,140,2),(39,142,1),(40,143,8),(48,151,8),(56,159,1))}
        for rate in (136,168):
            for name,custom in ((0,0),(1,0),(0,1),(1<<64,1<<80)):
                result=t.replay(rate,name,custom);steps=t.schedule(bool(name or custom))
                self.assertEqual(result['matching_prefix_overlap_bytes'],23)
                self.assertEqual(result['prefix_active_retained_span'],[2080,2155])
                self.assertEqual(result['retained_authority_span'],[1792,1800])
                self.assertFalse(result['padding_initialized']);self.assertFalse(result['local_and_staging_copy_erasure_qualified'])
                permitted=overwritten|(empty_overwritten if not (name or custom) else set())
                for at,step in enumerate(steps):
                    changed=steps[:at]+steps[at+1:]
                    if step in permitted:t.replay(rate,name,custom,changed);redundant+=1
                    else:
                        with self.assertRaises(ValueError):t.replay(rate,name,custom,changed)
                        rejected+=1
        self.assertEqual(rejected,374);self.assertEqual(redundant,58)
        print('AVX2 cSHAKE move deletions rejected / identical-origin redundant stores:',rejected,redundant)

    def test_avx2_cshake_moves_wrong_origins_domains_and_publication(self):
        count=0
        for rate in (136,168):
            for name,custom in ((0,0),(1,0),(0,1)):
                steps=t.schedule(bool(name or custom));at=steps.index(('replace_prefix',))
                for extra in (('publish',),('destroy',),('accept_final',),('state_ready',),
                    ('copy','frame',304,'frame',305,80),('copy','frame',304,'frame',31,1),
                    ('copy','frame',4888,'saved',0,1),('copy','frame',304,'saved',64,1),
                    ('copy','frame',304,'owner',1215,1),('copy','frame',304,'owner',2208,1),
                    ('copy','frame',304,'frame',1280,8),('copy','frame',379,'saved',0,1)):
                    with self.assertRaises(ValueError):t.replay(rate,name,custom,steps[:at]+[extra]+steps[at:])
                    count+=1
                targets=[('copy','frame',705,'frame',2976,943),('copy','frame',265,'frame',1610,32),
                    ('copy','frame',84,'frame',1647,1),('copy','frame',672,'frame',608,8),
                    ('copy','saved',8,'owner',2160,8)]
                for old in targets:
                    self.assertIn(old,steps);new=list(old);new[2]+=1
                    with self.assertRaises(ValueError):t.replay(rate,name,custom,[tuple(new) if v==old else v for v in steps])
                    count+=1
                for field in (1664,1665,1666):
                    old=next(v for v in steps if v[:3]==('literal','frame',field))
                    new=old[:3]+(old[3]^1,)
                    with self.assertRaises(ValueError):t.replay(rate,name,custom,[new if v==old else v for v in steps])
                    count+=1
                with self.assertRaises(ValueError):t.replay(rate,name,custom,steps+[('destroy',)])
                count+=1
        self.assertEqual(count,126)
        print('AVX2 cSHAKE move pointer/domain/order mutants rejected:',count)


class Avx2CshakeMovesTests:
    def test_avx2_cshake_moves_complete_start_coverage_and_instruction_mutants(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,covered,total=t.check(bodies,asm)
        self.assertEqual(len(covered),130);self.assertEqual(total,list(range(597)))
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in covered:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,260)
        print('AVX2 cSHAKE retained transfer instruction mutants rejected:',count)

    def test_avx2_cshake_moves_domain_padding_and_snapshot_mutants(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,_,_=t.check(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        changes=(('movq 160(%rsp), %rax','movq 161(%rsp), %rax'),
            ('movzbl 168(%rsp), %eax','movzbl 167(%rsp), %eax'),
            ('vmovups 265(%rsp), %ymm0','vmovups 264(%rsp), %ymm0'),
            ('movb %r13b, 1568(%rsp)','movb %r12b, 1568(%rsp)'),
            ('movl 80(%rsp), %eax','movl 79(%rsp), %eax'),
            ('movb $4, 1664(%rsp)','movb $31, 1664(%rsp)'),
            ('movl $31, %eax','movl $4, %eax'),('movb $5, %al','movb $3, %al'),
            ('cmpq $-1, %r14','cmpq $0, %r14'),('leaq 2976(%rsp), %rdx','leaq 2977(%rsp), %rdx'),
            ('movq 32(%rax), %rax','movq 33(%rax), %rax'),('cmovel %eax, %ecx','cmovnel %eax, %ecx'))
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check(bodies|{name:name+':\n'+body.replace(old,new)},asm)
        self.assertEqual(len(changes),12)

    def test_avx2_cshake_moves_prerequisites_and_integrated_failure(self):
        bodies,asm,ir,prior,construction,direct=self.avx2_cshake_fixture()
        initialized=c.avx2_cshake.inspect(bodies,asm,ir,prior,construction,direct)
        placement=self.start_fixture('avx2')[4]
        args=(bodies,asm,construction,initialized,placement);result=t.inspect(*args)
        self.assertTrue(result['avx2_start_instruction_coverage_complete'])
        self.assertTrue(result['cshake_constructor_transfer_origins_qualified'])
        self.assertFalse(result['all_constructor_paths_qualified']);self.assertFalse(result['private_frame_erasure_qualified'])
        paths=[(2,(k,)) for k in ('function','successful_placement_destroys_previous_typed_state_first',
            'successful_slot_and_phase_commit_after_state_copy')]
        paths += [(3,(k,)) for k in ('function','cshake_prefix_calls_and_failure_joins_qualified')]
        paths += [(3,('geometry','used_zero_preserved_by_engine_absorb'))]
        paths += [(4,('state_destructor',k)) for k in ('function','typed_payload_cleanup_composed')]
        for index,path in paths:
            changed=list(args);changed[index]=copy.deepcopy(changed[index]);node=changed[index]
            for key in path[:-1]:node=node[key]
            node[path[-1]]=False
            with self.assertRaises(ValueError):t.inspect(*changed)
        self.assertEqual(len(paths),8)
        with patch.object(c.avx2_cshake_moves,'inspect',side_effect=ValueError('AVX2 transfer failed')) as check:
            with self.assertRaisesRegex(ValueError,'AVX2 transfer failed'):
                c.inspect_route(self.saved,self.root,'avx2',self.spec['avx2'])
            check.assert_called_once()
