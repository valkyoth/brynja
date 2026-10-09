"""Constructor admission/placement mutations; constructor internals stay open."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.start


class StartModelTests:
    def test_start_selector_exhausts_all_slot_and_completion_shapes(self):
        count=0
        for present in range(256):
            for done in range(256):
                pending=[i for i in range(8) if present&(1<<i) and not done&(1<<i)]
                expected=pending[0] if pending else None
                for slot in (*range(9),(1<<64)-1):
                    self.assertEqual(t.select(present,done,slot),slot if slot==expected else None)
                    count+=1
        self.assertEqual(count,655360)
        for args in ((-1,0,0),(256,0,0),(0,-1,0),(0,256,0),(0,0,-1),(0,0,1<<64),
                     (True,0,0),(0,False,0),(0,0,False)):
            with self.assertRaises(ValueError):t.select(*args)

    def test_start_geometry_keeps_homes_and_retained_state_distinct(self):
        for lane,width,overlap in (('scalar',1136,8),('avx2',992,0)):
            result=t.geometry(lane)
            self.assertEqual(result['home_offsets_from_entry'],[40,48,56])
            self.assertEqual(result['placement_bytes'],width)
            self.assertEqual(result['same_source_overlap_bytes'],overlap)
            self.assertTrue(result['destination_complete'])
            self.assertFalse(result['constructor_source_initialization_qualified'])
            self.assertFalse(result['stack_copy_erasure_qualified'])
        self.assertEqual([v['alignment_padding'] for v in t.geometry('avx2')['alignment_cases']],[16,0])


class StartTests:
    def start_fixture(self,lane):
        bodies,asm,ir,lane,_,storage,transitions,receiver=self.update_fixture(lane)
        return bodies,asm,ir,lane,storage,transitions,receiver

    def test_start_all_reviewed_instruction_positions_are_load_bearing(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,asm,_,_,bodies=self.routes[lane]
            n,_,covered=t.check_shapes(bodies,asm,lane);name=n['start'];lines=c.lifecycle.code(bodies[name])
            for at in covered:
                for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                    with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm,lane)
                    count+=1
        self.assertEqual(count,902)

    def test_start_identity_tables_are_complete_and_cannot_relabel(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,asm,_,_,bodies=self.routes[lane];number,targets=t.TABLES[lane];table=f'.LJTI{number}_0'
            definition=table+':\n'+''.join(f'\t.long\t.LBB{number}_{v}-{table}\n' for v in targets)
            self.assertIn(definition,asm)
            for target in targets:
                old=f'.long\t.LBB{number}_{target}-{table}'
                with self.assertRaises(ValueError):t.check_shapes(bodies,asm.replace(old,f'.long\t.LBB{number}_2-{table}'),lane)
                count+=1
            for bad in (asm.replace(table+':',table+'_missing:'),asm+'\n'+definition):
                with self.assertRaises(ValueError):t.check_shapes(bodies,bad,lane)
                count+=1
        self.assertEqual(count,20)

    def test_start_index_home_placement_and_cleanup_mutations(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,asm,_,_,bodies=self.routes[lane];n,_,_=t.check_shapes(bodies,asm,lane)
            name=n['start'];lines=c.lifecycle.code(bodies[name]);body='\n'.join(lines)
            scalar=lane=='scalar';owner,slot=('r13','rsi') if scalar else ('rsi','rdi')
            changes=[('movb $1, %r9b','movb $2, %r9b'),('callq '+n['operation'],'nop'),
                ('cmpq %'+slot+', %rcx','cmpq %rcx, %rcx'),
                ('cmpq $7, %rcx','cmpq $8, %rcx'),('sete %r8b','setne %r8b'),
                ('movl $7, %ecx','movl $8, %ecx'),('callq '+c.lifecycle.DROP[lane],'nop'),
                ('callq '+c.lifecycle.ZERO,'nop'),('movl $1024, %edx','movl $1023, %edx'),
                (f'movb $2, {c.lifecycle.LAYOUT[lane]["phase"]}(%{owner})',
                 f'movb $3, {c.lifecycle.LAYOUT[lane]["phase"]}(%{owner})')]
            changes+=([('movq 7296(%rsp), %rbx','movq 7288(%rsp), %rbx'),
                ('movups %xmm0, 1136(%r13)','movups %xmm0, 1137(%r13)'),
                ('movq %rsi, 8(%r13)','movq %rdi, 8(%r13)')]
                if scalar else [('movq 4872(%rbp), %r14','movq 4864(%rbp), %r14'),
                ('leaq 3945(%rsp), %rdx','leaq 3944(%rsp), %rdx'),
                ('movq %rdi, 2240(%rsi)','movq %rsi, 2240(%rsi)')])
            for old,new in changes:
                self.assertIn(old,body)
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm,lane)
                count+=1
            # A later constructor may not enter the middle of the checked admission prefix.
            at=lines.index('.B18:')+1;bad=lines.copy();bad[at]='jmp .B2'
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm,lane)
            count+=1
        self.assertEqual(count,28)

    def test_start_caller_lifecycle_and_storage_prerequisites(self):
        count=0
        for lane in ('scalar','avx2'):
            args=self.start_fixture(lane);result=t.inspect(*args)
            for index,path in ((5,('checked_next_sequence',)),(5,('phase_match_before_admission',)),
                (5,('unfinished_guard_clears_and_quarantines',)),(5,('functions','operation')),
                (4,('state_pointer_inside_owner',)),(4,('state_destructor','function')),
                (4,('state_destructor','typed_payload_cleanup_composed')),(6,('functions','start'))):
                bad=list(args);bad[index]=copy.deepcopy(args[index]);node=bad[index]
                for key in path[:-1]:node=node[key]
                node[path[-1]]=False
                with self.assertRaises(ValueError):t.inspect(*bad)
                count+=1
            for key in ('entire_start_body_qualified','constructor_internals_and_value_lifetimes_qualified',
                        'all_unwind_paths_qualified','private_frame_erasure_qualified','whole_image_qualified'):
                self.assertFalse(result[key])
        self.assertEqual(count,16)
        with patch.object(t,'inspect',side_effect=ValueError('start review failed')):
            with self.assertRaisesRegex(ValueError,'start review failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])

    def test_start_owner_and_u128_abis_are_not_weakened(self):
        count=0
        for lane in ('scalar','avx2'):
            args=self.start_fixture(lane);result=t.inspect(*args);ir=args[2]
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+result['function']+'(' in l)
            for old,new in (('noalias ',' '),('nofree ',' '),('nonnull ',' '),('align '+str(c.lifecycle.LAYOUT[lane]['align']),'align 1'),
                ('dereferenceable('+str(c.lifecycle.LAYOUT[lane]['size'])+')','dereferenceable(1)'),
                ('i128 noundef %3','i64 noundef %3'),('i128 noundef %4','i64 noundef %4'),
                ('i64 noundef %2','i64 %2'),('range(i8 -1, 7)','range(i8 -1, 8)')):
                self.assertIn(old,row);bad=list(args);bad[2]=ir.replace(row,row.replace(old,new))
                with self.assertRaises(ValueError):t.inspect(*bad)
                count+=1
        self.assertEqual(count,18)
