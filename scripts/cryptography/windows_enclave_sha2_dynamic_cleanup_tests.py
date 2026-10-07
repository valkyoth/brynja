"""Nonvacuous bounds, aggregate-copy and descriptor-lifetime regressions."""
from unittest.mock import patch
import re
import windows_enclave_sha2_dynamic_cleanup as p
r=p.r


class DynamicCleanupTests:
    def test_dynamic_cleanup_direct_lifetime_rejects_partial_unknown_and_bypass_writes(self):
        lines=['entry:','movq %rax, 64(%rbp)','movq 64(%rbp), %rcx','retq']
        def check(code,init=1,read=2):
            return r.lifetime(code,p.g.graph(code,{}),{'rbp':(0,0),'rsp':(-128,-128)},
                {'d':(64,80)},{init:[('d',None)]},{read:['d']})
        self.assertEqual(check(lines)[0]['required_read_sites'],[2])
        for write in ('movb $0, 79(%rbp)','movq %rax, 63(%rbp)',
                      'movq %rax, 192(%rsp)','movq %rax, (%rbp,%rsi,8)'):
            with self.assertRaises(ValueError):check(lines[:2]+[write]+lines[2:],read=3)
        check(lines[:2]+['movq %rax, 80(%rbp)']+lines[2:],read=3)
        bad=lines[:1]+['jne use']+lines[1:2]+['use:']+lines[2:]
        with self.assertRaises(ValueError):check(bad,init=2,read=4)

    def test_dynamic_cleanup_copy_needs_source_and_cannot_initialize_before_final_store(self):
        lines=['entry:','movq %rax, 64(%rbp)','movq %rax, 96(%rbp)','retq']
        graph=p.g.graph(lines,{})
        def check(init,reads):return r.lifetime(lines,graph,{'rbp':(0,0)},
            {'a':(64,80),'b':(96,112)},init,reads)
        check({1:[('a',None)],2:[('b','a')]},{3:['b']})
        for init,reads in [({2:[('b','a')]},{3:['b']}),
            ({1:[('a',None)],2:[('b','a')]},{2:['b']}),({1:[('a',None)]},{3:['b']})]:
            with self.assertRaises(ValueError):check(init,reads)

    def test_dynamic_cleanup_rejects_stale_descriptor_on_loop_backedge(self):
        lines=['entry:','movq %rax, 64(%rbp)','read:','movq 64(%rbp), %rcx',
               'movb $0, 71(%rbp)','jne read','retq']
        with self.assertRaises(ValueError):r.lifetime(lines,p.g.graph(lines,{}),{'rbp':(0,0)},
            {'d':(64,80)},{1:[('d',None)]},{3:['d']})

    def test_dynamic_cleanup_flag_is_checked_on_each_path_not_as_global_fact(self):
        lines=['entry:','movb $0, 8(%rbx)','jne done','movq %rax, 64(%rbx)',
               'movb $1, 8(%rbx)','done:','callq cleanup','retq']
        def check(code):return r.lifetime(code,p.g.graph(code,{}),{'rbx':(0,0)},
            {'d':(64,80)},{3:[('d',None)]},{},flags=(8,),guarded={6:[('d',8)]})
        check(lines)
        for at,line in [(1,'movb $1, 8(%rbx)'),(1,'movb %al, 8(%rbx)'),
                        (4,'movb %al, 8(%rbx)')]:
            bad=lines[:];bad[at]=line
            with self.assertRaises(ValueError):check(bad)
        # If the guard remains false, this helper does not claim the destructor
        # runs: skipped cleanup needs the enclosing cleanup-coverage review.
        bad=lines[:];bad[4]='movb $1, 71(%rbx)';check(bad)


class DynamicCleanupSavedTests:
    def cleanup_rows(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.routes:
            if row[0].startswith('simd'):
                yield row[0],row[1],parent.load(self.saved,self.root,row[1])[3],row[-1]

    def test_actual_dynamic_cleanup_complete_inventory_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for lane,pin,asm,bodies in self.cleanup_rows():
            report=p.inspect(bodies,asm,lane)
            self.assertEqual(report['dynamic_sites'],3 if lane=='simd256' else 2)
            self.assertTrue(report['normal_direct_descriptor_write_lifetimes_checked'])
            self.assertFalse(report['descriptor_bounds_fully_qualified'])
            self.assertTrue(report['destructor_invocation_and_unwind_lifetime_join_pending'])
            with patch.object(p,'inspect',side_effect=ValueError('dynamic cleanup failed')) as check:
                with self.assertRaisesRegex(ValueError,'dynamic cleanup failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_dynamic_cleanup_loop_bounds_pointer_pair_advances_and_entry_mutants(self):
        count=0
        for lane,_,asm,bodies in self.cleanup_rows():
            result=p.inspect(bodies,asm,lane)
            sites=[(result['function'],v) for v in result['loops']]
            sites.append((result['destructor']['function'],result['destructor_loop']))
            for name,site in sites:
                lines=p.s.lines(bodies[name]);replacements=[]
                for at in range(site['seed'],site['exit']):
                    text=lines[at]
                    if text.startswith('cmpq $'):replacements.append((at,text.replace('$128','$144').replace('$64','$80')))
                    if text.startswith('addq $16'):replacements.append((at,text.replace('$16','$32')))
                    if text.startswith('testq %'):replacements.append((at,'testl %edx, %edx'))
                    if text.startswith('movq ') and text.endswith('%rdx'):
                        replacements.append((at,text.replace('8(', '16(').replace('872(', '880(').replace('2920(', '2928(').replace('824(', '832(')))
                for at,text in replacements:
                    bad=lines[:];bad[at]=text
                    with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane)
                    count+=1
                head=next(v[:-1] for v in lines[site['seed']:site['exit']] if v.endswith(':'))
                bad=lines[:site['seed']]+['jne '+head]+lines[site['seed']:]
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane)
                count+=1
        self.assertEqual(count,45)
        print('Dynamic clearing loop mutants rejected: '+str(count))

    def test_actual_dynamic_cleanup_lifetime_and_return_copy_mutants(self):
        count=0
        for lane,_,asm,bodies in self.cleanup_rows():
            result=p.inspect(bodies,asm,lane);name=result['function'];lines=p.s.lines(bodies[name])
            init=result['construction'][1] if lane=='simd256' else result['argument_copy'][1]
            base,off=('rbx',864) if lane=='simd256' else ('rbp',816)
            for write in (f'movb $0, {off+15}(%{base})',f'movq %rax, {off-1}(%{base})',
                          f'movq %rax, (%{base},%rsi,8)'):
                bad=lines[:init+1]+[write]+lines[init+1:]
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane)
                count+=1
            for item in result['copies']:
                owner=name if lane=='simd256' or item is result['copies'][0] else result['parent']
                code=p.s.lines(bodies[owner]);at=item['first_line']
                bad=code[:];bad[at]=re.sub(r'\d+(?=\(%rb[px]\))',
                    lambda m:str(int(m[0])+1),bad[at],count=1)
                self.assertNotEqual(bad[at],code[at])
                with self.assertRaises(ValueError):p.inspect(bodies|{owner:'\n'.join(bad)},asm,lane)
                count+=1
        self.assertEqual(count,11)

    def test_actual_wide_overflow_outside_slice_is_not_reported_absent(self):
        import windows_enclave_sha2_wide_failstop as f
        lane,_,asm,bodies=next(v for v in self.cleanup_rows() if v[0]=='simd512')
        result=f.inventory(bodies,asm)
        self.assertEqual(result['whole_function_overflow_paths'],1)
        self.assertTrue(result['admitted_input_unreachability_join_pending'])
        name=result['function'];lines=p.s.lines(bodies[name]);at=result['terminal_call']
        for where,text in [(at+1,'retq'),(result['guard']-1,'cmpb $8, %bl'),(at,'callq returning')]:
            bad=lines[:];bad[where]=text
            with self.assertRaises(ValueError):f.inventory(bodies|{name:'\n'.join(bad)},asm)
        bad=lines[:1]+['jne .B302']+lines[1:]
        with self.assertRaises(ValueError):f.inventory(bodies|{name:'\n'.join(bad)},asm)

    def test_actual_dynamic_cleanup_active_handler_pointer_and_flag_mutants(self):
        count=0
        for lane,_,asm,bodies in self.cleanup_rows():
            report=p.inspect(bodies,asm,lane)
            self.assertEqual(len(report['direct_write_lifetime']['guarded_invoke_sites']),
                             9 if lane=='simd256' else 10)
            for handler,item in report['unwind_requirements']['handlers'].items():
                lines=p.s.lines(bodies[handler]);at=item['call']-1;bad=lines[:]
                bad[at]=bad[at].replace(str(item['descriptor_offset']),str(item['descriptor_offset']+8))
                with self.assertRaises(ValueError):p.inspect(bodies|{handler:'\n'.join(bad)},asm,lane)
                count+=1
                if item['flag_offset'] is not None:
                    bad=lines[:];bad[item['call']-2]=bad[item['call']-2].replace('je','jne')
                    with self.assertRaises(ValueError):p.inspect(bodies|{handler:'\n'.join(bad)},asm,lane)
                    count+=1
            name=report['function'];lines=p.s.lines(bodies[name])
            annotations=[i for i,line in enumerate(lines) if line.startswith('.Ltmp')]
            bad=lines[:];bad[annotations[0]]='.Ltmp999:'
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane)
            count+=1
        self.assertEqual(count,6)
