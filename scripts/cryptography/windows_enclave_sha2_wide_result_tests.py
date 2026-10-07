"""Normal-return discriminants cannot stand in for descriptor lifetime proofs."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha2_wide_result as p


class WideResultTests:
    def result_paths(self,lines):
        return p.return_paths(lines,p.g.graph(lines,{}),lines.index('copy:'),
                              lines.index('error:'),lines.index('tag:'))

    def test_wide_result_returns_require_copy_or_error_on_every_path(self):
        good=['entry:','jne error','copy:','tag:','jmp done','error:','done:','retq']
        self.assertEqual(self.result_paths(good)['normal_returns'],{'7':['error','result']})
        for index,line in [(1,'jne done'),(1,'jne tag'),(4,'retq')]:
            bad=good[:];bad[index]=line
            if index==4:
                # Returning after tag is valid; instead return after copy but
                # before the tag. The remaining event is still reachable.
                bad=good[:3]+['jne done']+good[3:]
            with self.assertRaises(ValueError):self.result_paths(bad)

    def test_wide_result_no_vacuous_return_or_unreachable_required_form(self):
        for lines in [
            ['entry:','jmp error','copy:','tag:','error:','retq'],
            ['entry:','jne error','copy:','tag:','jmp loop','error:','loop:','jmp loop']]:
            with self.assertRaises(ValueError):self.result_paths(lines)

    def test_wide_result_success_edge_only_initializes_its_own_branch(self):
        lines=['entry:','movq %rax, 64(%rbp)','jne error','read:','movq 96(%rbp), %rcx',
               'retq','error:','retq']
        def check(code,edge=(2,3),read=4):
            return p.r.lifetime(code,p.g.graph(code,{}),{'rbp':(0,0)},
                {'a':(64,80),'b':(96,112)},{1:[('a',None)]},{read:['b']},
                edge_initializers={edge:[('b','a')]})
        self.assertEqual(check(lines)[0]['conditional_initialization_edges'],[(2,3)])
        bad=lines[:];bad[-1]='jmp read'
        with self.assertRaises(ValueError):check(bad)
        with self.assertRaises(ValueError):check(lines,(2,4))
        bad=lines[:];bad[2]='jmp error'
        with self.assertRaises(ValueError):check(bad)

    def test_wide_result_edge_cannot_refresh_corrupted_source(self):
        lines=['entry:','movq %rax, 64(%rbp)','movb $0, 71(%rbp)','read:',
               'movq 96(%rbp), %rcx','retq']
        with self.assertRaises(ValueError):p.r.lifetime(lines,p.g.graph(lines,{}),{'rbp':(0,0)},
            {'a':(64,80),'b':(96,112)},{1:[('a',None)]},{4:['b']},
            edge_initializers={(2,3):[('b','a')]})


class WideResultSavedTests:
    def wide_result_fixture(self):
        import windows_enclave_sha2_batch_chains as parent
        row=next(v for v in self.routes if v[0]=='simd512');asm=parent.load(self.saved,self.root,row[1])[3]
        return row,asm,p.d.inspect(row[-1],asm,'simd512')

    def wide_result_mutants(self,selector,replacements=(),insertions=()):
        row,asm,_=self.wide_result_fixture();bodies=row[-1];name=p.s.one(bodies,selector)
        lines=p.s.lines(bodies[name]);changes=[]
        for at,text in replacements:
            bad=lines[:];bad[at]=text;changes.append(bad)
        for at,text in insertions:changes.append(lines[:at]+[text]+lines[at:])
        for bad in changes:
            with self.subTest(change=next((i,b) for i,(a,b) in enumerate(zip(lines,bad)) if a!=b)):
                changed=bodies|{name:'\n'.join(bad)}
                with self.assertRaises(ValueError):
                    prior=p.d.inspect(changed,asm,'simd512')
                    p.inspect(changed,asm,prior)
        return len(changes)

    def test_actual_wide_result_handoff_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm,prior=self.wide_result_fixture();result=p.inspect(row[-1],asm,prior)
        self.assertEqual(result['child']['return_paths']['normal_returns'],{'145':['error','result']})
        self.assertEqual(len(result['child']['stores']),11)
        self.assertEqual(result['parent']['normal_drops'],[571,590])
        self.assertEqual(result['parent']['direct_write_lifetime']['guarded_invoke_sites'],[479,576])
        self.assertEqual(result['parent']['success_edge'],[449,450])
        self.assertFalse(result['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('wide handoff failed')) as check:
            with self.assertRaisesRegex(ValueError,'wide handoff failed'):
                parent.inspect_route(self.saved,self.root,row[0],row[1],False)
            check.assert_called_once()

    def test_actual_wide_result_child_stores_origins_and_escape_mutants(self):
        row,asm,prior=self.wide_result_fixture();report=p.inspect(row[-1],asm,prior)['child']
        lines=p.s.lines(row[-1][report['function']]);replace=[]
        for record in report['stores']:
            at=record['line'];old=lines[at]
            altered=re.sub(r'(\d*)\(%rsi\)',lambda m:str(int(m[1] or '0')+1)+'(%rsi)',old)
            replace.append((at,altered))
        replace += [(28,'movq %rdx, %rsi'),(106,'movb $0, 96(%rsi)'),(1732,'movb $-1, 95(%rsi)')]
        insert=[(28,'movq %rcx, %rbx'),(32,'movq %r9, %r10'),(35,'movq %rsi, %rax'),
                (105,'movb $0, %sil'),(1717,'movb $0, %sil'),(1733,'movq %rsi, 32(%rbp)'),
                (1733,'movb $0, 7(%rsi)'),(1733,'movq %rax, (%rsi,%r8,8)')]
        count=self.wide_result_mutants(r'Executor13digest_secret$',replace,insert)
        self.assertEqual(count,22);print('Wide result stores/origins/escape mutants rejected: '+str(count))

    def test_actual_wide_result_child_early_return_and_copy_bypass_mutants(self):
        replace=[(106,'jmp .B22'),(1733,'jmp .B302')]
        insert=[(i,'retq') for i in (25,35,105,1717,1723)]
        insert += [(35,'jne .B22'),(1716,'jne .B22')]
        count=self.wide_result_mutants(r'Executor13digest_secret$',replace,insert)
        self.assertEqual(count,9)

    def test_actual_wide_result_parent_argument_tag_drop_and_guard_mutants(self):
        replace=[(439,'leaq 4648(%rbx), %rcx'),(442,'leaq 360(%rbx), %r9'),
                 (447,'movzbl 4735(%rbx), %ecx'),(448,'cmpb $0, %cl'),(449,'jne .B69'),
                 (569,'leaq 352(%rbx), %rcx'),(588,'leaq 4640(%rbx), %rcx'),
                 (476,'movb %al, 55(%rbx)')]
        insert=[(435,'movb $0, 415(%rbx)'),(435,'movq %rax, 351(%rbx)'),
                (450,'movb $0, 4647(%rbx)'),(465,'movb $0, 359(%rbx)'),
                (563,'movq %rax, (%rbx,%r8,8)'),(465,'movq %rax, %rbx'),
                (447,'movb $0, 4736(%rbx)'),(450,'retq')]
        count=self.wide_result_mutants(r'Resident6digest$',replace,insert)
        self.assertEqual(count,16);print('Wide parent argument/discriminant/drop mutants rejected: '+str(count))

    def test_actual_wide_result_requires_fresh_descriptor_prerequisites(self):
        row,asm,prior=self.wide_result_fixture()
        for key in ('normal_direct_descriptor_write_lifetimes_checked','exact_pointer_length_pair_and_all_loop_indices_checked'):
            bad=copy.deepcopy(prior);bad[key]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
        bad=copy.deepcopy(prior);bad['geometry']['exact_lane_pointers_and_widths']=False
        with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
