"""Regression coverage for narrow pointer origins and distinct slot lifetimes."""
from unittest.mock import patch
import windows_enclave_sha2_narrow_lifetimes as p


class NarrowLifetimeTests:
    def test_narrow_pointer_trace_requires_every_path_and_real_anchor(self):
        good=['entry:','movq %rdx, %r15','movq %r15, 88(%rbx)',
              'loop:','movq 88(%rbx), %r15','callq helper','jne loop','retq']
        def check(lines):
            st=p.o.definitions(lines,'entry',{},(88,),bases=p.n.BASES)
            use=lines.index('callq helper')
            return p.n.trace(lines,st,use,'r15',lambda site,loc:site==-1 and loc=='rdx',(88,))
        self.assertEqual(check(good),[-1])
        for changed in (good[:1]+['jne loop']+good[1:],good[:1]+good[2:],
                good[:3]+['movb $0, 95(%rbx)']+good[3:],
                good[:3]+['movq %rax, 87(%rsp)']+good[3:],
                good[:3]+['movb $0, -33(%rbp)']+good[3:],
                good[:5]+['cmovbq %rax, %r15']+good[5:],
                good[:5]+['movb $0, %r15b']+good[5:]):
            with self.assertRaises(ValueError):check(changed)
        check(good[:3]+['movb $0, 96(%rbx)']+good[3:])

    def test_narrow_pointer_trace_does_not_treat_volatile_call_result_as_input(self):
        lines=['entry:','movq %r9, %rax','callq helper','use:','retq']
        states=p.o.definitions(lines,'entry',{},bases=p.n.BASES)
        with self.assertRaises(ValueError):p.n.trace(lines,states,3,'rax',
            lambda site,loc:site==-1 and loc=='r9')
        # Exceptional stack probe preserves argument registers only when the
        # caller explicitly supplies its separately validated ABI contract.
        states=p.o.definitions(lines,'entry',{},bases=p.n.BASES,call_clobbers={2:{'rax'}})
        self.assertEqual(p.n.trace(lines,states,3,'r9',lambda site,loc:site==-1 and loc=='r9'),[-1])
        with self.assertRaises(ValueError):p.o.definitions(lines,'entry',{},call_clobbers={2:{'fake'}})

    def test_narrow_slot_read_inventory_includes_comparison_rmw_and_exposure(self):
        lines=['entry:','movq %rax, 112(%rbx)','movq 112(%rsp), %rcx',
               'cmpq $0, 112(%rbx)','addq $1, 112(%rbx)','leaq 112(%rbx), %r8','retq']
        self.assertEqual(p.n.reads(lines,112),[2,3,4,5])

    def test_narrow_slot_phases_do_not_preserve_pointer_fact_after_reuse(self):
        lines=['entry:','movq %r9, 112(%rbx)','movq 112(%rbx), %rax',
               'movq $0, 112(%rbx)','movq 112(%rbx), %rax','retq']
        states=p.o.definitions(lines,'entry',{},(112,),bases=p.n.BASES)
        anchor=lambda site,loc:site==-1 and loc=='r9'
        p.n.trace(lines,states,2,112,anchor,(112,))
        with self.assertRaises(ValueError):p.n.trace(lines,states,4,112,anchor,(112,))

    def test_narrow_guard_must_be_fresh_for_current_iteration(self):
        lines=['entry:','load:','movq %r9, %rax','cmpq $8, %rax','ja error',
               'use:','movq (%rax), %rcx','jne load','error:','retq']
        edges=p.g.graph(lines,{})
        p.g.success_edge(edges,2,4,6)
        changed=lines[:3]+['jne use']+lines[3:]
        with self.assertRaises(ValueError):p.g.success_edge(p.g.graph(changed,{}),2,5,7)


class NarrowLifetimeSavedTests:
    def narrow_fixture(self):
        import windows_enclave_sha2_batch_chains as parent
        row=next(v for v in self.routes if v[0]=='simd256')
        asm=parent.load(self.saved,self.root,row[1])[3]
        return row,asm

    def test_actual_narrow_pointer_lifetimes_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm=self.narrow_fixture();result=p.inspect(row[-1],asm,row[4])
        self.assertEqual(len(result['authority']['authority_reads']),11)
        self.assertEqual(len(result['authority']['authority_uses']),20)
        self.assertEqual(len(result['authority']['owner_reads']),6)
        self.assertEqual(result['scalar_inputs']['slot112_lifetimes'],
            {'counter':[879,885],'input':[1016,1034,1093],'output':[1376,1382]})
        self.assertEqual(result['input_consumers']['vector_gather_call'],865)
        self.assertEqual(result['reachable_instructions'],1655)
        self.assertTrue(result['input_fields_and_authority_field_integrity_against_aliases_required'])
        self.assertFalse(result['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('narrow lifetime failed')) as check:
            with self.assertRaisesRegex(ValueError,'narrow lifetime failed'):
                parent.inspect_route(self.saved,self.root,row[0],row[1],False)
            check.assert_called_once()

    def test_actual_narrow_authority_and_input_pointer_overwrites_reject(self):
        row,asm=self.narrow_fixture();bodies=row[-1];result=p.inspect(bodies,asm,row[4])
        name=result['function'];lines=p.s.lines(bodies[name]);changes=[]
        auth=result['authority']
        for slot,reads in ((88,auth['authority_reads']),(152,auth['owner_reads']),
                (112,result['scalar_inputs']['slot112_lifetimes']['input'])):
            for at in reads:
                for text in (f'movb $0, {slot+7}(%rbx)',f'movq %r11, {slot-1}(%rsp)'):
                    changes.append(lines[:at]+[text]+lines[at:])
        for at in (auth['owner_initializer'],auth['authority_initializer'],result['scalar_inputs']['initializer']):
            bad=lines[:];bad[at]='nop';changes.append(bad)
        for at in auth['authority_uses']:
            site,reg=at['line'],at['register']
            changes.append(lines[:site]+[f'movq %r11, %{reg}']+lines[site:])
        for slot in p.n.INPUTS:
            at=lines.index('.B14:')+1
            changes.append(lines[:at]+[f'movb $0, {slot+7}(%rbx)']+lines[at:])
        for changed in changes:
            with self.subTest(change=len(changed)):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},asm,row[4])
        self.assertEqual(len(changes),71)
        print('Narrow authority/input pointer overwrite mutations rejected: '+str(len(changes)))

    def test_actual_narrow_loop_bypass_reuse_and_index_mutations_reject(self):
        row,asm=self.narrow_fixture();bodies=row[-1];name=p.s.one(bodies,r'Resident6digest$')
        lines=p.s.lines(bodies[name]);changes=[]
        for original,replacement in (
            ('movq 8(%rax), %r15','movq 16(%rax), %r15'),
            ('movq -17(%rdi,%r15), %r13','movq -9(%rdi,%r15), %r13'),
            ('addq $24, %r15','addq $48, %r15'),('addq $40, %r12','addq $80, %r12'),
            ('cmpq $209, %r15','cmpq $233, %r15'),('addq $40, %rcx','addq $80, %rcx'),
            ('cmpq $320, %rcx','cmpq $360, %rcx'),('movq 544(%rbx,%rax), %rax','movq 552(%rbx,%rax), %rax'),
            ('movl $224, %eax','movl $0, %eax'),('cmpq $2272, %rax','cmpq $2528, %rax'),
            ('movb %r8b, 10784(%rbx,%rcx)','movb %r8b, 88(%rbx,%rcx)'),
            ('movq %r12, 7968(%rbx,%r15,8)','movq %r12, 88(%rbx,%r15,8)'),
            ('movq 112(%rbx), %rcx','movq 120(%rbx), %rcx'),
            ('leaq 7840(%rbx), %rax','leaq 7841(%rbx), %rax')):
            at=p.o.unique(lines,original);bad=lines[:];bad[at]=replacement;changes.append(bad)
        for label,target in (('.B2:','.B14'),('.B146:','.B151'),('.B146:','.B154'),
                              ('.B146:','.B163'),('.B4:','.B5'),('.B155:','.B155')):
            at=lines.index(label)+1
            changes.append(lines[:at]+['jne '+target]+lines[at:])
        for at,text in ((1050,'movq %r11, %rdi'),(1043,'movb $0, %dil'),(1083,'movb $0, %r12b'),
                       (120,'callq clobber'),(594,'jne .B75')):
            changes.append(lines[:at]+[text]+lines[at:])
        for index,changed in enumerate(changes):
            with self.subTest(mutant=index):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},asm,row[4])
        self.assertEqual(len(changes),25)
        print('Narrow lifetime/index/iteration bypass mutations rejected: '+str(len(changes)))

    def test_actual_narrow_operation_result_cannot_forge_original_owner(self):
        row,_=self.narrow_fixture();bodies=row[-1];name=p.s.one(bodies,r'Owner9operation$')
        lines=p.s.lines(bodies[name]);at=lines.index('movq %rbx, (%rsi)');changes=[]
        for text in ('movq %rdi, %rbx','movb $0, %bl','movq %rdi, %rsi',
                     'movb $0, -9(%rbp)'):
            # The saved owner is reloaded before this point; corrupt it before
            # both possible callback reload paths instead of after its last use.
            site=lines.index('movq %rbx, -16(%rbp)')+1 if '(%rbp)' in text else at
            changes.append(lines[:site]+[text]+lines[site:])
        bad=lines[:];bad[at+1]='movb $2, 8(%rsi)';changes.append(bad)
        for changed in changes:
            with self.assertRaises(ValueError):p.operation_result(bodies|{name:'\n'.join(changed)})

    def test_actual_narrow_transfer_arguments_cannot_lose_input_origin(self):
        row,asm=self.narrow_fixture();bodies=row[-1];name=p.s.one(bodies,r'Resident6digest$')
        lines=p.s.lines(bodies[name]);changes=[]
        for call in (865,1021,1048,1099):
            for text in ('movq %r11, %r8','callq unknown','movb $0, %r8b'):
                changes.append(lines[:call]+[text]+lines[call:])
        for at in (844,847,854,857):
            bad=lines[:];bad[at]='nop';changes.append(bad)
        for changed in changes:
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},asm,row[4])
        self.assertEqual(len(changes),16)
        print('Narrow input final-argument/guard mutations rejected: '+str(len(changes)))

    def test_actual_narrow_unwind_slots_bound_to_every_invoke_not_nounwind_calls(self):
        row,asm=self.narrow_fixture();bodies=row[-1];ir=row[4]
        name=p.s.one(bodies,r'Resident6digest$');lines=p.s.lines(bodies[name])
        states,edges,_=p.n.prepare(lines,asm,name)
        pointers=p.authority(lines,states,edges,bodies)
        result=p.unwind.inspect(bodies,asm,ir,lines,states,pointers)
        self.assertEqual(len(result['callsite_lifetimes']),11)
        count=0
        for call in result['callsite_lifetimes']:
            for slot in call['required_pointer_slots']:
                bad={k:dict(v) for k,v in states.items()};bad[call['call']][slot]={-1}
                with self.assertRaises(ValueError):p.unwind.inspect(bodies,asm,ir,lines,bad,pointers)
                count+=1
        # The unrelated shared cleanup block before authority initialization has
        # a nounwind zeroizer. It must not be falsely treated as an invoke.
        self.assertNotIn(374,[v['call'] for v in result['callsite_lifetimes']])
        body=p.unwind.function(ir,name)
        first=next(v for v in body if 'invoke ' in v)
        for changed in (ir.replace(first,first.replace('invoke ','call '),1),
                        ir.replace(first,first+'\n'+first,1)):
            with self.assertRaises(ValueError):p.unwind.inspect(bodies,asm,changed,lines,states,pointers)
        changed=lines[:];changed[lines.index('.Ltmp54:')]='.Ltmp1000:'
        with self.assertRaises(ValueError):p.unwind.inspect(bodies,asm,ir,changed,states,pointers)
        self.assertGreaterEqual(count,16)
        print('Narrow unwind pointer and invoke-population mutations rejected: '+str(count+3))
