"""Unwind tables, complete handler bodies and actual guard-lifetime regressions."""
from unittest.mock import patch
import windows_enclave_sha3_simd_exception_effects as t


class SimdExceptionEffectsSavedTests:
    def simd_exception_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return b,asm,r['simd_digest'],r['simd_service_call_effects']

    def test_simd_exception_effects_final_health_cleanup_and_metadata(self):
        b,asm,*_=self.simd_exception_effects_fixture();n=t.names(b);r=t.health_cleanup(b,asm,n);count=0
        for at in range(len(r['handler_code'])):
            code=r['handler_code'].copy();code[at]='ud2'
            bad=b|{r['funclet']:r['funclet']+':\n'+'\n'.join(code)}
            with self.assertRaises(ValueError):t.health_cleanup(bad,asm,n)
            count+=1
        import re
        for label,fields in r['expected_tables'].items():
            for at in range(len(fields)):
                changed=fields.copy();changed[at]='0' if fields[at]!='0' else '1'
                pattern=r'(?m)^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)'
                bad=re.sub(pattern,lambda _:label+':\n'+''.join('\t.long\t'+v+'\n' for v in changed),asm)
                with self.assertRaises(ValueError):t.health_cleanup(b,bad,n)
                count+=1
        body=b[n['check']]
        for marker in ('.Ltmp44','.Ltmp45'):
            bad=b|{n['check']:body.replace(marker+':',marker+'_wrong:')}
            with self.assertRaises(ValueError):t.health_cleanup(bad,asm,n)
        bad=b|{n['check']:body.replace('.Ltmp44:','').replace('.Ltmp45:','.Ltmp44:\n.Ltmp45:')}
        with self.assertRaises(ValueError):t.health_cleanup(bad,asm,n)
        self.assertEqual(count,28)

    def test_simd_exception_effects_every_handler_and_destructor_instruction(self):
        b,asm,caller,services=self.simd_exception_effects_fixture();n=t.names(b);h,shapes=t.handlers(b,n)
        selected=shapes|{n['operation_drop']:t.operation_shape(n)};count=0
        for name,code in selected.items():
            for at in range(len(code)):
                bad=b|{name:name+':\n'+'\n'.join(code[:at]+['ud2']+code[at+1:])}
                with self.assertRaises(ValueError):t.inspect(bad,asm,caller,services)
                count+=1
        print('Keccak executor exception/destructor instruction mutations rejected:',count)

    def test_simd_exception_effects_table_fields_and_handler_order(self):
        b,asm,*_=self.simd_exception_effects_fixture();n=t.names(b);h,_=t.handlers(b,n)
        expected=t.tables(asm,n,h);count=0
        for label,fields in expected.items():
            for at in range(len(fields)):
                changed=fields.copy();changed[at]='0' if fields[at]!='0' else '1'
                import re
                pattern=r'(?m)^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)'
                bad=re.sub(pattern,lambda _:label+':\n'+''.join('\t.long\t'+v+'\n' for v in changed),asm)
                with self.assertRaises(ValueError):t.tables(bad,n,h)
                count+=1
        self.assertEqual(count,30)
        print('Keccak FH3 map field/order mutations rejected: 30')

    def test_simd_exception_effects_ip_markers_resolve_actual_instruction_positions(self):
        b,_,*_=self.simd_exception_effects_fixture();n=t.names(b);body=b[n['executor']];code=t.life.code(body)
        r=t.call_states(body,code)
        self.assertEqual(r['markers'],{'.Lfunc_begin30':0,'.Ltmp28':41,'.Ltmp29':45,
            '.Ltmp30':500,'.Ltmp38':1288,'.Ltmp40':1391,'.Ltmp43':1401})
        for marker in ('.Ltmp28','.Ltmp30','.Ltmp38','.Ltmp40'):
            bad=body.replace(marker+':',marker+'_wrong:')
            with self.assertRaises(ValueError):t.call_states(bad,code)
        bad=body.replace('.Ltmp38:','').replace('.Ltmp40:','.Ltmp38:\n.Ltmp40:')
        with self.assertRaises(ValueError):t.call_states(bad,code)

    def test_simd_exception_effects_guard_length_flag_and_pointer_mutations(self):
        b,asm,*_=self.simd_exception_effects_fixture();n=t.names(b);code=t.life.code(b[n['executor']])
        def verify(lines):
            edges,_=t.o.reconcile.graph(lines,asm);spans,_,_=t.o.frame_writes(lines,edges)
            states=t.w.definitions(lines,edges,spans,tuple(sorted(set(t.previous.SLOTS)|{464,472})))
            origins=t.previous.control.analyse(lines,edges,spans)
            return t.guard_lifetimes(lines,edges,spans,states,origins)
        verify(code)
        for at,line in ((22,'movq %rcx, 440(%rbp)'),(23,'movq %r15, 448(%rbp)'),
            (24,'movq %rbx, 456(%rbp)'),(25,'movq $1023, 464(%rbp)'),(26,'movb $1, 472(%rbp)'),
            (41,'movq %r14, 968(%rbp)'),(1288,'movq %rsi, 952(%rbp)')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):verify(bad)

    def test_simd_exception_effects_scope_prerequisites_and_integration(self):
        args=self.simd_exception_effects_fixture();b,asm,caller,services=args;r=t.inspect(*args)
        self.assertEqual(len(r['ordered_handler_chains']),8)
        self.assertEqual(len(r['ordered_handler_chains']['43']),2)
        self.assertEqual(len(r['ordered_handler_chains']['1129']),1)
        self.assertFalse(r['complete_private_frame_erasure_qualified'])
        self.assertFalse(r['asynchronous_fault_and_fatal_abort_cleanup_claimed'])
        for obj,key,value in ((services,'all_executor_call_site_footprints_assigned',False),
            (services,'pending_callee_effect_sites',[1129]),
            (caller['helpers'],'output_drop_clears_four_present_nonempty_destinations',False)):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('unwind failed')):
            with self.assertRaisesRegex(ValueError,'unwind failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
