"""Finite private-population, frame, prerequisite and fail-stop regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_batch_completion as p


class CompletionSavedTests:
    def completion_fixture(self,lane):
        import windows_enclave_sha2_batch_chains as main
        if not hasattr(self.__class__,'_completion_fixtures'):self.__class__._completion_fixtures={}
        cache=self.__class__._completion_fixtures
        if lane not in cache:
            row=next(r for r in self.routes if r[0]==lane)
            _,pin,data,image,_,_,bodies=row
            report=main.inspect_route(self.saved,self.root,lane,pin,False)
            records=main.bind_all(data,image,row[-2])
            sizes,_,vectors,_,_=main.c.frames(records,bodies)
            cache[lane]=(row,records,sizes,vectors,report)
        return cache[lane]

    def test_completion_actual_population_storage_and_shared_limits(self):
        import windows_enclave_sha2_batch_chains as main
        for lane,count in main.COUNTS.items():
            row,records,sizes,vectors,r=self.completion_fixture(lane)
            proof=r['private_chain_composition'];storage=proof['storage']
            self.assertTrue(proof['author_private_review_complete'])
            self.assertEqual(len(proof['functions']),count)
            self.assertEqual(set(proof['functions']),set(records))
            self.assertEqual(set(storage['transient']['frames']),set(records))
            self.assertEqual(proof['population']['funclets'],0 if lane=='scalar' else 1 if lane=='sha_ni' else 16)
            self.assertEqual(proof['remaining_private_assignments'],[])
            self.assertEqual(storage['resident']['page_bytes'],4096)
            self.assertEqual(storage['transient']['window_reclamation_package'],8)
            for field in ('whole_frame_erasure_qualified','whole_image_qualified','independent_retest',
                          'arbitrary_exception_cleanup_qualified'):self.assertFalse(proof[field])
            for field in ('individual_spills_moves_padding_or_registers_erased','shared_runtime_frames_included',
                          'cumulative_depth_qualified'):self.assertFalse(storage['transient'][field])
            self.assertFalse(proof['fail_stop']['fatal_abort_is_cleanup_success'])
            with patch.object(p,'inspect',side_effect=ValueError('composition missing')) as check:
                with self.assertRaisesRegex(ValueError,'composition missing'):
                    main.inspect_route(self.saved,self.root,lane,row[1],False)
                check.assert_called_once()

    def test_completion_every_frame_requires_geometry_and_bounded_vector_saves(self):
        count=0
        for lane in ('scalar','sha_ni','simd256','simd512'):
            _,records,sizes,vectors,r=self.completion_fixture(lane)
            args=(r['runtime_boundaries_pending'],lane,r['semantics'])
            for name in records:
                bad=dict(sizes);bad.pop(name)
                with self.assertRaises(ValueError):p.assignment.storage(records,bad,vectors,*args)
                for value in (-1,65536,True):
                    with self.assertRaises(ValueError):p.assignment.storage(records,sizes|{name:value},vectors,*args)
                for value in ([[5,0]],[[16,0]],[[6,-1]],[[6,sizes[name]]]):
                    with self.assertRaises(ValueError):p.assignment.storage(records,sizes,vectors|{name:value},*args)
                count+=8
        self.assertEqual(count,1424)

    def test_completion_all_roles_are_explicit_and_prior_replay_required(self):
        for lane in ('scalar','sha_ni','simd256','simd512'):
            _,records,_,_,r=self.completion_fixture(lane);prior=r['reproduced_primitive_contracts'];sem=r['semantics']
            with self.assertRaisesRegex(ValueError,'one explicit batch review role'):
                p.assignment.functions(records|{'new_unreviewed_body':{}},prior,lane,sem)
            badprior=copy.deepcopy(prior);badsem=copy.deepcopy(sem)
            if lane.startswith('simd'):badsem['simd_primitive_contracts']['prior_semantic_review_replayed']=False
            else:badprior['prior_semantic_review_replayed']=False
            with self.assertRaises(ValueError):p.assignment.functions(records,badprior,lane,badsem)
            # An omitted reproduced helper cannot silently acquire an ordinary
            # role by virtue of an otherwise equal source or function name.
            if lane=='sha_ni':
                for name in prior['reproduced_scalar_fallbacks']:
                    changed=copy.deepcopy(prior);changed['reproduced_scalar_fallbacks'].pop(name)
                    with self.assertRaises(ValueError):p.assignment.functions(records,changed,lane,sem)

    def test_completion_metadata_callback_and_dispatch_population_rejections(self):
        count=0
        for lane in ('scalar','sha_ni','simd256','simd512'):
            row,records,_,_,r=self.completion_fixture(lane);bodies=row[-1]
            args=(r['dispatch_tables'],r['callback_tables'],r['semantics'],lane)
            for funclet in (n for n in records if n.startswith('?dtor$')):
                bad=copy.deepcopy(records)
                for record in bad.values():record['metadata']=[m for m in record.get('metadata',[]) if m['symbol']!=funclet]
                with self.assertRaises(ValueError):p.assignment.population(bad,bodies,*args)
                count+=1
            with self.assertRaises(ValueError):p.assignment.population(records,bodies|{'orphan':'orphan:\nretq'},*args)
            for insn in ('callq *%rax','jmpq *%rax'):
                with self.assertRaises(ValueError):
                    p.assignment.population(records,bodies|{'RetainedWork':bodies['RetainedWork']+'\n'+insn},*args)
            for table in r['callback_tables']:
                bad=copy.deepcopy(r['callback_tables']);bad[table]['slots']['32']='missing'
                with self.assertRaises(ValueError):
                    p.assignment.population(records,bodies,r['dispatch_tables'],bad,r['semantics'],lane)
            if r['dispatch_tables']:
                bad=copy.deepcopy(r['dispatch_tables']);next(iter(bad.values()))['operands'].pop()
                with self.assertRaises(ValueError):
                    p.assignment.population(records,bodies,bad,r['callback_tables'],r['semantics'],lane)
        self.assertEqual(count,33)

    def test_completion_existing_contracts_cannot_be_missing_false_or_truthy(self):
        count=0
        for lane in ('scalar','sha_ni','simd256','simd512'):
            *_,r=self.completion_fixture(lane)
            for path in p.prerequisites(r['semantics'],lane):
                for replacement in (None,False,1):
                    bad=copy.deepcopy(r['semantics']);keys=path.split('.');node=bad
                    for key in keys[:-1]:node=node[key]
                    if replacement is None:node.pop(keys[-1])
                    else:node[keys[-1]]=replacement
                    with self.assertRaises(ValueError):p.prerequisites(bad,lane)
                    count+=1
        self.assertEqual(count,147)

    def test_completion_terminal_population_and_no_successful_abort(self):
        count=0
        for lane in ('scalar','sha_ni','simd256','simd512'):
            row,_,_,_,r=self.completion_fixture(lane);bodies=row[-1]
            proof=p.terminals.inspect(bodies,lane,r['semantics'])
            for caller,target in proof['calls']:
                for change in ('remove','extra'):
                    body='\n'.join(p.s.lines(bodies[caller]));needle='callq '+target
                    changed=body.replace(needle,'nop') if change=='remove' else body+'\n'+needle
                    self.assertNotEqual(body,changed)
                    with self.assertRaises(ValueError):p.terminals.inspect(bodies|{caller:changed},lane,r['semantics'])
                    count+=1
            fmt=p.s.one(bodies,r'panicking9panic_fmt$')
            with self.assertRaises(ValueError):p.terminals.inspect(bodies|{fmt:bodies[fmt]+'\nretq'},lane,r['semantics'])
        self.assertEqual(count,14)

    def test_completion_sha_ni_length_branches_are_load_bearing(self):
        row,_,_,_,_=self.completion_fixture('sha_ni');bodies=row[-1]
        actual=p.s.sequences;captures=[]
        def collect(body,sequences):captures.extend(sequences);return actual(body,sequences)
        with patch.object(p.s,'sequences',collect):proof=p.terminals.sha_ni_lengths(bodies)
        name=proof['function'];body='\n'.join(p.s.lines(bodies[name]))
        self.assertEqual([v['length_bytes'] for v in proof['cases']],[8,16])
        count=0
        for sequence in captures:
            for line in sequence.split('|'):
                changed=body.replace(sequence.replace('|','\n'),sequence.replace(line,'nop',1).replace('|','\n'))
                self.assertNotEqual(changed,body)
                with self.assertRaises(ValueError):p.terminals.sha_ni_lengths(bodies|{name:changed})
                count+=1
        self.assertEqual(count,34)

    def test_completion_sha_ni_fallbacks_reject_body_table_and_abi_drift(self):
        row,_,_,_,r=self.completion_fixture('sha_ni');functions=row[-2];ir=row[4];t=p.terminals
        _,old,old_ir,_=t.reuse.prior(self.saved,'scalar');previous=t.reuse.c.previous.inventory(old)
        constants=r['constants'];proof=t.fallback_contracts(functions,previous,ir,old_ir,constants)
        count=0
        for name,review in proof.items():
            code,refs,extent=functions[name]
            for value in ((bytes([code[0]^1])+code[1:],refs,extent),(code,refs,not extent),(code,[],extent)):
                with self.assertRaises(ValueError):t.fallback_contracts(functions|{name:value},previous,ir,old_ir,constants)
                count+=1
            for key,value in (('sha256','0'*64),('bytes',1)):
                bad=copy.deepcopy(constants);bad[review['table']][key]=value
                with self.assertRaises(ValueError):t.fallback_contracts(functions,previous,ir,old_ir,bad)
                count+=1
            for before,after in (('dereferenceable(640)','dereferenceable(641)'),('+sha,','-sha,')):
                with self.assertRaises(ValueError):t.fallback_contracts(functions,previous,ir.replace(before,after),old_ir,constants)
                count+=1
        self.assertEqual(count,14)
