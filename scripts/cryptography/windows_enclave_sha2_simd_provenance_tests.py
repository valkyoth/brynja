"""No-escape/all-use tests for the saved SIMD descriptor IR allocation."""
import re
from unittest.mock import patch
import windows_enclave_sha2_simd_provenance as p

g=p.graph


class ProvenanceTests:
    def test_descriptor_alias_graph_composes_bounded_byte_offsets(self):
        lines=['%root = alloca [40 x i8], align 8',
               '%later = getelementptr inbounds nuw i8, ptr %indexed, i64 8',
               '%indexed = getelementptr inbounds nuw i8, ptr %root, i64 %index']
        aliases=g.aliases(g.definitions(lines),'%root',40,{'%index':(0,16)})
        self.assertEqual(aliases,{'%root':(0,), '%indexed':(0,16),'%later':(8,24)})
        for bad in ({},{'%index':(-1,)},{'%index':(32,)},{'%index':()}):
            with self.assertRaises(ValueError): g.aliases(g.definitions(lines),'%root',40,bad)

    def test_descriptor_graph_rejects_alias_escape_and_unmodeled_operations(self):
        prefix=['%root = alloca [24 x i8], align 8',
                '%alias = getelementptr inbounds nuw i8, ptr %root, i64 8']
        def reject(*args): raise ValueError('unreviewed call')
        for line in ('%cast = bitcast ptr %alias to ptr',
                     '%number = ptrtoint ptr %alias to i64',
                     '%cast = addrspacecast ptr %alias to ptr addrspace(1)',
                     '%select = select i1 %test, ptr %alias, ptr null',
                     '%phi = phi ptr [ %alias, %entry ], [ null, %other ]',
                     'store ptr %alias, ptr %output, align 8',
                     'store ptr %alias, ptr %root, align 8',
                     'ret ptr %alias','%cmp = icmp eq ptr %alias, null',
                     'call void @external(ptr nonnull %alias)',
                     'call void %callback(ptr nonnull %alias)',
                     '%typed = getelementptr i64, ptr %alias, i64 1'):
            with self.subTest(line=line),self.assertRaises(ValueError):
                g.scan(prefix+[line],'%root',24,{},reject)

    def test_descriptor_load_and_store_extent_and_exact_token_identity(self):
        prefix=['%root = alloca [24 x i8], align 8',
                '%alias = getelementptr inbounds nuw i8, ptr %root, i64 23']
        def reject(*args): self.fail('unexpected call')
        result=g.scan(prefix+['%byte = load i8, ptr %alias, align 1',
                             'store i8 0, ptr %root, align 8',
                             'call void @unrelated(ptr %root_extra)'],'%root',24,{},reject)
        self.assertEqual(result['reads'][0]['offsets'],[23])
        self.assertEqual(result['writes'][0]['offset'],0)
        for op in ('%bad = load ptr, ptr %alias, align 1',
                   'store i16 0, ptr %alias, align 1',
                   'store volatile i8 0, ptr %alias, align 1'):
            with self.assertRaises(ValueError): g.scan(prefix+[op],'%root',24,{},reject)
        with self.assertRaises(ValueError): g.definitions(prefix+['%root = alloca [24 x i8], align 8'])

    def test_descriptor_function_identity_and_nested_call_arguments(self):
        ir='define void @test() {\n %root = alloca [24 x i8], align 8\n ret void\n}'
        self.assertEqual(g.function(ir,'test')[1],'%root = alloca [24 x i8], align 8')
        for bad in ('',ir+'\n'+ir):
            with self.assertRaises(ValueError): g.function(bad,'test')
        name,args,tail=g.call('call void @test(ptr captures(address, read_provenance) %root, i64 8) #1')
        self.assertEqual((name,len(args),g.pointer(args[0]),tail),('test',2,'%root',' #1'))
        with self.assertRaises(ValueError): g.call('call void @test(ptr %root')

    def test_descriptor_call_policy_rejects_destination_swaps_and_extra_consumers(self):
        aliases={'%root':(0,), '%tail':(64,), '%interior':(8,)}
        allow=p.calls_for('%root',4,'drop','simd512')
        self.assertEqual(allow('llvm.memcpy.p0.p0.i64',
            ['ptr nonnull %root','ptr readonly %3','i64 64','i1 false'],'',aliases,{'%root'})['kind'],'initialize')
        cases=[('llvm.memcpy.p0.p0.i64',['ptr nonnull %root','ptr readonly %3','i64 72','i1 false'],{'%root'}),
               ('llvm.memcpy.p0.p0.i64',['ptr nonnull %3','ptr readonly %root','i64 64','i1 false'],{'%root'}),
               (p.s.ZERO,['ptr nonnull %interior','i64 noundef 8'],{'%interior'}),
               (p.s.ZERO,['ptr nonnull %tail','i64 noundef 16'],{'%tail'}),
               ('drop',['ptr dereferenceable(72) %root'],{'%root'}),
               ('unknown',['ptr nonnull %root'],{'%root'})]
        for name,args,used in cases:
            with self.assertRaises(ValueError): allow(name,args,'',aliases,used)


class ProvenanceSavedTests:
    def provenance_routes(self):
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            name=p.s.one(bodies,r'Resident6digest$' if lane=='simd256' else r'Executor13digest_secret$')
            lines=g.function(ir,name)
            yield lane,bodies,lines,'%10' if lane=='simd256' else '%14'

    def test_provenance_review_is_required_and_complete_population_is_bound(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            report=p.inspect(bodies,ir,lane)
            self.assertEqual((report['aliases'],report['reads'],report['writes']),
                             (72,51,25) if lane=='simd256' else (28,26,5))
            self.assertTrue(report['machine_stack_slot_lifetime_composition_pending'])
            with patch.object(p,'inspect',side_effect=ValueError('provenance failed')) as gate:
                with self.assertRaisesRegex(ValueError,'provenance failed'): c.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()

    def test_provenance_all_aliases_reject_extra_writes_and_address_escape(self):
        count=0
        for lane,bodies,lines,root in self.provenance_routes():
            drop=p.s.one(bodies,r'SecretBatchOutput.*Drop4drop$');size=136 if lane=='simd256' else 72
            aliases=g.aliases(g.definitions(lines),root,size,p.cleanup_index(lines,lane,root,drop))
            for alias in aliases:
                at=next(i for i,l in enumerate(lines) if l.startswith(alias+' = '))+1
                for injected in (f'store i8 0, ptr {alias}, align 1',
                                 f'call void @unexpected(ptr nonnull {alias})',
                                 f'%escape = ptrtoint ptr {alias} to i64'):
                    bad=lines[:at]+[injected]+lines[at:]
                    with self.assertRaises(ValueError): p.inspect(bodies,'\n'.join(bad),lane)
                    count+=1
        self.assertEqual(count,300)
        print('SIMD descriptor allocation alias-write/escape mutations rejected: '+str(count))

    def test_provenance_cleanup_index_bounds_and_incoming_copy_are_load_bearing(self):
        count=0
        for lane,bodies,lines,root in self.provenance_routes():
            narrow=lane=='simd256';index=888 if narrow else 987;limit=128 if narrow else 64
            predicates=[(f'icmp eq i64 %{index}, {limit}',f'icmp eq i64 %{index}, {limit+16}'),
                        (f'icmp eq i64 %{index}, {limit}',f'icmp ne i64 %{index}, {limit}'),
                        (f'add nuw nsw i64 %{index}, 16',f'add nuw nsw i64 %{index}, 8')]
            for old,new in predicates:
                text='\n'.join(lines);self.assertEqual(text.count(old),1)
                with self.assertRaises(ValueError): p.inspect(bodies,text.replace(old,new),lane)
                count+=1
            if not narrow:
                at=next(i for i,l in enumerate(lines) if 'llvm.memcpy' in l and ' %14,' in l)
                for replacement in (lines[at].replace('i64 64','i64 72'),lines[at].replace(' %3,',' %4,')):
                    bad=lines[:];bad[at]=replacement
                    with self.assertRaises(ValueError): p.inspect(bodies,'\n'.join(bad),lane)
                    count+=1
        self.assertEqual(count,8)
        print('SIMD descriptor cleanup/copy bound mutations rejected: '+str(count))

    def test_provenance_each_narrow_destination_retains_its_distinct_original_scratch_slot(self):
        count=0
        for lane,bodies,lines,root in self.provenance_routes():
            if lane!='simd256': continue
            for i,line in enumerate(lines):
                if not re.match(r'store ptr %\w+, ptr ',line): continue
                match=re.match(r'store ptr (%\w+), ptr (\S+),',line)
                if match[1] not in ('%18','%152','%155','%158','%161','%164','%167','%174'): continue
                bad=lines[:];bad[i]=line.replace('store ptr '+match[1]+',','store ptr null,')
                with self.assertRaises(ValueError): p.inspect(bodies,'\n'.join(bad),lane)
                count+=1
        self.assertEqual(count,8)
        print('SIMD original scratch pointer replacements rejected: '+str(count))

    def test_prepared_sources_reject_wrong_origin_escape_and_copy_destination(self):
        count=0
        for lane,bodies,lines,root in self.provenance_routes():
            narrow=lane=='simd256';stride=32 if narrow else 64
            for slot,phi in enumerate(p.PHIS[lane]):
                source=825+8*slot if narrow else 942+10*slot
                definition=next(i for i,l in enumerate(lines) if l.startswith(f'%{source} = '))
                merge=next(i for i,l in enumerate(lines) if l.startswith(phi+' = '))
                call=next(i for i,l in enumerate(lines) if phi in re.findall(g.SSA,l) and 'call fastcc' in l)
                _,args,_=g.call(lines[call]);destination=g.pointer(args[0])
                changes=[(definition,lines[definition].replace(f'i64 {1024+stride*slot}',f'i64 {1025+stride*slot}')),
                         (merge,lines[merge].replace('[ null,','[ poison,')),
                         (call,lines[call].replace('readonly ','')),
                         (call,lines[call].replace(' '+destination+',',' %0,'))]
                for at,replacement in changes:
                    self.assertNotEqual(lines[at],replacement)
                    bad=lines[:];bad[at]=replacement
                    with self.assertRaises(ValueError): p.inspect(bodies,'\n'.join(bad),lane)
                    count+=1
                bad=lines[:merge+1]+[f'store ptr {phi}, ptr %output, align 8']+lines[merge+1:]
                with self.assertRaises(ValueError): p.inspect(bodies,'\n'.join(bad),lane)
                count+=1
        self.assertEqual(count,60)
        print('SIMD prepared-source origin/escape/copy mutations rejected: '+str(count))
