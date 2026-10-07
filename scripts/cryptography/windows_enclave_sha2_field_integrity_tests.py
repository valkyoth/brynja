"""Metadata preservation, escape and definition-lifetime regressions."""
from unittest.mock import patch
import windows_enclave_sha2_field_integrity as p
import windows_enclave_sha2_compact_lifetimes as compact
g=p.g


class FieldIntegrityTests:
    def test_compact_cursor_cannot_use_old_slot_role_or_an_unanchored_cycle(self):
        lines=['entry:','seed','use','step','exit']
        edges={0:[1],1:[2],2:[3],3:[2,4],4:[]}
        states={2:{104:{1,3}},3:{104:{1,3}}}
        compact.cursor(lines,states,edges,104,1,3,[2,3])
        for definitions in ({-1,1,3},{3},{0,1}):
            bad={2:{104:definitions},3:{104:definitions}}
            with self.assertRaises(ValueError):compact.cursor(lines,bad,edges,104,1,3,[2,3])
        with self.assertRaises(ValueError):compact.cursor(lines,states,edges|{0:[1,2]},104,1,3,[2,3])

    def test_field_lifetime_requires_initialization_on_every_path(self):
        edges={1:[2,4],2:[3],3:[4],4:[]}
        with self.assertRaises(ValueError):g.lifetime(edges,[4],[2],[])
        g.lifetime(edges,[4],[1],[])
        with self.assertRaises(ValueError):g.lifetime(edges,[4],[1],[3])

    def test_field_lifetime_does_not_reuse_previous_iteration(self):
        edges={1:[2],2:[3],3:[4],4:[2,5],5:[]}
        g.lifetime(edges,[3],[2],[4])
        with self.assertRaises(ValueError):g.lifetime(edges,[3],[1],[4])
        with self.assertRaises(ValueError):g.lifetime(edges,[99],[1],[])

    def test_field_lifetime_follows_invoke_and_cleanup_edges(self):
        lines=['define void @f() {','entry:','%r = invoke i8 @f()',
               'to label %ok unwind label %bad','ok:','br label %end',
               'bad:','cleanupret from %pad unwind label %end','end:','ret void','}']
        edges=g.cfg(lines)
        g.lifetime(edges,[8],[1],[])
        with self.assertRaises(ValueError):g.lifetime(edges,[8],[1],[6])
        with self.assertRaises(ValueError):g.cfg(lines[:2]+['indirectbr ptr %x, [label %ok]']+lines[3:])

    def test_field_aliases_include_forward_phi_and_reject_external_escape(self):
        lines=['define void @f(ptr %a) {','entry:',
               '%x = getelementptr inbounds nuw i8, ptr %a, i64 8',
               '%p = phi ptr [ %x, %entry ], [ %later, %entry ]',
               '%later = getelementptr inbounds nuw i8, ptr %a, i64 16',
               '%v = load ptr, ptr %p, align 8','ret void','}']
        def scan(ls):return g.inventory(ls,{'%a':[('authority',0,0)]},{},lambda *a:False)
        known,records=scan(lines)
        self.assertEqual(known['%p'],[('authority',8,8),('authority',16,16)])
        self.assertEqual(len(records),1)
        for text in ('store ptr %x, ptr %outside, align 8',
                     '%cast = ptrtoint ptr %x to i64','%cast = bitcast ptr %x to ptr',
                     '%v = atomicrmw add ptr %x, i64 1 seq_cst',
                     '%p = phi ptr [ %x, %entry ], [ %outside, %entry ]'):
            with self.assertRaises(ValueError):scan(lines[:5]+[text]+lines[5:])

    def test_field_partial_and_overlapping_write_extents(self):
        lines=['define void @f(ptr %a) {','entry:',
               '%x = getelementptr inbounds nuw i8, ptr %a, i64 7',
               'store i16 0, ptr %x, align 1','ret void','}']
        _,records=g.inventory(lines,{'%a':[('authority',0,0)]},{},lambda *a:False)
        self.assertEqual(records[0]['spans'],[('authority',7,9)])
        self.assertTrue(p.overlap(records[0]['spans'][0],8,16))

    def test_field_call_effects_reject_unknown_and_unbounded_writes(self):
        row=dict(target='unknown',args=['ptr %a'],pointers={0:'%a'})
        known={'%a':[('authority',0,0)]}
        with self.assertRaises(ValueError):p.effects.calls(row,known,'simd512')
        row.update(target='xsecret_memory_volatile23zeroize_region_volatile',args=['ptr %a','i64 %length'])
        with self.assertRaises(ValueError):p.effects.calls(row,known,'simd512')
        row['args'][1]='i64 17'
        self.assertEqual(p.effects.calls(row,known,'simd512')[0],[('authority',0,17)])


class FieldIntegritySavedTests:
    def field_rows(self):return [row for row in self.routes if row[0].startswith('simd')]

    def test_actual_field_population_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.field_rows():
            lane,pin,_,_,ir,_,bodies=row;r=p.inspect(bodies,ir,lane)
            self.assertEqual((r['aliases'],r['accesses'],r['call_count']),
                             (143,159,53) if lane=='simd256' else (145,139,29))
            self.assertEqual(len(r['index_reads']),5 if lane=='simd256' else 11)
            self.assertTrue(r['physical_allocation_separation_and_lifetime_composition_pending'])
            self.assertFalse(r['whole_frame_qualified'])
            with patch.object(p,'inspect',side_effect=ValueError('metadata preservation failed')) as check:
                with self.assertRaisesRegex(ValueError,'metadata preservation failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_every_input_read_rejects_late_descriptor_write(self):
        count=0
        for lane,_,_,_,ir,_,bodies in self.field_rows():
            result=p.inspect(bodies,ir,lane);name=result['function'];lines=g.ir.function(ir,name)
            for at in result['input_reads']:
                dest=lines[at].split(', ptr ')[1].split(',')[0]
                bad=ir.replace(lines[at],f'store i8 0, ptr {dest}, align 1\n  '+lines[at],1)
                with self.assertRaises(ValueError):p.inspect(bodies,bad,lane)
                count+=1
        self.assertEqual(count,90)
        print('Metadata late input-field write mutations rejected: '+str(count))

    def test_actual_every_compact_read_rejects_intervening_wipe(self):
        count=0
        for lane,_,_,_,ir,_,bodies in self.field_rows():
            result=p.inspect(bodies,ir,lane);lines=g.ir.function(ir,result['function'])
            wipe=next(line for line in lines if 'workspace' in line and 'Workspace4wipe(' in line)
            for at in result['index_reads']:
                bad=ir.replace(lines[at],wipe+'\n  '+lines[at],1)
                with self.assertRaisesRegex(ValueError,'after invalidation'):p.inspect(bodies,bad,lane)
                count+=1
        self.assertEqual(count,16)
        print('Metadata compact-index wipe-before-read mutations rejected: '+str(count))

    def test_actual_authority_callback_backend_and_owner_field_writes_reject(self):
        count=0
        for lane,_,_,_,ir,_,bodies in self.field_rows():
            result=p.inspect(bodies,ir,lane);lines=g.ir.function(ir,result['function'])
            seeds,bounds=p.configuration(lines,lane);known,_=g.aliases(lines,seeds,bounds)
            for alias,spans in known.items():
                if spans not in ([('authority',8,8)],[('authority',17,17)],
                                 [('owner',8,8)] if lane=='simd256' else [('owner',0,0)]):continue
                anchor=next((line for line in lines if line.startswith(alias+' = ')),lines[1])
                bad=ir.replace(anchor,anchor+f'\n  store i8 0, ptr {alias}, align 1',1)
                with self.assertRaises(ValueError):p.inspect(bodies,bad,lane)
                count+=1
        self.assertEqual(count,15)
        print('Metadata authority/callback immutable-field mutations rejected: '+str(count))

    def test_actual_metadata_escapes_bypass_and_widened_effects_reject(self):
        count=0
        for lane,_,_,_,ir,_,bodies in self.field_rows():
            result=p.inspect(bodies,ir,lane);lines=g.ir.function(ir,result['function'])
            root='%20' if lane=='simd256' else '%2';anchor=lines[result['input_reads'][0]]
            changes=[ir.replace(anchor,text+'\n  '+anchor,1) for text in (
                f'call void @unknown(ptr {root})',f'%escape = ptrtoint ptr {root} to i64',
                f'store ptr {root}, ptr %0, align 8')]
            # Any whole-workspace alias must be included, not just aliases
            # derived from the chosen compact-index GEP itself.
            work='%19' if lane=='simd256' else '%4';offset=4096 if lane=='simd256' else 4576
            changes.append(ir.replace(anchor,
                f'%hidden = getelementptr inbounds nuw i8, ptr {work}, i64 {offset}\n  '
                'store i64 0, ptr %hidden, align 1\n  '+anchor,1))
            end=lines[result['compaction_complete']]
            changes.append(ir.replace(anchor,'br label %'+end[:-1]+'\n  '+anchor,1))
            for bad in changes:
                with self.assertRaises(ValueError):p.inspect(bodies,bad,lane)
                count+=1
        self.assertEqual(count,10)

    def test_actual_narrow_integer_alias_and_input_initialization_cannot_drift(self):
        row=next(row for row in self.field_rows() if row[0]=='simd256');ir,bodies=row[4],row[-1]
        changes=[('%327 = ptrtoint ptr %325 to i64','%327 = ptrtoint ptr %19 to i64'),
                 ('%334 = phi ptr [ %324, %322 ], [ null, %314 ]',
                  '%334 = phi ptr [ %19, %322 ], [ null, %314 ]'),
                 ('store i64 %327, ptr %7, align 8','store i64 %327, ptr %8, align 8'),
                 ('%exitcond.not = icmp eq i64 %86, 8','%exitcond.not = icmp eq i64 %86, 7'),
                 ('%88 = add nuw nsw i64 %86, 1','%88 = add nuw nsw i64 %86, 2'),
                 ('store i64 %327, ptr %7, align 8','store i64 %327, ptr %7, align 8\n  store i64 0, ptr %7, align 8'),
                 ('%8 = alloca i64, align 8','%8 = alloca i64, align 8\n  %escape = bitcast ptr %8 to ptr'),
                 ('store ptr %1028, ptr %89, align 8','store ptr null, ptr %89, align 8')]
        for old,new in changes:
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):p.inspect(bodies,ir.replace(old,new,1),'simd256')

    def test_actual_compact_cursor_slots_reject_overwrite_bypass_and_reuse(self):
        import windows_enclave_sha2_batch_chains as parent
        count=0
        for lane,pin,_,_,_,_,bodies in self.field_rows():
            asm=parent.load(self.saved,self.root,pin)[3];r=compact.inspect(bodies,asm,lane)
            name=r['function'];lines=p.s.lines(bodies[name]);slot,base=(104,'rbx') if lane=='simd256' else (1024,'rbp')
            changes=[]
            for at in r['cursor_reads']:
                for text in (f'movb $0, {slot+7}(%{base})',f'movq %r11, {slot-1}(%{base})'):
                    changes.append(lines[:at]+[text]+lines[at:])
            for at in r['base_reads']:
                changes.append(lines[:at]+['movq %r11, 944(%rbp)']+lines[at:])
            bad=lines[:];bad[r['initializer']]='nop';changes.append(bad)
            bad=lines[:];bad[r['increment']]=f'addq $16, {slot}(%{base})';changes.append(bad)
            for changed in changes:
                with self.assertRaises(ValueError):compact.inspect(bodies|{name:'\n'.join(changed)},asm,lane)
                count+=1
            with patch.object(compact,'inspect',side_effect=ValueError('compact cursor failed')) as check:
                with self.assertRaisesRegex(ValueError,'compact cursor failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
        self.assertEqual(count,25)
        print('Compact cursor overwrite/base/initialization/increment mutations rejected: '+str(count))
