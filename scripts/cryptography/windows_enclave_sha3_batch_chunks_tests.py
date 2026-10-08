"""Setup fragment and selected unwind mutations against saved emitted bodies."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c


class ChunkTests:
    def test_chunks_complete_emitted_paths_reject_every_instruction_mutant(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies=self.routes[lane][-1];_,shapes=c.chunks.check_shapes(bodies,lane)
            for name in shapes:
                lines=c.lifecycle.code(bodies[name])
                for at in range(len(lines)):
                    for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                        with self.assertRaises(ValueError):
                            c.chunks.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},lane)
                        count+=1
        self.assertEqual(count,810)
        print('SHA-3 setup fragment/bridge/cleanup instruction mutants rejected:',count)

    def test_chunks_input_tail_bounds_budget_and_selector_rejections(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies=self.routes[lane][-1];n,_=c.chunks.check_shapes(bodies,lane)
            name=n['setup_chunk'];body='\n'.join(c.chunks.s.lines(bodies[name]));scalar=lane=='scalar'
            changes=[('movb $2, %r9b','movb $3, %r9b'),('subb $1, %cl','subb $2, %cl'),
                ('cmpb $8, %cl','cmpb $9, %cl'),('cmovel %eax, %edx','cmovnel %eax, %edx'),
                ('addq $-8, %'+('r13' if scalar else 'r12'),'nop'),('shlb %cl, %dl','shrb %cl, %dl'),
                ('decq %rcx','incq %rcx'),('callq '+n['mask'],'nop'),
                ('cmpq $7, %'+('rdi' if scalar else 'rsi'),'cmpq $8, %'+('rdi' if scalar else 'rsi')),
                ('jb .B'+('15' if scalar else '16'),'ja .B'+('15' if scalar else '16')),
                ('movq '+('192(%rsp), %r12' if scalar else '112(%rbp), %r9'),
                 'movq '+('200(%rsp), %r12' if scalar else '120(%rbp), %r9')),
                ('callq '+c.lifecycle.DROP[lane],'nop')]
            for old,new in changes:
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.chunks.check_shapes(bodies|{name:body.replace(old,new)},lane)
                count+=1
        self.assertEqual(count,24)

    def test_chunks_every_descriptor_field_store_and_guard_slot_rejected(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies=self.routes[lane][-1];n,_=c.chunks.check_shapes(bodies,lane);name=n['setup_chunk']
            body='\n'.join(c.chunks.s.lines(bodies[name]));reg='rsp' if lane=='scalar' else 'rbp'
            # Pointer, split little-endian length, bit length, terminal-bit count.
            offsets=[56,64,65,69,71,72,80] if lane=='scalar' else [-64,-56,-55,-51,-49,-48,-40]
            if lane=='avx2':offsets += [-16,-1]
            for offset in offsets:
                token=f', {offset}(%{reg})';self.assertIn(token,body)
                with self.assertRaises(ValueError):
                    c.chunks.check_shapes(bodies|{name:body.replace(token,f', {offset+1}(%{reg})')},lane)
                count+=1
        self.assertEqual(count,16)

    def test_chunks_handler_metadata_and_call_interval_are_load_bearing(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];n,_=c.chunks.check_shapes(bodies,'avx2')
        result=c.chunks.cleanup_tables(asm,bodies,n);count=0
        for label,want in result['expected_tables'].items():
            match=re.search(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
            lines=match[1].splitlines(keepends=True)
            for at in range(len(want)):
                bad=lines.copy();bad[at]='\t.long\tUNREVIEWED\n'
                with self.assertRaises(ValueError):
                    c.chunks.cleanup_tables(asm[:match.start(1)]+''.join(bad)+asm[match.end(1):],bodies,n)
                count+=1
            for bad in (asm.replace(label+':',label+'_absent:'),asm+'\n'+match[0]):
                with self.assertRaises(ValueError):c.chunks.cleanup_tables(bad,bodies,n)
                count+=1
        self.assertEqual(count,24)
        name=n['setup_chunk'];body='\n'.join(c.chunks.s.lines(bodies[name]))
        for old,new in [('.Ltmp10:','.Ltmp12:'),('.Ltmp11:','.Ltmp12:'),
            ('.Ltmp10:',''),('.Ltmp11:',''),('callq '+n['state'],'nop'),
            ('.seh_handler __CxxFrameHandler3, @unwind, @except','.seh_handler UNREVIEWED, @unwind, @except'),
            ('.long $cppxdata$'+name+'@IMGREL','.long 0')]:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):c.chunks.cleanup_tables(asm,bodies|{name:body.replace(old,new)},n)

    def test_chunks_argument_abis_reject_descriptor_alias_and_capture_drift(self):
        count=0
        for lane in ('scalar','avx2'):
            _,_,_,ir,_,bodies=self.routes[lane];n=c.chunks.names(bodies,lane)
            changes=[('setup_chunk','range(i64 0, 1025)','range(i64 0, 1026)'),
                ('setup_chunk','zeroext ',' '),('state','noalias ',' '),('state','readonly ',' '),
                ('state','captures(none)','captures(address)'),('state','dereferenceable(32)','dereferenceable(31)'),
                ('state','dead_on_return ',' '),('state','align 8','align 1'),
                ('mask','dereferenceable(1)','dereferenceable(0)'),('mask','range(i8 -128, 0)','range(i8 -128, 1)')]
            if lane=='scalar':
                for key in ('a8','88'):
                    changes += [(key,'dereferenceable(1120)','dereferenceable(1119)'),
                                (key,'range(i8 0, 2)','range(i8 0, 3)'),(key,'captures(none)','captures(address)')]
            else:changes += [('glue','nonnull ',' '),('glue','range(i8 0, 2)','range(i8 0, 3)')]
            for key,old,new in changes:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):c.chunks.arguments(ir.replace(row,row.replace(old,new)),bodies,lane)
                count+=1
        self.assertEqual(count,28)

    def test_chunks_compose_live_caller_helpers_cleanup_without_scope_promotion(self):
        for lane in ('scalar','avx2'):
            args=self.update_fixture(lane);result=c.chunks.inspect(*args)
            for index,path in [(4,('prior_semantics_replayed',)),(5,('state_destructor','typed_payload_cleanup_composed')),
                (5,('state_pointer_inside_owner',)),(6,('checked_next_sequence',)),
                (6,('phase_match_before_admission',)),(6,('unfinished_guard_clears_and_quarantines',)),
                (7,('payload_pointer_retained_from_worker_buffer',))]:
                bad=list(args);bad[index]=copy.deepcopy(args[index]);value=bad[index]
                for key in path[:-1]:value=value[key]
                value[path[-1]]=False
                with self.assertRaises(ValueError):c.chunks.inspect(*bad)
            for name in result['exact_replayed_helpers']:
                bad=list(args);bad[4]=copy.deepcopy(args[4]);del bad[4]['exact_body_reference_extent_and_abi'][name]
                with self.assertRaises(ValueError):c.chunks.inspect(*bad)
            for index,key in ((6,'operation'),(7,'setup_chunk')):
                bad=list(args);bad[index]=copy.deepcopy(args[index]);bad[index]['functions'][key]='wrong'
                with self.assertRaises(ValueError):c.chunks.inspect(*bad)
            bad=list(args);bad[7]=copy.deepcopy(args[7]);bad[7]['payload_limit']=1025
            with self.assertRaises(ValueError):c.chunks.inspect(*bad)
            for key in ('setup_finalization_qualified','descriptor_padding_erased','private_frame_erasure_qualified',
                        'all_unwind_paths_qualified','whole_image_qualified','descriptor_pointer_captured',
                        'descriptor_referenced_input_capture_claimed'):
                self.assertFalse(result[key])
            with patch.object(c.chunks,'inspect',side_effect=ValueError('chunks failed')) as check:
                with self.assertRaisesRegex(ValueError,'chunks failed'):c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()


class ChunkModelTests:
    def test_chunks_all_public_lengths_and_terminal_counts(self):
        for length in range(1025):
            for last in range(256):
                got=c.chunks.fragment(length,last)
                valid=last==0 if length==0 else 1<=last<=8
                self.assertEqual(got is not None,valid)
                if valid:
                    self.assertEqual(got['bits'],(length-1)*8+last if length else 0)
                    self.assertEqual(got['read_tail'],bool(length and last<8))
                    self.assertLessEqual(got['bits'],8192)
        for length in (1,1024):
            for last in range(1,9):
                for tail in range(256):
                    self.assertEqual(c.chunks.fragment(length,last,tail) is not None,tail<1<<last)
        for args in ((-1,0),(1025,8),(1,-1),(1,256),(1,1,256)):
            with self.assertRaises(ValueError):c.chunks.fragment(*args)

    def test_chunks_split_length_stores_cover_all_bytes_without_overlap(self):
        # The complete emitted contract separately binds each store to its slot.
        # Model the unusual 1+4+2+1 split independently of int.to_bytes(8).
        for length in list(range(1025))+[1<<i for i in range(64)]+[(1<<64)-1]:
            fields=[(0,length&255,1),(1,(length>>8)&0xffffffff,4),
                    (5,(length>>40)&0xffff,2),(7,length>>56,1)]
            output=bytearray(8);written=set()
            for offset,value,width in fields:
                places=set(range(offset,offset+width));self.assertFalse(places&written);written|=places
                output[offset:offset+width]=value.to_bytes(width,'little')
            self.assertEqual(written,set(range(8)));self.assertEqual(output,length.to_bytes(8,'little'))
