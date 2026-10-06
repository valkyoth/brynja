"""Focused caller-boundary regressions; included by the saved chain test entry."""
import re
from unittest.mock import patch
import windows_enclave_sha2_simd_digest as d


class DigestTests:
    def test_digest_canonical_tail_and_length_boundaries(self):
        for length in (0,1,63,64,65,127,128,129,1023,1024,1025,(1<<64)-1):
            for last in range(10):
                for tail in range(256):
                    good=(length<=1024 and ((length==0 and last==0) or
                          (length>0 and 1<=last<=8 and tail % (1<<(8-last))==0)))
                    expected=(0 if length==0 else (length-1)*8+last) if good else None
                    self.assertEqual(d.admission_bits(length,last,tail),expected)
        for index,bad in ((0,-1),(0,1<<64),(1,256),(2,256),(1,True)):
            args=[1,8,0];args[index]=bad
            with self.assertRaises(ValueError): d.admission_bits(*args)

    def test_digest_output_width_ceil_and_storage_bound(self):
        for tag,expected in enumerate((48,64,28,32)):
            for unused in (0,1,511,65535): self.assertEqual(d.output_width(tag,unused),expected)
        for bits in range(65536):
            expected=-(-bits//8)
            self.assertEqual(d.output_width(4,bits),expected)
            self.assertEqual(expected<=64,bits<=512)
        for tag,bits in ((-1,0),(5,0),(True,0),(4,-1),(4,65536)):
            with self.assertRaises(ValueError): d.output_width(tag,bits)

    def test_digest_slot_and_input_layouts_are_disjoint_within_active_lifetime(self):
        for count,width,inputs,scratch,descriptors,owner in (
            (8,32,544,3936,864,16),(4,64,192,1376,352,24)):
            slots=[set(range(scratch+i*width,scratch+(i+1)*width)) for i in range(count)]
            self.assertEqual(sum(map(len,slots)),len(set.union(*slots)))
            self.assertEqual(set.union(*slots),set(range(scratch,scratch+256)))
            ranges=[set(range(inputs,inputs+count*40)),set(range(descriptors,descriptors+count*16)),
                    set.union(*slots)]
            for i,a in enumerate(ranges):
                for b in ranges[i+1:]: self.assertFalse(a&b)
            # Both copy paths cover each owner's output slot once, not all 256
            # bytes per copy. Shorter identities leave their zeroed slot tail.
            destination=[range(owner+i*width,owner+(i+1)*width) for i in range(count)]
            self.assertEqual([n for r in destination for n in r],list(range(owner,owner+256)))


class DigestSavedTests:
    def test_digest_caller_review_is_required(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            with patch.object(d,'inspect',side_effect=ValueError('digest caller review failed')) as gate:
                with self.assertRaisesRegex(ValueError,'digest caller review failed'): c.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()

    def test_digest_caller_early_returns_cannot_skip_output_or_workspace_cleanup(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            name=d.storage.symbols(bodies)['resident'];lines=d.s.lines(bodies[name])
            labels=(('.B261','.B262','.B266','.Ltmp67','.B271','.B251','.B253','.B256') if lane=='simd256'
                    else ('.Ltmp73','.B70','.B72','.Ltmp75','.B90','.B81','.B68'))
            d.inspect(bodies,lane)
            for label in labels:
                at=lines.index(label+':')+1;bad=lines[:at]+['retq']+lines[at:]
                with self.assertRaises(ValueError): d.inspect(bodies|{name:'\n'.join(bad)},lane)
                count+=1
        self.assertEqual(count,15)
        print('SIMD retained-output premature returns rejected: '+str(count))

    def test_digest_guard_cannot_be_disarmed_after_admission(self):
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            name=d.storage.symbols(bodies)['resident'];lines=d.s.lines(bodies[name])
            flag=55 if lane=='simd256' else 54
            at=lines.index('.B13:')+1
            bad=lines[:at]+[f'movb $1, {flag}(%rbx)']+lines[at:]
            with self.assertRaises(ValueError): d.admission(bodies|{name:'\n'.join(bad)},lane)

    def test_digest_width_dispatch_binds_every_entry_and_unique_population(self):
        import windows_enclave_sha2_batch_chains as c
        count=0
        for lane,pin,_,_,_,_,bodies in self.routes:
            if lane!='simd512': continue
            _,_,_,assembly,_,_=c.load(self.saved,self.root,pin)
            tables=d.wide_widths(bodies,assembly)
            self.assertEqual(len(tables),4)
            for table,labels in tables.items():
                for label in labels:
                    before=f'.LBB35_{label}-{table}'
                    self.assertEqual(assembly.count(before),1)
                    bad=assembly.replace(before,f'.LBB35_66-{table}')
                    with self.assertRaises(ValueError): d.wide_widths(bodies,bad)
                    count+=1
                definition=re.search(r'^'+re.escape(table)+r':\n(?:\s*\.long\s+[^\n]+\n)+',assembly,re.M)[0]
                for bad in (assembly.replace(definition,''),assembly+'\n'+definition):
                    with self.assertRaises(ValueError): d.wide_widths(bodies,bad)
                    count+=1
        self.assertEqual(count,28)
        print('SIMD output-width dispatch mutations rejected: '+str(count))
