"""Review-binding and bounded gate-word checks, not a scheduler model checker."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_publication_review as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={}
        for name,code in bodies.items():
            refs[name]=review.store_refs(name)+[dict(offset=review.ABORT[name],symbol='PrivateWaveAbort',addend=0,trailing=0)]
            for ref in refs[name][:-1]:
                offset=ref['offset']
                code[offset-3:offset+8]=b'\x48\xc7\x05'+ref['addend'].to_bytes(4,'little',signed=True)+bytes(4)
            offset=review.ABORT[name]
            code[offset-1:offset+4]=b'\xe8\0\0\0\0'
            for offset,hexcode in review.anchors(name):
                value=bytes.fromhex(hexcode)
                code[offset:offset+len(value)]=value
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_all_load_bearing_instruction_bytes(self):
        bodies,refs=self.synthetic()
        review.check_instructions(bodies,refs)
        for name,code in bodies.items():
            sites=[(r['offset']-3,11) for r in refs[name][:-1]]+[(review.ABORT[name]-1,5)]
            sites += [(offset,len(bytes.fromhex(h))) for offset,h in review.anchors(name)]
            for offset,size in sites:
                for i in range(offset,offset+size):
                    changed=bytearray(code)
                    changed[i]^=1
                    with self.assertRaises(ValueError):
                        review.check_instructions(bodies|{name:bytes(changed)},refs)

    def test_exact_reference_population_and_fields(self):
        bodies,refs=self.synthetic()
        for name,rows in refs.items():
            variants=[rows[:-1],rows+[rows[0]],list(reversed(rows))]
            for key,value in (('offset',1),('symbol','other'),('addend',0),('trailing',4)):
                variants.append([rows[0]|{key:value},*rows[1:]])
            for changed in variants:
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{name:changed})

    def test_entire_body_identity_and_population(self):
        bodies,_=self.synthetic()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for name,code in bodies.items():
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError):
                    review.check_bodies({n:b for n,b in bodies.items() if n!=name})
                for i in range(len(code)):
                    changed=bytearray(code)
                    changed[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:bytes(changed)})
                    count+=1
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,919)

    def test_close_preserves_generation_and_live_tickets(self):
        for low in range(1<<19):
            word=(0xffffffff<<32)|low
            closed=review.close_word(word)
            self.assertEqual(closed,(word & ~(1<<17)) | (1<<18))
            self.assertEqual(closed>>32,0xffffffff)
            self.assertEqual(closed&0xf0,word&0xf0)
            self.assertEqual(review.quiescent(closed),low&0xf0==0)
            self.assertEqual(review.quiescent(word),not bool(low&(1<<17)) and bool(low&(1<<18)) and not bool(low&0xf0))
        for bad in (-1,1<<64,True,1.0):
            with self.assertRaises(ValueError): review.close_word(bad)
            with self.assertRaises(ValueError): review.quiescent(bad)

    def test_quiescence_is_not_success_or_retirement(self):
        # Success/claimed masks are not required by join. Failure must still join.
        for claimed in range(16):
            for success in range(16):
                word=(9<<32)|0x40000|(success<<8)|claimed
                self.assertTrue(review.quiescent(word))
                self.assertNotEqual(review.close_word(word),9<<32)  # does not retire
                for live in range(1,16): self.assertFalse(review.quiescent(word|(live<<4)))

    def globals(self):
        targets={review.PREFIX+n:1000+i*64 for i,n in enumerate(review.GLOBALS)}
        rows=[dict(rva=1000,virtual_size=320,flags=0x80000000)]
        records={n:dict(reference_targets=dict(targets)) for n in review.BODIES}
        return rows,records

    def test_global_ranges_and_eleven_distinct_store_addresses(self):
        rows,records=self.globals()
        spans=review.writable_spans(rows,records)
        self.assertEqual(sum(s['bytes'] for s in spans),88)
        reference=records['join']['reference_targets']
        addresses=[reference[r['symbol']]+r['addend']+4 for r in review.store_refs('join')]
        self.assertEqual(len(set(addresses)),11)
        self.assertEqual(addresses,[1000,1008,1016,1024,1064,1072,1080,1088,1128,1192,1256])
        for invalid in ([],rows*2,[rows[0]|{'flags':0xa0000000}],[rows[0]|{'flags':0}],
                        [rows[0]|{'virtual_size':260}]):
            with self.assertRaises(ValueError): review.writable_spans(invalid,records)
        key=review.PREFIX+'5SLOTS'
        records['drop']['reference_targets'][key]+=8
        with self.assertRaises(ValueError): review.writable_spans(rows,records)
        rows,records=self.globals()
        for r in records.values(): r['reference_targets'][review.PREFIX+'4BITS']=1016
        with self.assertRaises(ValueError): review.writable_spans(rows,records)

    def test_identity_before_parsing(self):
        with patch.object(review.caller,'function',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
