"""Selected cleanup-instruction and write-coverage models; not enclave execution."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_state_cleanup as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={}
        for name,edges in review.TRANSFERS.items():
            refs[name]=[dict(offset=o,symbol=s,addend=0,trailing=0) for o,(s,_) in edges.items()]
            for offset,(_,opcode) in edges.items():
                bodies[name][offset-1:offset+4]=bytes([opcode])+bytes(4)
        for name,offset,hexcode in review.ANCHORS:
            code=bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)]=code
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_instructions_and_tail_restoration(self):
        bodies,refs=self.synthetic()
        review.check_instructions(bodies,refs)
        self.assertEqual((len(review.ANCHORS),sum(map(len,review.TRANSFERS.values()))),(23,16))
        sites=[(n,o-1,5) for n,edges in review.TRANSFERS.items() for o in edges]
        sites += [(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        for name,offset,size in sites:
            for i in range(offset,offset+size):
                changed=bytearray(bodies[name])
                changed[i]^=1
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies|{name:bytes(changed)},refs)
        self.assertEqual(review.TRANSFERS['memory'][0x46],(review.slot.CLEAR,0xe9))
        self.assertEqual(review.TRANSFERS['scratch'][0x7c],(review.slot.CLEAR,0xe9))

    def test_no_missing_extra_or_redirected_call(self):
        bodies,refs=self.synthetic()
        for name,rows in refs.items():
            variants=[rows+[dict(offset=1,symbol='extra',addend=0,trailing=0)]]
            if rows:
                variants += [rows[:-1],rows+[rows[0]]]
                for key,value in (('offset',0),('symbol','other'),('addend',1),('trailing',1)):
                    variants.append([rows[0]|{key:value},*rows[1:]])
            for changed in variants:
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{name:changed})

    def test_complete_review_identity(self):
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
        self.assertEqual(count,495)

    def test_remainder_loop_covers_every_byte_once(self):
        for length in (*range(4097),65535,65536):
            self.assertEqual(review.clear_offsets(length),list(range(length)))
        for bad in (-1,65537,True,1.0):
            with self.assertRaises(ValueError): review.clear_offsets(bad)

    def test_exact_regions_no_padding_or_metadata_invented(self):
        def expanded(regions): return [offset+i for offset,size in regions for i in range(size)]
        memory=expanded(review.MEMORY_REGIONS)
        scratch=expanded(review.SCRATCH_REGIONS)
        self.assertEqual(sorted(memory),list(range(234)))
        self.assertEqual(scratch,list(range(576)))
        self.assertEqual(len(set(memory)),234)
        for prefix in (False,True):
            result=review.write_ranges(False,prefix)
            volatile=expanded(result['volatile'])
            self.assertEqual(set(volatile),set(range(576))|set(range(624,858))|({936} if prefix else set()))
            self.assertEqual(len(volatile),1044+int(prefix))
            self.assertEqual(result['ordinary_zero'],[(616,8)]+([(937,1),(864,64)] if prefix else []))
            self.assertEqual(result['ordinary_marker'],[(859,1),(938,1),(962,1)])
            # Wipes cannot change the prefix-discriminant store: the second
            # conditional prefix drop is skipped on this valid normal path.
            self.assertNotIn(938,volatile+expanded(result['ordinary_zero']))
            self.assertNotIn(944,volatile)  # whole State tag is not erased
            self.assertLess(len(set(volatile)),992)

    def test_empty_variant_never_reads_or_erases_payload(self):
        for prefix in (False,True):
            self.assertEqual(review.write_ranges(True,prefix),dict(volatile=[],ordinary_zero=[],ordinary_marker=[]))
        for args in ((0,False),(False,1),(None,True)):
            with self.assertRaises(ValueError): review.write_ranges(*args)

    def test_geometry_distinguishes_tail_and_direct_entry(self):
        result=review.geometry(review.Window(0,65536))
        self.assertEqual(result['state_from_high'],-2560)
        self.assertEqual(result['helper_from_high'],-2608)
        self.assertEqual(result['direct_clear_entry_from_high'],-2616)
        self.assertEqual(result['tail_clear_entry_from_high'],-2568)
        self.assertFalse(result['scoped_cleanup_chain_has_external_callees'])
        self.assertFalse(result['maximum_whole_worker_depth_qualified'])
        self.assertFalse(result['exception_cleanup_qualified'])
        for low in (4096,1<<32,(1<<64)-69632):
            self.assertEqual(result,review.geometry(review.Window(low,low+65536)))

    def test_identity_before_parsing(self):
        with patch.object(review.caller,'function',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
