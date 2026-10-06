"""Worker admission/lifetime checks used by the saved batch-chain test entry."""
from unittest.mock import patch
import windows_enclave_sha2_simd_worker as w


class WorkerTests:
    def test_worker_identity_decoder_full_low_domain_and_u64_edges(self):
        for value in (*range(65536),(1<<32)-1,(1<<63),(1<<64)-1):
            for narrow in (True,False):
                expected=({224:0,256:1}.get(value) if narrow else
                    value-512 if 512<=value<=515 else (value<<16)|4 if 1<=value<=511 and value!=384 else None)
                self.assertEqual(w.identity(value,narrow),expected)

    def test_worker_lane_command_length_tail_and_address_boundaries(self):
        maximum=(1<<64)-1
        for lane,digest,block,code in (('simd256',100,64,256),('simd512',90,128,513)):
            for size in (0,block-1,block,block+1,1023,1024,1025,maximum):
                for last in range(10):
                    for source in (0,1,maximum-size,maximum):
                        expected=(block<=size<=1024 and 1<=last<=8 and (size!=block or last==8)
                                  and source!=0 and source+size<=maximum)
                        self.assertEqual(w.admitted_lane(lane,digest,code,size,last,source),expected)
            self.assertTrue(w.admitted_lane(lane,digest+1,code,0,0,0))
            self.assertTrue(w.admitted_lane(lane,digest+2,0,0,0,0))
            for at in range(4):
                fields=[0,0,0,0];fields[at]=1
                self.assertFalse(w.admitted_lane(lane,digest+2,*fields))
            for at in range(1,4):
                fields=[code,0,0,0];fields[at]=1
                self.assertFalse(w.admitted_lane(lane,digest+1,*fields))
            self.assertFalse(w.admitted_lane(lane,digest-1,code,block,8,1))
            for bad in (-1,1<<64,True):
                with self.assertRaises(ValueError): w.admitted_lane(lane,digest,code,block,8,bad)

    def test_worker_page_and_window_disjointness(self):
        maximum=(1<<64)-1
        for low in (0,4096,8192,1<<32,maximum-65536,maximum):
            for high in (low,min(maximum,low+65535),min(maximum,low+65536),maximum):
                for page in (0,1,4096,8192,65536,69632,maximum-4095):
                    expected=(page>0 and page%4096==0 and high-low==65536 and
                              page<=maximum-4096 and not (page<high and low<page+4096))
                    self.assertEqual(w.admitted_window(page,low,high),expected)
        self.assertTrue(w.admitted_window(4096,8192,73728))
        self.assertTrue(w.admitted_window(73728,8192,73728))
        self.assertFalse(w.admitted_window(8192,8192,73728))

    def test_worker_receipt_loops_cover_exact_buffers(self):
        for payload,header,narrow in ((8192,288,True),(4096,160,False)):
            header_bytes=[a+d for a in range(payload+3,payload+header+3,4) for d in (-3,-2,-1,0)]
            if narrow:
                payload_bytes=([a+d for a in range(2,payload+1,3) for d in (-2,-1)]+
                    [a for a in range(2,payload,3)])
            else: payload_bytes=[a+d for a in range(3,payload+3,4) for d in (-3,-2,-1,0)]
            self.assertEqual(sorted(payload_bytes),list(range(payload)))
            self.assertEqual(header_bytes,list(range(payload,payload+header)))


class WorkerSavedTests:
    def test_worker_review_is_required(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            with patch.object(w,'inspect',side_effect=ValueError('worker review failed')) as gate:
                with self.assertRaisesRegex(ValueError,'worker review failed'): c.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()

    def test_export_success_cannot_return_before_clear(self):
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            name=w.role(bodies,'receive');label='.B65' if lane=='simd256' else '.B73'
            lines=w.s.lines(bodies[name]);at=lines.index(label+':')+1
            lines.insert(at,'retq')
            with self.assertRaises(ValueError): w.inspect(bodies|{name:'\n'.join(lines)},lane)
