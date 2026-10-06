"""Focused kernel/transpose regressions included by the batch-chain test entry."""
import re
from unittest.mock import patch
import windows_enclave_sha2_simd_kernel as k


class KernelTests:
    def test_exact_integer_cube_roots_and_round_constants(self):
        for n in (*range(2000),1<<96,1<<192,409**3):
            r=k.cuberoot(n)
            self.assertLessEqual(r**3,n);self.assertGreater((r+1)**3,n)
        for lane,size,first,last in (
            ('simd256',4,0x428a2f98,0xc67178f2),
            ('simd512',8,0x428a2f98d728ae22,0x6c44198c4a475817)):
            raw=k.round_constants(lane)
            self.assertEqual(len(raw),64*size if size==4 else 80*size)
            self.assertEqual(int.from_bytes(raw[:size],'little'),first)
            self.assertEqual(int.from_bytes(raw[-size:],'little'),last)
        with self.assertRaises(ValueError): k.parameters('unreviewed')

    def test_transpose_bounds_endianness_and_inactive_lanes(self):
        count=0
        for bits in (32,64):
            word=bits//8;lanes=32//word
            for words in (8,16):
                size=words*32
                # Every public width, including zero, with distinct per-byte input.
                source=bytes((n*37+n//word)%256 for n in range(size))
                for width in range(lanes+1):
                    offsets=k.transpose_offsets(bits,words,width,True)
                    self.assertEqual(len(offsets),words*width)
                    self.assertEqual(len({a for a,_ in offsets}),len(offsets))
                    self.assertEqual(len({b for _,b in offsets}),len(offsets))
                    packed=bytearray(b'\xa5'*size)
                    for a,b in offsets:
                        self.assertTrue(0<=a<=size-word and 0<=b<=size-word)
                        packed[b:b+word]=source[a:a+word][::-1]
                    for index in range(words):
                        for lane in range(lanes):
                            actual=packed[index*32+lane*word:index*32+(lane+1)*word]
                            a=lane*words*word+index*word
                            self.assertEqual(actual,source[a:a+word][::-1] if lane<width else b'\xa5'*word)
                    restored=bytearray(b'\x5a'*size)
                    for a,b in k.transpose_offsets(bits,words,width,False):
                        restored[b:b+word]=packed[a:a+word][::-1]
                    self.assertEqual(restored[:width*words*word],source[:width*words*word])
                    self.assertEqual(restored[width*words*word:],b'\x5a'*((lanes-width)*words*word))
                    count+=1
            for width in (-1,lanes+1,True):
                with self.assertRaises(ValueError): k.transpose_offsets(bits,8,width,True)
        self.assertEqual(count,28)

    def test_kernel_schedule_bounds_and_cleanup_partition(self):
        for lane in k.CONSTANTS:
            bits,rounds,work,tmp,_=k.parameters(lane)
            self.assertEqual(work,256+32*rounds);self.assertEqual(tmp,work+256)
            for r in range(16,rounds):
                here=256+32*r
                self.assertEqual([here+delta for delta in (-512,-480,-224,-64)],
                                 [256+32*(r-back) for back in (16,15,7,2)])
                self.assertLessEqual(here+32,work)
            # Fixed vectors only: no shuffles/cross-lane instructions in either kernel.
            instructions=k.kernel_shape(lane)
            self.assertFalse(any(re.search(r'perm|shuf|blend|gather|scatter',v) for v in instructions))
            cleared=set(range(work))|set(range(tmp,tmp+192))
            self.assertEqual(set(range(tmp+192))-cleared,set(range(work,tmp)))
            self.assertEqual(rounds*(bits//8),len(k.round_constants(lane)))


class KernelSavedTests:
    def test_every_kernel_transpose_instruction_and_abi_envelope_is_required(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if lane not in k.CONSTANTS: continue
            names=[n for n in bodies if re.search(r'transfer9transpose|hardened_batch3x86(?:6secret8compress|15compress_secret)$',n)]
            self.assertEqual(len(names),5)
            k.inspect(bodies,lane)
            for name in names:
                lines=bodies[name].splitlines(keepends=True)
                for at,line in enumerate(lines):
                    code=line.strip()
                    if not code or code.startswith(('#','.')) or code.endswith(':'): continue
                    for replacement in ('\tnop\n','\tretq\n'+line):
                        bad=list(lines);bad[at]=replacement
                        with self.assertRaises(ValueError): k.inspect(bodies|{name:''.join(bad)},lane)
                        count+=1
            for marker in ('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END',
                           'BRYNJA_TRANSFER_BEGIN','BRYNJA_TRANSFER_ERASE','BRYNJA_TRANSFER_END'):
                name=next(n for n in names if marker in bodies[n])
                with self.assertRaises(ValueError):
                    k.inspect(bodies|{name:bodies[name].replace(marker,'REMOVED')},lane)
        self.assertGreater(count,1000)
        print('SIMD kernel/transpose instruction and early-return mutations rejected: '+str(count))

    def test_kernel_review_cannot_be_skipped_or_accept_other_constants(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,_,_,_,ir,_,bodies in self.routes:
            if lane not in k.CONSTANTS: continue
            with patch.object(k,'inspect',side_effect=ValueError('kernel review failed')) as gate:
                with self.assertRaisesRegex(ValueError,'kernel review failed'): c.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()
            raw=k.round_constants(lane);name=k.CONSTANTS[lane]
            constants={name:dict(bytes=len(raw),sha256=c.digest(raw))}
            c.public_constructor_constants(constants,lane)
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                with self.assertRaises(ValueError):
                    c.public_constructor_constants({name:dict(bytes=len(raw),sha256=c.digest(bad))},lane)
