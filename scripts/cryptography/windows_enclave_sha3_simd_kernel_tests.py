"""Four-lane leaf geometry and saved-code negative regressions."""
import hashlib
from unittest.mock import patch
import windows_enclave_sha3_simd_kernel as k


def constants():
    return {k.TABLE:dict(bytes=192,sha256=hashlib.sha256(k.round_constants()).hexdigest())}


class SimdKernelModelTests:
    def test_simd_leaf_round_constants_and_rotation_coordinates(self):
        raw=k.round_constants()
        # Independent published Keccak-f[1600] table, not a production import.
        expected=[0x1,0x8082,0x800000000000808a,0x8000000080008000,
            0x808b,0x80000001,0x8000000080008081,0x8000000000008009,
            0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,
            0x8000000000008089,0x8000000000008003,0x8000000000008002,
            0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,
            0x8000000000008080,0x80000001,0x8000000080008008]
        self.assertEqual(raw,b''.join(n.to_bytes(8,'little') for n in expected))
        rho=k.rotations()
        self.assertEqual([rho[x,y] for y in range(5) for x in range(5)],
            [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14])
        self.assertEqual({(y,(2*x+3*y)%5) for x,y in rho},set(rho))

    def test_simd_leaf_transpose_bounds_roundtrip_and_inactive_bytes(self):
        source=bytes((i*37+i//8)%256 for i in range(800))
        for width in range(5):
            packed=bytearray(b'\xa5'*800);restored=bytearray(b'\x5a'*800)
            pairs=k.offsets(width,True)
            self.assertEqual(len(pairs),25*width)
            self.assertEqual(len({a for a,_ in pairs}),25*width)
            self.assertEqual(len({b for _,b in pairs}),25*width)
            for a,b in pairs:
                self.assertTrue(0<=a<=792 and 0<=b<=792)
                packed[b:b+8]=source[a:a+8]
            for word in range(25):
                for lane in range(4):
                    expected=source[200*lane+8*word:200*lane+8*word+8] if lane<width else b'\xa5'*8
                    self.assertEqual(packed[32*word+8*lane:32*word+8*lane+8],expected)
            for a,b in k.offsets(width,False):restored[b:b+8]=packed[a:a+8]
            self.assertEqual(restored[:200*width],source[:200*width])
            self.assertEqual(restored[200*width:],b'\x5a'*(800-200*width))
        for width in (-1,5,True,2.0):
            with self.assertRaises(ValueError):k.offsets(width,True)

    def test_simd_leaf_vector_bounds_and_erasure_partition(self):
        states={32*(x+5*y) for x in range(5) for y in range(5)}
        columns={800+32*x for x in range(5)};deltas={960+32*x for x in range(5)}
        staging={1120+32*(y+5*((2*x+3*y)%5)) for x in range(5) for y in range(5)}
        self.assertEqual(states|columns|deltas|staging,set(range(0,1920,32)))
        cleared={b for a in range(800,1920,32) for b in range(a,a+32)}
        self.assertEqual(cleared,set(range(800,1920)))
        self.assertEqual(set(range(1920))-cleared,set(range(800)))
        code=k.kernel_shape()
        self.assertFalse(any('rsp' in l or 'call' in l or 'shuf' in l or 'perm' in l for l in code))
        self.assertEqual(code.count('vzeroupper'),1)


class SimdKernelSavedTests:
    def test_simd_leaf_every_instruction_and_marker_rejects_changes(self):
        _,_,_,ir,_,bodies=self.routes['simd']
        result=k.inspect(bodies,ir,constants());count=0
        for name in result['functions'].values():
            lines=bodies[name].splitlines(keepends=True)
            for at,line in enumerate(lines):
                text=line.strip()
                if not text or text.startswith('#') or text.startswith('.Lfunc'):continue
                if text==name+':' or text.startswith('.seh_proc'):continue
                for replacement in ('\tnop\n','\tretq\n'+line):
                    bad=list(lines);bad[at]=replacement
                    with self.assertRaises(ValueError):k.inspect(bodies|{name:''.join(bad)},ir,constants())
                    count+=1
            for marker in ('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END',
                           'BRYNJA_TRANSFER_BEGIN','BRYNJA_TRANSFER_ERASE','BRYNJA_TRANSFER_END'):
                if marker in bodies[name]:
                    with self.assertRaises(ValueError):
                        k.inspect(bodies|{name:bodies[name].replace(marker,'REMOVED')},ir,constants())
        self.assertGreater(count,600)
        print('Keccak SIMD leaf instruction/label/envelope mutations rejected:',count)

    def test_simd_leaf_linked_constants_and_resolved_abis_fail_closed(self):
        _,_,_,ir,_,bodies=self.routes['simd'];good=constants()
        result=k.inspect(bodies,ir,good);raw=k.round_constants()
        for at in range(len(raw)):
            bad=bytearray(raw);bad[at]^=1
            with self.assertRaises(ValueError):k.inspect(bodies,ir,{k.TABLE:dict(bytes=192,sha256=hashlib.sha256(bad).hexdigest())})
        for bad in ({},{k.TABLE:good[k.TABLE]|{'bytes':191}}):
            with self.assertRaises(ValueError):k.inspect(bodies,ir,bad)
        count=0
        for name in result['functions'].values():
            declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for before,after in [('nonnull',''),('noundef',''),('fastcc',''),
                ('dereferenceable(1920)','dereferenceable(1919)'),('range(i64 2, 5)','range(i64 0, 5)')]:
                if before not in declaration:continue
                with self.assertRaises(ValueError):k.inspect(bodies,ir.replace(declaration,declaration.replace(before,after)),good)
                count+=1
        self.assertEqual(count,16)
        with self.assertRaises(ValueError):k.inspect(bodies,ir.replace('+avx2','+avx512f'),good)

    def test_simd_leaf_integrated_review_cannot_be_skipped(self):
        import windows_enclave_sha3_batch_chains as c
        with patch.object(k,'inspect',side_effect=ValueError('SIMD leaf review rejected')) as call:
            with self.assertRaisesRegex(ValueError,'SIMD leaf review rejected'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
