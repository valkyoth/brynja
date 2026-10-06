"""Strict allowlisted ABI/reference reuse and positive-length clear tests."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_simd_reuse as r


class ReuseTests:
    def test_simd_reuse_abi_only_allows_named_substitutions(self):
        for role in ('compress', 'wipe', 'copy', 'bytes', 'zero'):
            argument = '%2' if role == 'bytes' else '%1'
            bound = 'range(i64 0, 256)' if role in ('copy', 'bytes') else 'range(i64 0, -9223372036854775808)'
            before = f'fastcc readonly dereferenceable(640) {bound} {argument} "target-features"="{r.FEATURES}"'
            current = before.replace(r.FEATURES, r.SIMD_FEATURES)
            if role in ('copy', 'bytes'): current = current.replace('range(i64 0, 256)', 'range(i64 0, -9223372036854775808)')
            if role == 'zero': current = current.replace('range(i64 0,', 'range(i64 1,')
            r.abi(before, current, role)
            for bad in (current.replace('+avx2', '-avx2'), current.replace('fastcc', 'ccc'),
                        current.replace('readonly', ''), current.replace('640', '639'),
                        current.replace('range(i64', 'range(i32'), current + ' nounwind', before):
                with self.assertRaises(ValueError): r.abi(before, bad, role)
            with self.assertRaises(ValueError): r.abi(before + before, current, role)
        with self.assertRaises(ValueError): r.abi('', '', 'unreviewed')

    def test_simd_copy_and_clear_geometries_cover_exact_bytes(self):
        for length in range(4097):
            copy = r.transfer_geometry(length)
            visited = [i for word in range(copy['word_iterations']) for i in range(8 * word, 8 * word + 8)]
            visited += list(range(copy['word_end'], copy['tail_end']))
            self.assertEqual(visited, list(range(length)))
            if not length: continue
            clear = r.zero_geometry(length)
            visited = list(range(*clear['prefix']))
            visited += [i for word in range(clear['word_iterations'])
                        for i in range(clear['word_start'] + 8 * word, clear['word_start'] + 8 * word + 8)]
            self.assertEqual(visited, list(range(length)))
        for length in (r.BOUND - 8, r.BOUND - 1):
            self.assertEqual(r.transfer_geometry(length)['tail_end'], length)
            self.assertEqual(r.zero_geometry(length)['word_end'], length)
            self.assertLessEqual(r.transfer_geometry(length)['last_word'] + 8, length)
            self.assertEqual(r.zero_geometry(length)['last_word'] + 8, length)
        for bad in (-1, True, r.BOUND):
            with self.assertRaises(ValueError): r.transfer_geometry(bad)
            with self.assertRaises(ValueError): r.zero_geometry(bad)
        with self.assertRaises(ValueError): r.zero_geometry(0)


class ReuseSavedTests:
    def test_simd_helpers_reject_body_reference_extent_and_abi_drift(self):
        _, old_data, old_ir, _ = r.prior.prior(self.saved, 'scalar')
        previous = r.prior.c.previous.inventory(old_data); count = 0
        for lane, _, _, _, ir, functions, _ in self.routes:
            if not lane.startswith('simd'): continue
            raw = r.kernel.round_constants(lane)
            constants = {r.kernel.CONSTANTS[lane]: dict(bytes=len(raw), sha256=r.prior.digest(raw))}
            matched = r.helpers(functions, previous, ir, old_ir, lane, constants)
            self.assertEqual(set(matched), {'compress', 'copy', 'bytes', 'wipe'})
            for role, name in r.names(functions, lane).items():
                code, refs, kind = functions[name]
                for change in ((bytes([code[0] ^ 1]) + code[1:], refs, kind),
                               (code[:-1], refs, kind), (code, refs, not kind),
                               (code, refs + [dict(offset=0, symbol='unexpected', trailing=0, addend=0)], kind)):
                    with self.assertRaises(ValueError):
                        r.helpers(functions | {name: change}, previous, ir, old_ir, lane, constants)
                    count += 1
                header = next(line for line in ir.splitlines() if line.startswith('define ') and '@' + name + '(' in line)
                for token in ('fastcc', 'noundef', 'nonnull'):
                    bad = ir.replace(header, header.replace(token, 'BROKEN', 1))
                    with self.assertRaises(ValueError): r.helpers(functions, previous, bad, old_ir, lane, constants)
                    count += 1
                if role != 'compress': continue
                for field, value in (('offset', 0), ('symbol', 'different-table'), ('trailing', 1), ('addend', 4)):
                    changed = copy.deepcopy(refs); changed[0][field] = value
                    with self.assertRaises(ValueError):
                        r.helpers(functions | {name: (code, changed, kind)}, previous, ir, old_ir, lane, constants)
                    count += 1
            for bad in ({}, {r.kernel.CONSTANTS[lane]: dict(bytes=len(raw) - 1, sha256=r.prior.digest(raw))},
                        {r.kernel.CONSTANTS[lane]: dict(bytes=len(raw), sha256='0' * 64)}):
                with self.assertRaises(ValueError): r.helpers(functions, previous, ir, old_ir, lane, bad)
                count += 1
        self.assertEqual(count, 70)
        print('SIMD primitive body/reference/ABI/constant mutations rejected: ' + str(count))

    def test_simd_zeroizer_rejects_instruction_and_store_width_changes(self):
        count = 0
        for lane, _, _, _, _, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            self.assertFalse(r.zeroizer(bodies)['all_callers_checked'])
            lines = r.s.lines(bodies[r.s.ZERO])
            for index, line in enumerate(lines[2:], 2):
                if line.endswith(':') or line.startswith('.'): continue
                for replacement in ('retq', 'nop'):
                    if line == replacement: continue
                    bad = lines[:]; bad[index] = replacement
                    with self.assertRaises(ValueError): r.zeroizer(bodies | {r.s.ZERO: '\n'.join(bad)})
                    count += 1
            for index, line in enumerate(lines):
                if not line.startswith('movb $0,'): continue
                bad = lines[:]; bad[index] = line.replace('movb', 'movq')
                with self.assertRaises(ValueError): r.zeroizer(bodies | {r.s.ZERO: '\n'.join(bad)})
                count += 1
        self.assertEqual(count, 112)
        print('SIMD zeroizer instruction/store mutations rejected: ' + str(count))

    def test_simd_reuse_replays_prior_review_and_is_required_by_parent(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane, pin, _, _, ir, functions, bodies in self.routes:
            if not lane.startswith('simd'): continue
            with patch.object(r.prior, 'prior', side_effect=ValueError('prior proof failed')) as gate:
                with self.assertRaisesRegex(ValueError, 'prior proof failed'):
                    r.inspect(self.saved, lane, functions, ir, bodies, {})
                gate.assert_called_once()
            with patch.object(r, 'inspect', side_effect=ValueError('SIMD reuse failed')) as gate:
                with self.assertRaisesRegex(ValueError, 'SIMD reuse failed'):
                    chains.inspect_route(self.saved, self.root, lane, pin, False)
                gate.assert_called_once()
