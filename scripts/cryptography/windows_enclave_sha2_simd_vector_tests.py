"""Vector-loop snapshot mutations and independent geometry/accounting tests."""
import itertools
from unittest.mock import patch
import windows_enclave_sha2_simd_vector as v


class VectorTests:
    def test_vector_geometry_all_active_masks_preserves_original_lane_order(self):
        for lane in ('simd256', 'simd512'):
            capacity, state, block = v.parameters(lane)
            for mask in range(1 << capacity):
                indices = [i for i in range(capacity) if mask & (1 << i)]
                inputs = [(1024, 8192 - 8 * i) if i in indices else None for i in range(capacity)]
                for width in (capacity, capacity // 2):
                    groups = v.geometry(lane, width, indices, inputs)
                    used = [r['index'] for g in groups for r in g['rows']]
                    self.assertEqual(used, indices[:len(indices) // width * width])
                    for group in groups:
                        self.assertEqual(group['common'], min(inputs[r['index']][1] // (8 * block)
                                                             for r in group['rows']))
                        states = [bytes([i]) * state for i in range(capacity)]
                        packed = [states[r['index']] for r in group['rows']]
                        restored = states[:]
                        for row, value in zip(group['rows'], packed):
                            restored[row['index']] = value
                            self.assertLessEqual(row['state'][1], 256)
                            self.assertLessEqual(row['packed_state'][1], 256)
                            self.assertLessEqual(row['block_destination'][1], 512)
                        self.assertEqual(restored, states)

    def test_vector_geometry_permutations_and_partial_groups(self):
        for lane in ('simd256', 'simd512'):
            capacity, _, block = v.parameters(lane)
            # Deliberately nonascending indices catch an accidental lane=index
            # assumption; width differs from capacity on the smaller kernel.
            for indices in itertools.permutations(range(capacity), capacity // 2):
                inputs = [(block, 8 * block)] * capacity
                group = v.geometry(lane, capacity // 2, indices, inputs)[0]
                self.assertEqual([r['index'] for r in group['rows']], list(indices))
                self.assertEqual([r['packed'] for r in group['rows']], list(range(capacity // 2)))
                self.assertEqual(v.geometry(lane, capacity, indices, inputs), [])

    def test_vector_block_boundary_and_maximum_bit_count_never_overread(self):
        for lane in ('simd256', 'simd512'):
            capacity, _, block = v.parameters(lane)
            for bits in (0, 1, 7, 8, 8 * block - 1, 8 * block, 8 * block + 1,
                         8191, 8192, v.MAX):
                available = (bits + 7) // 8
                blocks = bits // (8 * block)
                groups = v.geometry(lane, capacity, list(range(capacity)), [(available, bits)] * capacity,
                                    1 if lane == 'simd256' else 0)
                if blocks == 0 and lane == 'simd256':
                    self.assertEqual(groups, [])
                    continue
                row = groups[0]['rows'][0]
                self.assertEqual(row['input_end'], blocks * block)
                self.assertEqual(row['offset'], blocks)
                self.assertEqual(row['last_block_start'], (blocks - 1) * block if blocks else None)
                self.assertLessEqual(row['input_end'], available)
                self.assertLessEqual(row['input_end'], v.MAX)
                if bits >= 8:
                    with self.assertRaises(ValueError):
                        v.geometry(lane, capacity, list(range(capacity)), [(bits // 8 - 1, bits)] * capacity)

    def test_vector_invalid_geometry_and_compaction_preconditions_reject(self):
        for lane in ('simd256', 'simd512'):
            capacity, _, _ = v.parameters(lane); inputs = [(1024, 8192)] * capacity
            for indices in ([0, 0], [capacity], [-1], [True], list(range(capacity + 1))):
                with self.assertRaises(ValueError): v.geometry(lane, capacity, indices, inputs)
            for width in (0, 1, capacity + 1, True, -1, 1 << 64):
                with self.assertRaises(ValueError): v.geometry(lane, width, [], inputs)
            with self.assertRaises(ValueError): v.geometry(lane, capacity, [0], [None] * capacity)
            with self.assertRaises(ValueError): v.geometry(lane, capacity, [], inputs[:-1])
            for invalid in (-1, True, 1 << 64):
                with self.assertRaises(ValueError):
                    v.geometry(lane, capacity, list(range(capacity)), [(invalid, 0)] * capacity)
        with self.assertRaises(ValueError): v.parameters('unreviewed')

    def test_vector_accounting_exact_maximum_and_failed_completion(self):
        for width in (2, 4, 8):
            self.assertEqual(v.account(width, width, v.MAX - width, v.MAX - 1, v.MAX,
                                       v.MAX - 1, v.MAX - width), (0, v.MAX, v.MAX, v.MAX))
            for budget in range(width):
                self.assertEqual(v.account(width, budget, 0, 0, 1, 0, 0), 'WorkLimit')
            for args in ((width, v.MAX - width + 1, 0, 1, 0, 0),
                         (width, 0, v.MAX, 0, 0, 0), (width, 0, 0, 0, 0, 0),
                         (width, 0, 0, 2, 0, 0), (width, 0, 0, 1, v.MAX, 0),
                         (width, 0, 0, 1, 0, v.MAX - width + 1)):
                self.assertEqual(v.account(width, *args), 'Invariant')
        with self.assertRaises(ValueError): v.account(0, 0, 0, 0, 0, 0, 0)


class VectorSavedTests:
    def test_vector_review_is_required_without_claiming_frame_completion(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane, _, _, _, ir, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            report = v.inspect(bodies, lane)
            self.assertFalse(report['whole_frame_qualified'])
            self.assertTrue(report['scalar_finish_and_machine_frame_lifetimes_pending'])
            with patch.object(v, 'inspect', side_effect=ValueError('vector review failed')) as gate:
                with self.assertRaisesRegex(ValueError, 'vector review failed'):
                    chains.shapes.inspect(bodies, ir, lane)
                gate.assert_called_once()

    def test_every_vector_instruction_rejects_removal_insertion_and_early_return(self):
        counts = {}
        for lane, _, _, _, _, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            report = v.inspect(bodies, lane); name = report['function']; lines = v.s.lines(bodies[name]); count = 0
            for start, end, expected in v.regions(bodies, lane):
                first = lines.index(start + ':'); last = lines.index(end + ':')
                for index in range(first, last):
                    if lines[index].endswith(':'): continue
                    for replacement in ([], ['nop', lines[index]], ['retq']):
                        bad = lines[:index] + replacement + lines[index + 1:]
                        with self.assertRaises(ValueError): v.inspect(bodies | {name: '\n'.join(bad)}, lane)
                        count += 1
            counts[lane] = count
        self.assertEqual(counts, {'simd256': 687, 'simd512': 861})
        print('SIMD vector instruction/control mutations rejected: ' + str(counts))

    def test_vector_region_rejects_external_side_entries_and_ambiguous_labels(self):
        for lane, _, _, _, _, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            name = v.inspect(bodies, lane)['function']; lines = v.s.lines(bodies[name])
            for start, end, _ in v.regions(bodies, lane):
                for boundary in (start, end):
                    with self.assertRaises(ValueError): v.inspect(bodies | {name: bodies[name] + '\n' + boundary + ':'}, lane)
            start, end, expected = v.regions(bodies, lane)[-1]
            for label in (line[:-1] for line in expected if line.startswith('.B') and line.endswith(':')):
                bad = '\n'.join(lines + ['jmp ' + label])
                with self.assertRaises(ValueError): v.inspect(bodies | {name: bad}, lane)
