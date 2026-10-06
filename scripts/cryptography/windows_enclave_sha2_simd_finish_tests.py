"""Independent padding geometry and saved finalization regression tests."""
import re
from unittest.mock import patch
import windows_enclave_sha2_simd_finish as f


def reference_padding(remainder, partial, bits, block):
    # Bit-string specification, independent of byte placement/cutoff branches.
    width = 64 if block == 64 else 128
    value = ''.join(format(byte, '08b') for byte in remainder)
    value += format(partial, '08b')[:bits % 8] + '1'
    value += '0' * (-(len(value) + width) % (8 * block))
    value += format(bits, f'0{width}b')
    return bytes(int(value[i:i + 8], 2) for i in range(0, len(value), 8))


class FinishTests:
    def test_finish_padding_every_private_message_bit_length_matches_bit_specification(self):
        data = bytes(range(256)) * 4
        for lane, block in (('simd256', 64), ('simd512', 128)):
            for bits in range(8193):
                complete = bits // 8
                remainder = data[complete - complete % block:complete]
                partial = (0xad & ((255 << (8 - bits % 8)) & 255)) if bits % 8 else 0
                actual = f.padding(lane, remainder, partial, bits)
                self.assertEqual(actual, reference_padding(remainder, partial, bits, block))
                self.assertIn(len(actual), (block, 2 * block))
            for bits in (0, 24):
                remainder = b'abc' if bits else b''
                expected = remainder + b'\x80' + bytes(block - len(remainder) - 9) + bits.to_bytes(8, 'big')
                self.assertEqual(f.padding(lane, remainder, 0, bits), expected)

    def test_finish_consumed_blocks_partition_all_private_input_lengths(self):
        for lane, block in (('simd256', 64), ('simd512', 128)):
            for bits in range(8193):
                complete = bits // (block * 8)
                for consumed in range(complete + 1):
                    result = f.geometry(lane, (bits + 7) // 8, bits, consumed)
                    self.assertEqual(result['first'], consumed * block)
                    self.assertEqual(result['end'], complete * block)
                    self.assertEqual(result['blocks'] + consumed, complete)
                    self.assertEqual(result['remainder'], (bits // 8) - complete * block)
                    self.assertLessEqual(result['end'], bits // 8)
                with self.assertRaises(ValueError): f.geometry(lane, (bits + 7) // 8, bits, complete + 1)

    def test_finish_all_fractional_bytes_require_canonical_input(self):
        for lane in ('simd256', 'simd512'):
            for valid in range(1, 8):
                for byte in range(256):
                    if byte & (255 >> valid):
                        with self.assertRaises(ValueError): f.padding(lane, b'', byte, valid)
                    else:
                        result = f.padding(lane, b'', byte, valid)
                        self.assertEqual(result[0], byte + (1 << (7 - valid)))
            bits = (1 << 64) - 1
            _, _, block = f.vector.parameters(lane)
            result = f.padding(lane, bytes((bits // 8) % block), 254, bits)
            self.assertEqual(result[-8:], b'\xff' * 8)
            if lane == 'simd512': self.assertEqual(result[-16:-8], bytes(8))
            for bad in (-1, True, 1 << 64):
                with self.assertRaises(ValueError): f.geometry(lane, 0, bad, 0)
            with self.assertRaises(ValueError): f.padding(lane, b'wrong remainder', 0, 0)
            with self.assertRaises(ValueError): f.geometry(lane, 2, 8, 0)
            with self.assertRaises(ValueError): f.padding(lane, b'', 256, 0)

    def test_finish_wide_output_width_and_mask_for_every_supported_identity(self):
        for tag, bits in enumerate((384, 512, 224, 256)):
            self.assertEqual(f.wide_output(tag), (bits // 8, 255))
        for bits in range(1, 512):
            if bits == 384: continue
            width, mask = f.wide_output(4, bits)
            self.assertEqual(width, len(range(0, bits, 8)))
            self.assertEqual(mask, int(('1' * (bits % 8 or 8)).ljust(8, '0'), 2))
            self.assertLessEqual(width, 64)
            self.assertGreaterEqual(width - 1, 0)
        for value in (0, 384, 512, 65535, -1, True):
            with self.assertRaises(ValueError): f.wide_output(4, value)
        for tag in (-1, 5, True):
            with self.assertRaises(ValueError): f.wide_output(tag)


class FinishSavedTests:
    def test_finish_rejects_each_instruction_change_and_direct_side_entry(self):
        counts = {}
        for lane, _, _, _, _, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            report = f.inspect(bodies, lane); name = report['function']; lines = f.s.lines(bodies[name])
            start, end, expected = f.region(bodies, lane); first = lines.index(start + ':'); count = 0
            for offset, line in enumerate(expected):
                if line.endswith(':'): continue
                index = first + offset
                for replacement in ([], ['retq'], ['nop', line]):
                    bad = lines[:index] + replacement + lines[index + 1:]
                    with self.assertRaises(ValueError): f.inspect(bodies | {name: '\n'.join(bad)}, lane)
                    count += 1
            for label in (line[:-1] for line in expected if re.fullmatch(r'\.B\d+:', line)):
                if label == start: continue
                with self.assertRaises(ValueError):
                    f.inspect(bodies | {name: '\n'.join(lines + ['jmp ' + label])}, lane)
            counts[lane] = count
        self.assertEqual(counts, {'simd256': 543, 'simd512': 807})
        print('SIMD scalar finish instruction/control mutations rejected: ' + str(counts))

    def test_finish_mask_specialization_and_erasure_are_load_bearing(self):
        count = 0
        for lane, _, _, _, _, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            name = f.s.one(bodies, r'secret_memory_mask9mask_byte$')
            for marker in ('BRYNJA_MASK_BEGIN', 'BRYNJA_MASK_ERASE', 'BRYNJA_MASK_END'):
                bad = bodies[name].replace(marker, '') + '\n# ' + marker
                with self.assertRaises(ValueError): f.mask_helper(bodies | {name: bad}, lane)
            for regex in (r'secret_memory_mask9mask_byte$', r'secret_memory22apply_secret_byte_mask$'):
                name = f.s.one(bodies, regex); lines = bodies[name].splitlines()
                for index, line in enumerate(lines):
                    if not line.strip() or line.endswith(':') or line.strip() in ('#APP', '#NO_APP'): continue
                    with self.assertRaises(ValueError):
                        f.mask_helper(bodies | {name: '\n'.join(lines[:index] + lines[index + 1:])}, lane)
                    count += 1
        self.assertEqual(count, 21)
        print('SIMD scalar finish mask/erase mutations rejected: ' + str(count))

    def test_finish_wide_dispatch_rejects_every_wrong_variant_and_ambiguous_table(self):
        import windows_enclave_sha2_batch_chains as chains
        assembly = ''.join(f'.LJTI23_{n}:\n' + ''.join(f'\t.long\t.LBB23_{label}-.LJTI23_{n}\n' for label in labels)
                           for n, labels in ((5, [212, 216, 214, 215, 213]), (6, [220, 224, 222, 223, 221])))
        tables = f.tables(assembly); count = 0
        for table, labels in tables.items():
            for old in labels:
                for new in labels:
                    if old == new: continue
                    with self.assertRaises(ValueError):
                        f.tables(assembly.replace(f'.LBB23_{old}-{table}', f'.LBB23_{new}-{table}'))
                    count += 1
        for bad in ('', assembly + assembly, assembly.replace('.long', '.quad'), assembly.replace('.LJTI23_5:', 'absent:')):
            with self.assertRaises(ValueError): f.tables(bad)
        self.assertEqual(count, 40)
        lane, pin, *_ = next(row for row in self.routes if row[0] == 'simd512')
        _, _, _, actual, _, _ = chains.load(self.saved, self.root, pin)
        self.assertEqual(f.tables(actual), tables)
        with patch.object(f, 'tables', side_effect=ValueError('finish dispatch failed')) as gate:
            with self.assertRaisesRegex(ValueError, 'finish dispatch failed'):
                chains.inspect_route(self.saved, self.root, lane, pin, False)
            gate.assert_called_once()

    def test_finish_review_is_required_and_leaves_frame_and_primitive_composition_pending(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane, _, _, _, ir, _, bodies in self.routes:
            if not lane.startswith('simd'): continue
            result = f.inspect(bodies, lane)
            self.assertFalse(result['whole_frame_qualified'])
            self.assertTrue(result['scalar_compression_helper_composition_pending'])
            with patch.object(f, 'inspect', side_effect=ValueError('finish review failed')) as gate:
                with self.assertRaisesRegex(ValueError, 'finish review failed'): chains.shapes.inspect(bodies, ir, lane)
                gate.assert_called_once()
