"""Geometry-model boundaries, not native stack or external SDK qualification."""
import unittest

import windows_enclave_frame_geometry as model


class Tests(unittest.TestCase):
    def test_reviewed_chain_offsets_and_explicit_unknown_callees(self):
        value = model.scheduler(model.Window(0, 65536))
        self.assertEqual(value['frames'], {
            'body': dict(entry_from_high=-40, current_from_high=-208),
            'root': dict(entry_from_high=-216, current_from_high=-11392),
            'leaf': dict(entry_from_high=-216, current_from_high=-352),
            'closure': dict(entry_from_high=-11400, current_from_high=-11568),
            'dispatch': dict(entry_from_high=-11576, current_from_high=-11648),
            'copy_adapter': dict(entry_from_high=-11400, current_from_high=-11440)})
        self.assertFalse(value['maximum_transitive_depth_qualified'])
        self.assertFalse(value['runtime_placement_measured'])
        for callee in value['unknown_callees']:
            self.assertIsNone(callee['callee_frame_bytes'])
            self.assertFalse(callee['callee_spills_qualified'])

    def test_translation_does_not_change_geometry(self):
        baseline = model.scheduler(model.Window(0, 65536))
        for low in (4096, 1 << 32, (1 << 64)-69632):
            self.assertEqual(model.scheduler(model.Window(low, low+65536)), baseline)

    def test_home_space_is_not_mistaken_for_local_allocation(self):
        window = model.Window(0, 65536)
        body = model.Frame.enter(window, window.high-32, 168)
        self.assertEqual(body.slot('last home byte', 39, 1, 'entry')['offset_from_high'], -1)
        with self.assertRaises(ValueError): body.slot('past home', 40, 1, 'entry')

    def test_nonempty_full_span_and_64bit_bounds(self):
        window = model.Window(4096, 69632)
        for address, size in ((4095, 1), (69632, 1), (69631, 2), (4096, 0), (4096, -1),
                              (4096, 65537), (2**64, 8), (4096.0, 8), (4096, True)):
            with self.assertRaises(ValueError): window.span('bad', address, size)
        self.assertEqual(window.span('whole', 4096, 65536)['bytes'], 65536)

    def test_invalid_windows_and_frames_reject(self):
        for low, high in ((-4096, 61440), (1, 65537), (0, 65535), (2**64-65536, 2**64), (False, 65536)):
            with self.assertRaises(ValueError): model.Window(low, high)
        window = model.Window(0, 65536)
        for caller, fixed, align in ((65520, 40, 16), (32, 40, 16), (65504, 7, 16),
                                      (65504, -8, 16), (65504, 8, 64), (65503, 40, 16), (65504, 16, 16)):
            with self.assertRaises(ValueError): model.Frame.enter(window, caller, fixed, align)

    def test_alignment_rounding_cannot_hide_underflow(self):
        window = model.Window(0, 65536)
        with self.assertRaises(ValueError): model.Frame.enter(window, 16, 16, 32)
        frame = model.Frame.enter(window, 64, 40, 32)
        self.assertEqual(frame.current, 0)
        with self.assertRaises(ValueError): frame.unknown_callee('cannot fit return address')


if __name__ == '__main__': unittest.main()
