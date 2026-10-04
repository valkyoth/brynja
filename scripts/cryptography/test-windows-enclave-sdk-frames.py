"""Synthetic body-drift/geometry checks; not execution of Microsoft's library."""
import unittest
from unittest.mock import patch

import windows_enclave_sdk_frames as sdk


class Tests(unittest.TestCase):
    def bodies(self): return {n: bytes.fromhex(h) for n,(_,h) in sdk.BODIES.items()}

    def test_exact_population(self):
        sdk.check_bodies(self.bodies())
        for name in sdk.BODIES:
            changed = self.bodies()
            del changed[name]
            with self.assertRaises(ValueError): sdk.check_bodies(changed)
        with self.assertRaises(ValueError): sdk.check_bodies(self.bodies() | {'extra': b''})

    def test_every_instruction_byte_is_bound(self):
        for name, code in self.bodies().items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                with self.subTest(name=name, byte=index), self.assertRaises(ValueError):
                    sdk.check_bodies(self.bodies() | {name: bytes(changed)})

    def test_truncation_and_appending_reject(self):
        for name, code in self.bodies().items():
            for changed in (code[:-1], code+b'\x90'):
                with self.assertRaises(ValueError): sdk.check_bodies(self.bodies() | {name: changed})

    def test_wrong_image_rejects_before_parsing(self):
        with patch.object(sdk.pe, 'linked', side_effect=AssertionError('must not parse')):
            with self.assertRaises(ValueError): sdk.inspect(b'MZ-not-the-reviewed-SDK')

    def test_selected_frame_and_register_offsets(self):
        value = sdk.geometry(sdk.Window(0,65536))
        self.assertEqual(value['rtl_frame_from_high'], -12016)
        self.assertEqual(value['copy_frame_from_high'], -11488)
        spans = {s['name']: s for s in value['spans']}
        self.assertEqual(len(spans), 22)
        self.assertEqual(spans['RtlCallEnclave XMM6']['offset_from_high'], -11968)
        self.assertEqual(spans['RtlCallEnclave XMM15']['offset_from_high'], -11824)
        self.assertEqual(spans['RtlCallEnclave R15']['offset_from_high'], -11712)
        self.assertEqual(spans['CallEnclave argument/result home']['offset_from_high'], -11640)
        self.assertEqual(spans['call syscall return']['offset_from_high'], -12024)

    def test_translation_and_nonclaims(self):
        value = sdk.geometry(sdk.Window(0,65536))
        self.assertEqual(value, sdk.geometry(sdk.Window(1 << 32, (1 << 32)+65536)))
        for name in ('kernel_storage_qualified', 'status_helper_depth_qualified',
                     'sdk_self_erasure_claimed', 'maximum_transitive_depth_qualified'):
            self.assertIs(value[name], False)


if __name__ == '__main__': unittest.main()
