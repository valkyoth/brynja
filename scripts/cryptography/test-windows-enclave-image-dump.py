"""Current-image dump validator tests; no registry changes or crashes."""
import struct
import unittest
from unittest.mock import Mock, patch

import windows_enclave_image_dump as runner
import windows_enclave_image_dump_model as model
from windows_protection_probe import ProbeError


def target(phase='admission'):
    return dict(pid=123, phase=phase, base=0x10000000, control=0x30000000,
        window=0x10010000, window_locked_pages=16 if phase == 'admission' else 0,
        retained=0 if phase == 'admission' else 0x10030000,
        retained_locked_pages=0 if phase == 'admission' else 1)


def blob(regions):
    size = 16+16*len(regions)
    header = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
    header += struct.pack('<IIIQQ', 9, size, 44, len(regions), 44+size)
    header += b''.join(struct.pack('<QQ', a, len(b)) for a,b in regions)
    return header+b''.join(b for _,b in regions)


class Tests(unittest.TestCase):
    def test_both_checkpoints(self):
        for phase in model.PHASES:
            value = target(phase)
            model.validate(value, 123, phase)
            observation = model.analyze(blob([(value['control'], b'\x5a'*8192)]), value)
            self.assertTrue(observation['reservation_absent_in_this_dump'])

    def test_controls_must_be_complete_correct_and_present(self):
        for phase in model.PHASES:
            for data in (b'', b'\x5a'*8191, b'\0'*8192, b'\xff'*8192):
                with self.assertRaises(ProbeError):
                    model.analyze(blob([(target()['control'], data)]), target(phase))

    def test_zero_partial_and_full_enclave_inclusion_never_passes_as_absence(self):
        for phase in model.PHASES:
            value = target(phase)
            for address in (value['window'], value['base']+4096, 0x10030000):
                for size in (1,4096,65536):
                    observed = model.analyze(blob([(value['control'], b'\x5a'*8192),
                                                   (address, bytes(size))]), value)
                    self.assertFalse(observed['reservation_absent_in_this_dump'])
                    self.assertEqual(observed['reservation_included_bytes'], size)

    def test_bounds_aliases_and_phase_mismatches_reject(self):
        for phase in model.PHASES:
            value = target(phase)
            changes = [('base',0), ('base',0x10000001), ('window',value['base']),
                ('window',value['base']+model.RESERVATION-model.WINDOW),
                ('control',value['window']), ('control',2**64-1),
                ('window_locked_pages',1), ('retained_locked_pages',2),
                ('retained',value['window']), ('pid',124)]
            for key,bad in changes:
                with self.subTest(phase=phase,key=key), self.assertRaises(ProbeError):
                    model.validate(value | {key:bad},123,phase)
            with self.assertRaises(ProbeError): model.validate(value,123,'unknown')

    def test_integer_types_and_schema(self):
        value = target('retained')
        for key in set(value)-{'phase'}:
            for bad in (True, '1', -1, 2**64):
                with self.assertRaises(ProbeError): model.validate(value | {key:bad},123,'retained')
        for bad in (value | {'extra':0}, {k:v for k,v in value.items() if k != 'retained'}):
            with self.assertRaises(ProbeError): model.validate(bad,123,'retained')

    def test_invalid_dump_and_duplicate_ranges(self):
        for data in (b'', b'MDMP', bytes(64), blob([(0x30000000,b'a'*8192)]*2)):
            with self.assertRaises(ProbeError): model.analyze(data,target())

    def test_required_crash_and_checkpoint_identity(self):
        import json
        for code,text,stderr in ((0,json.dumps(target()),''),
            (0xc0000005,json.dumps(target()),''),
            (0xc0000602,json.dumps(target() | {'pid':124}),''),
            (0xc0000602,json.dumps(target()),'unexpected')):
            process = Mock(pid=123, returncode=code)
            process.communicate.return_value = (text,stderr)
            context = Mock()
            context.__enter__ = Mock(return_value=process)
            context.__exit__ = Mock(return_value=False)
            with patch.object(runner.subprocess,'Popen',return_value=context):
                with self.assertRaises(ProbeError): runner.run_child('owned.exe','public.dll','admission')

    def test_loaded_diagnostic_sources_are_bound(self):
        sources = runner.shared.sources()
        for name in ('windows_enclave_image_dump.py','windows_enclave_image_dump_child.py',
                     'windows_enclave_image_dump_model.py','windows_minidump.py'):
            self.assertEqual(sources['scripts/cryptography/'+name],
                runner.shared.digest(runner.shared.ROOT/'scripts/cryptography'/name))

    def test_timeout_kills_only_owned_child(self):
        process = Mock(pid=123)
        process.communicate.side_effect = [runner.subprocess.TimeoutExpired('owned.exe',90), ('','')]
        context = Mock()
        context.__enter__ = Mock(return_value=process)
        context.__exit__ = Mock(return_value=False)
        with patch.object(runner.subprocess,'Popen',return_value=context):
            with self.assertRaises(RuntimeError): runner.run_child('owned.exe','public.dll','admission')
        process.kill.assert_called_once_with()
        self.assertEqual(process.communicate.call_count,2)


if __name__ == '__main__': unittest.main()
