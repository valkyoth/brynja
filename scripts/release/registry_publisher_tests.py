"""Offline registry, clock and subprocess controls for publication."""
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import Mock, patch

import registry_ownership as registry
import registry_sequence as seq
import registry_transport as tx
import release_crates as cli


class RegistryPublisher(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.waits = []
        self.active = {}
        self.names = ('first', 'second', 'third', 'last')
        self.plan = {'crates': {n: {'version': '1.0.0', 'change': k} for n, k in
                               zip(self.names, ('initial', 'code', 'initial', 'code'))}}
        self.start(tx.time, 'monotonic', side_effect=lambda: self.now)
        self.start(tx.time, 'time', side_effect=lambda: self.now)
        self.start(tx.time, 'sleep', side_effect=self.advance)
        self.start(registry, 'owners', return_value={('user', 1)})
        self.start(registry, 'inspect', side_effect=lambda n, *_: self.active.get(n))
        self.start(registry, 'indexed')
        self.index = self.start(tx, 'wait_index')
        self.checksum = self.start(seq, 'package_checksum', return_value='a' * 64)
        self.calls = []

    def start(self, obj, name, **options):
        p = patch.object(obj, name, **options)
        self.addCleanup(p.stop)
        return p.start()

    def advance(self, seconds):
        self.waits.append(seconds)
        self.now += seconds

    def sent(self, name):
        self.calls.append((name, self.now))
        self.active[name] = {'created_at': datetime.fromtimestamp(self.now, timezone.utc).isoformat()}

    def run_plan(self, send=None, **options):
        seq.sequence(self.plan, self.names, self.names, send or self.sent, **options)

    def test_mixed_cooldowns_do_not_restart_new_name_timer_for_updates(self):
        self.run_plan()
        self.assertEqual(self.waits, [120, 540, 120])
        self.assertEqual([n for n, _ in self.calls], list(self.names))
        self.assertEqual(self.index.call_count, 4)

    def test_consecutive_initials_and_updates(self):
        self.names = ('first', 'third', 'second', 'last')
        self.run_plan()
        self.assertEqual(self.waits, [660, 120, 120])

    def test_interrupt_after_upload_uses_registry_timestamp_on_restart(self):
        def interrupted(name):
            self.sent(name)
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_plan(interrupted)
        self.now += 30
        self.run_plan()
        self.assertEqual(self.waits, [90, 540, 120])
        self.assertEqual([n for n, _ in self.calls], list(self.names))
        self.run_plan(Mock(side_effect=AssertionError('already published')))
        self.assertEqual(self.waits, [90, 540, 120])

    def test_status_and_manual_skip_cannot_upload_or_ignore_gaps(self):
        self.run_plan(Mock(side_effect=AssertionError('read-only')), status=True)
        self.index.assert_not_called()
        self.checksum.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'skip missing'):
            seq.sequence(self.plan, self.names, self.names[1:], self.sent)
        self.assertFalse(self.calls or self.waits)

    def test_upload_limit_prefers_longer_server_delay_then_rechecks(self):
        attempts = []
        def limited(name):
            attempts.append(name)
            if len(attempts) == 1:
                raise tx.UploadLimited('700')
            self.sent(name)
        self.run_plan(limited)
        self.assertEqual(attempts[:2], ['first', 'first'])
        self.assertEqual(self.calls[0], ('first', 1700))
        self.assertEqual(tx.retry_seconds(format_datetime(datetime.fromtimestamp(
            self.now + 800, timezone.utc)), 120), 800)

    def test_version_appears_during_backoff_no_second_upload(self):
        def limited(name):
            self.sent(name)
            if name == 'first':
                raise tx.UploadLimited(None)
        self.run_plan(limited)
        self.assertEqual([n for n, _ in self.calls], list(self.names))
        self.assertEqual(self.index.call_count, 4)
        self.index.assert_any_call('first', '1.0.0', expected='a' * 64)

    def test_later_active_archive_mismatch_blocks_even_the_first_upload(self):
        self.sent('last')
        self.calls.clear()
        self.index.side_effect = ValueError('checksum mismatch')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.run_plan()
        self.checksum.assert_called_once_with('last', '1.0.0')
        self.index.assert_called_once_with('last', '1.0.0', expected='a' * 64)
        self.assertEqual(self.calls, [])

    def test_version_appearing_during_backoff_with_wrong_bytes_stops(self):
        def limited(name):
            self.sent(name)
            raise tx.UploadLimited(None)
        self.index.side_effect = ValueError('checksum mismatch')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.run_plan(limited)
        self.index.assert_called_once_with('first', '1.0.0', expected='a' * 64)
        self.assertEqual([name for name, _ in self.calls], ['first'])

    def test_checksum_compares_real_archives_not_stale_target(self):
        # Two freshly packaged copies of identical inputs match. The identity
        # and version stay the same when a source edit changes the checksum.
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, CARGO_NET_OFFLINE='true'):
            root = Path(td)
            (root / 'src').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="1.0.0"\nedition="2021"\n')
            code = root / 'src/lib.rs'
            code.write_text('pub const VALUE: u32 = 1;\n')
            subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root, check=True)
            stale = root / 'target/package/fixture-1.0.0.crate'
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'stale')
            self.checksum.side_effect = real_checksum
            initial = seq.package_checksum('fixture', '1.0.0', root=root)
            self.assertEqual(initial, seq.package_checksum('fixture', '1.0.0', root=root))
            code.write_text('pub const VALUE: u32 = 2;\n')
            self.assertNotEqual(initial, seq.package_checksum('fixture', '1.0.0', root=root))
            self.assertEqual(stale.read_bytes(), b'stale')

    def test_ambiguous_failure_not_retried_and_rate_limit_is_bounded(self):
        ambiguous = Mock(side_effect=subprocess.CalledProcessError(1, ['cargo']))
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_plan(ambiguous)
        ambiguous.assert_called_once()
        limited = Mock(side_effect=tx.UploadLimited(None))
        with self.assertRaisesRegex(RuntimeError, 'repeated'):
            self.run_plan(limited)
        self.assertEqual(limited.call_count, 4)
        self.assertEqual(self.waits, [660] * 3)

    def test_bad_or_excessive_retry_time_never_causes_early_retry(self):
        for hint, error in [('not a date', ValueError), ('7200', RuntimeError)]:
            limited = Mock(side_effect=tx.UploadLimited(hint))
            with self.assertRaises(error):
                self.run_plan(limited)
            limited.assert_called_once()
        self.assertFalse(self.waits)

    def test_cargo_diagnostics_distinguish_upload_rejection_from_other_errors(self):
        prefix = 'error: failed to publish foo v1.0.0 to registry at https://crates.io\nCaused by:\n  '
        for message, hint in (
            ('failed to get a 200 OK response, got 429\nheaders:\n\tretry-after: 800', '800'),
            ('the remote server responded with an error (status 429 Too Many Requests): '
             'please try again after Thu, 01 Jan 1970 00:30:00 GMT', 'Thu, 01 Jan 1970 00:30:00 GMT')):
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stderr=prefix + message)):
                with self.assertRaises(tx.UploadLimited) as err:
                    tx.upload(['cargo'], '.')
                self.assertEqual(err.exception.hint, hint)
        for msg in (prefix + 'unauthorized', 'failed to download dependency (429)', 'timed out after uploading'):
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stderr=msg)):
                with self.assertRaises(subprocess.CalledProcessError):
                    tx.upload(['cargo'], '.')

    def test_sparse_index_waits_for_exact_active_version(self):
        # Invoke the actual function, not setUp's mocked index callback.
        rows = b'{"name":"leaf","vers":"0.1.0","yanked":false}\n'
        found = rows.replace(b'0.1.0', b'1.0.0')
        for replies, error in (([rows, found], None), ([found.replace(b'false', b'true')], ValueError),
                               ([rows] * 31, RuntimeError)):
            stream = iter(replies)
            with patch.object(tx, 'read', side_effect=lambda url, decode: decode(io.BytesIO(next(stream)))):
                if error:
                    with self.assertRaises(error):
                        real_index('leaf', '1.0.0')
                else:
                    real_index('leaf', '1.0.0')

    def test_sparse_index_requires_matching_checksum_on_resume(self):
        digest = 'a' * 64
        for actual in (None, 'b' * 64, digest):
            row = b'{"name":"leaf","vers":"1.0.0","yanked":false' + (
                b'' if actual is None else b',"cksum":"' + actual.encode() + b'"') + b'}\n'
            with patch.object(tx, 'read', side_effect=lambda _, decode: decode(io.BytesIO(row))):
                if actual == digest:
                    real_index('leaf', '1.0.0', expected=digest)
                else:
                    with self.assertRaisesRegex(ValueError, 'checksum'):
                        real_index('leaf', '1.0.0', expected=digest)

    def test_impact_excludes_unrelated_crates_and_follows_transitive_pins(self):
        names = ('root', 'unrelated', 'middle', 'end', 'brynja')
        packages = {n: {'dependencies': []} for n in names}
        packages['middle']['dependencies'] = [{'name': 'root'}]
        packages['end']['dependencies'] = [{'name': 'middle'}]
        with patch.object(cli, 'PUBLISH_ORDER', names):
            self.assertEqual(list(cli.pin_impact(packages, ['root'])), ['root', 'middle', 'end', 'brynja'])


real_index = tx.wait_index
real_checksum = seq.package_checksum
