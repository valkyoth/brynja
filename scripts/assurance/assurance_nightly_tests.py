"""Frozen-nightly upstream and strict-update regression cases."""
import copy
import io
from unittest import mock

import assurance_policy as assurance
from assurance_process_tests import fails_with


def test_frozen_nightly_identity_and_update_notification() -> None:
    policy = copy.deepcopy(assurance.read_policy())
    policy['tools'] = [tool for tool in policy['tools'] if tool['id'] in ('miri', 'rust-sanitizers')]
    version = policy['tools'][0]['version']
    revision = policy['tools'][0]['revision']
    def document(date, sha, available=True):
        return (f'date = "{date}"\n[pkg.rust]\ngit_commit_hash = "{sha}"\n'
                '[pkg.miri-preview.target.x86_64-unknown-linux-gnu]\n'
                f'available = {str(available).lower()}\n').encode()
    dated = document(version[8:], revision)
    latest = document('2099-01-01', 'a' * 40)
    for invalid_version in ('latest', 'nightly-not-a-date'):
        changed = copy.deepcopy(policy)
        for tool in changed['tools']:
            tool['version'] = invalid_version
        with mock.patch.object(assurance.urllib.request, 'urlopen') as network:
            with fails_with('invalid frozen nightly date'):
                assurance.network_check(changed)
            network.assert_not_called()
    calls = []
    def fetch(url, timeout):
        calls.append(url)
        assert timeout == assurance.SUBPROCESS_TIMEOUT_SECONDS
        return io.BytesIO(dated if '/' + version[8:] + '/' in url else latest)
    with mock.patch.object(assurance.urllib.request, 'urlopen', side_effect=fetch):
        assurance.network_check(policy)
        assert calls == ['https://static.rust-lang.org/dist/' + version[8:] + '/channel-rust-nightly.toml',
                         'https://static.rust-lang.org/dist/channel-rust-nightly.toml']
        with fails_with('nightly update required'):
            assurance.network_check(policy, require_latest_nightly=True)
        for key, value in [('revision', 'b' * 40), ('execution_toolchain', 'nightly-2000-01-01'),
                           ('version', 'nightly-2000-01-01')]:
            changed = copy.deepcopy(policy)
            changed['tools'][0][key] = value
            with fails_with('nightly'):
                assurance.network_check(changed)
    for invalid in (document(version[8:], 'b' * 40), document('2000-01-01', revision),
                    document(version[8:], revision, False)):
        with mock.patch.object(assurance.urllib.request, 'urlopen', return_value=io.BytesIO(invalid)):
            with fails_with('nightly'):
                assurance.network_check(policy)
    for invalid_latest in (document(version[8:], 'b' * 40),
                           document('2000-01-01', revision),
                           document('not-a-date', revision)):
        with mock.patch.object(assurance.urllib.request, 'urlopen',
                               side_effect=[io.BytesIO(dated), io.BytesIO(invalid_latest)]):
            with fails_with('nightly'):
                assurance.network_check(policy)
    with mock.patch.object(assurance.urllib.request, 'urlopen',
                           side_effect=[io.BytesIO(dated), io.BytesIO(dated)]):
        assurance.network_check(policy, require_latest_nightly=True)
    with mock.patch.object(assurance.urllib.request, 'urlopen', return_value=io.BytesIO(b'x' * 33)), \
         mock.patch.object(assurance, 'MAXIMUM_NIGHTLY_MANIFEST_BYTES', 32):
        with fails_with('bounded input'):
            assurance.network_check(policy)
    with mock.patch.object(assurance.urllib.request, 'urlopen', side_effect=OSError('offline')):
        try:
            assurance.network_check(policy)
        except OSError:
            pass
        else:
            raise AssertionError('network failure admitted frozen evidence')
