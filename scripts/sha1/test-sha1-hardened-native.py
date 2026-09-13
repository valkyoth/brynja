#!/usr/bin/env python3
"""Native orchestration must reject fake routes, incomplete tests and drift."""
import argparse
import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch
import hardened_native as native

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('capture-sha1-hardened-native.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
spec = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('check-sha1-hardened-native.py'))
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


def result(lane):
    arm = native.LANES[lane] == 'arm'
    kernel = 'legacy-aarch64-sha1' if arm else 'legacy-x86-sha1'
    target = 'aarch64-apple-darwin' if lane == 'apple-m2-aarch64' else 'aarch64-unknown-linux-gnu' if arm else 'x86_64-unknown-linux-gnu'
    return dict(hosted='test result: ok. 1 passed; 0 failed;\nSHA1_HOSTED_HARDENED: '+(kernel if arm else 'portable'),
        portable='test result: ok. 4 passed; 0 failed;',
        static=f'test result: ok. 4 passed; 0 failed;\nHARDENED_SHA1_EXECUTION: {kernel}; blocks=512\nSHA1_HARDENED_OPERATIONAL: {kernel}; actual hardened startup and digest passed',
        packaged='Independent hardened SHA-1 oracle: 1135 bit messages, public and secret destinations\nPackaged hardened ownership/classification negatives: 22 rejected\nHardened output/quarantine/padding compiled mutants: 10 rejected\nCompiled source-owner and scratch cleanup removals: 10 rejected',
        codegen=f'Hardened SHA-1 MIR/LLVM/assembly: PASS; 1.98.1; {target}; seven owned regions; no register-erasure claim')


def main():
    count = 0
    for lane in native.LANES:
        good = result(lane)
        native.validate_results(good, lane)
        for key in good:
            for bad in ('', 'test result: ok. 0 passed; 0 failed;', good[key].replace('passed', 'failed')):
                if bad == good[key]: continue
                changed = dict(good, **{key: bad})
                try: native.validate_results(changed, lane)
                except ValueError: count += 1
                else: raise AssertionError('accepted missing native result: '+key)
        for original, replacement in (('blocks=512','blocks=0'), ('HARDENED_SHA1_EXECUTION:', 'test prefix HARDENED_SHA1_EXECUTION:'), ('1135', '1134'), ('20 rejected','0 rejected')):
            changed = {k:v.replace(original, replacement) for k,v in good.items()}
            if changed == good: continue
            try: native.validate_results(changed, lane)
            except ValueError: count += 1
            else: raise AssertionError('accepted wrong evidence: '+original)
        calls = []
        def run(command, env):
            calls.append(command)
            assert 'brynja_sha1_cpu_evidence' not in env.get('RUSTFLAGS', '')
            if 'check-sha1-package.py' in ' '.join(command):
                assert '--hardened' in command and 'target-feature=' in env['RUSTFLAGS']
                assert env['BRYNJA_REQUIRE_HARDENED_SHA1'] == '1'
                return good['packaged']
            if 'check-sha1-hardened-codegen.py' in ' '.join(command): return good['codegen']
            assert '--locked' in command and '--offline' in command
            if 'runtime-hardened-execution' in command:
                assert 'RUSTFLAGS' not in env
                return good['hosted']
            if '--lib' in command:
                assert 'target-feature=' in env['RUSTFLAGS']
                assert env['BRYNJA_REQUIRE_HARDENED_SHA1'] == '1'
                return good['static']
            assert 'RUSTFLAGS' not in env
            return good['portable']
        with patch.object(native.host, 'run', side_effect=run):
            assert native.collect(lane, '+neon,+sha2' if native.LANES[lane]=='arm' else '+sha,+sse2', native.clean_environment()) == good
        assert len(calls) == 5
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-hardened-capture-') as temporary:
        for change in (None, 'attestation', 'overwrite', 'dirty', 'commit', 'source'):
            path = Path(temporary)/'result.json'
            if change == 'overwrite': path.write_text('existing')
            arguments = argparse.Namespace(attest_native=change!='attestation', lane='intel-x86_64', output=path)
            commits = iter(('a'*40, 'b'*40 if change=='commit' else 'a'*40))
            hashes = iter(({'source':'1'}, {'source':'2' if change=='source' else '1'}))
            def git(command, env=None):
                if command[:2] == ['git', 'status']: return ' M source' if change=='dirty' else ''
                if command[:2] == ['git', 'rev-parse']: return next(commits)
                return 'rustc 1.98.1'
            with patch.object(native.policy,'validate'), patch.object(native.policy,'hashes',side_effect=lambda:next(hashes)), \
                 patch.object(native.host,'run',side_effect=git), patch.object(native.host,'host',return_value=('Intel','+sha,+sse2')), \
                 patch.object(native,'collect',return_value=result('intel-x86_64')):
                try: capture.capture(arguments)
                except ValueError:
                    if change is None: raise
                    count += 1
                else:
                    assert change is None
                    record = json.loads(path.read_text())
                    assert record['profile']=='hardened-legacy-only' and record['owned_memory_regions']==7
                    assert not record['fips_validated'] and not record['independent_review'] and not record['register_erasure']
            if path.exists():
                if change=='overwrite': assert path.read_text()=='existing'
                else: assert change is None
                path.unlink()
    record = dict(schema=1, version='0.24.42', lane='intel-x86_64', source_sha256={'source':'hash'},
        commit='a'*40, native='operator-self-attested', profile='hardened-legacy-only', owned_memory_regions=7,
        fips_validated=False, independent_review=False, register_erasure=False, system='Linux',
        static_features='+sse2,+sha', compiler='release: 1.98.1\nhost: x86_64-unknown-linux-gnu',
        cpu='GenuineIntel', results=result('intel-x86_64'),
        disposition='pending owner review; native correctness is not migration or side-channel proof')
    qualification.validate_record(record, 'intel-x86_64', {'source':'hash'})
    for key in record:
        changed = dict(record)
        del changed[key]
        try: qualification.validate_record(changed, 'intel-x86_64', {'source':'hash'})
        except (ValueError, TypeError): count += 1
        else: raise AssertionError('accepted missing native field: '+key)
    for key, value in (('owned_memory_regions', 6), ('profile', 'ordinary-public-only'), ('register_erasure', True),
                       ('fips_validated', True), ('source_sha256', {'source':'changed'}), ('static_features', '+sha'),
                       ('compiler', 'release: 1.98.1\nhost: aarch64-unknown-linux-gnu')):
        try: qualification.validate_record(dict(record, **{key:value}), 'intel-x86_64', {'source':'hash'})
        except ValueError: count += 1
        else: raise AssertionError('accepted tampered native field: '+key)
    count += index_tests(record)
    print(f'Hardened SHA-1 native capture: four lane controls and {count} regressions passed')


def index_tests(template):
    """The tag gate must reject incomplete, stale or redirected qualification."""
    count = 0
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-native-index-') as temporary:
        root = Path(temporary)
        (root / 'security').mkdir()
        index = dict(schema=1, version='0.24.42', owner_review='accepted-correctness-with-residuals', captures={})
        for lane in ('intel-x86_64', 'aws-aarch64', 'apple-m2-aarch64'):
            record = copy.deepcopy(template)
            arm = native.LANES[lane] == 'arm'
            target = 'aarch64-apple-darwin' if lane=='apple-m2-aarch64' else 'aarch64-unknown-linux-gnu' if arm else 'x86_64-unknown-linux-gnu'
            record.update(lane=lane, results=result(lane), system='Darwin' if lane=='apple-m2-aarch64' else 'Linux',
                          static_features='+neon,+sha2' if arm else '+sse2,+sha',
                          compiler='release: 1.98.1\nhost: '+target)
            text = json.dumps(record)
            relative = 'security/'+lane+'.json'
            (root / relative).write_text(text)
            index['captures'][lane] = dict(path=relative, sha256=hashlib.sha256(text.encode()).hexdigest())
        def check(value):
            (root / qualification.INDEX).write_text(json.dumps(value))
            qualification.validate(root)
        with patch.object(native.policy, 'hashes', return_value={'source':'hash'}), \
             patch.object(qualification.subprocess, 'run') as ancestry:
            check(index)
            assert ancestry.call_count == 3
            for call in ancestry.call_args_list:
                assert call.args[0] == ['git', 'merge-base', '--is-ancestor', 'a'*40, 'HEAD']
                assert call.kwargs == dict(cwd=root, check=True, timeout=30)
            for change in ('pending', 'version', 'lane', 'checksum', 'absolute', 'parent', 'source', 'symlink', 'ancestry'):
                bad = copy.deepcopy(index)
                entry = bad['captures']['intel-x86_64']
                if change == 'pending': bad['owner_review'] = 'pending'
                elif change == 'version': bad['version'] = '0.24.41'
                elif change == 'lane': del bad['captures']['aws-aarch64']
                elif change == 'checksum': entry['sha256'] = '0'*64
                elif change == 'absolute': entry['path'] = str(root / entry['path'])
                elif change == 'parent': entry['path'] = '../'+root.name+'/'+entry['path']
                elif change == 'source':
                    record = json.loads((root / entry['path']).read_text())
                    record['source_sha256'] = {'source':'different'}
                    text = json.dumps(record)
                    (root / 'security/stale.json').write_text(text)
                    entry.update(path='security/stale.json', sha256=hashlib.sha256(text.encode()).hexdigest())
                elif change == 'symlink':
                    try: (root / 'security/link.json').symlink_to(root / entry['path'])
                    except OSError: continue  # Windows may forbid symlinks without developer privileges.
                    entry['path'] = 'security/link.json'
                elif change == 'ancestry':
                    ancestry.side_effect = subprocess.CalledProcessError(1, ['git', 'merge-base'])
                try: check(bad)
                except (ValueError, subprocess.CalledProcessError): count += 1
                else: raise AssertionError('native index accepted '+change)
                finally: ancestry.side_effect = None
    return count


if __name__ == '__main__': main()
