#!/usr/bin/env python3
"""Real policy-removal and sanitizer-environment/fatal-exit regressions."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import md5_hardened_policy as policy
import md5_hardened_codegen as codegen


def opaque_identity():
    for arch in ('x86','arm'):
        tokens = ('brynja_legacy_md5', arch+'_secret', '6kernel8compress')
        symbol = '_RNbrynja_legacy_md5'+arch+'_secret6kernel8compress'
        valid = symbol+':\n ret\n_RNordinary:\n omitted_simd\n'
        assert codegen.asm_body(valid,tokens).strip() == 'ret'
        for mutated in (valid+valid, valid.replace('6kernel8compress','compress_secret'),
                        valid.replace(arch+'_secret','ordinary'), '',
                        valid.replace(symbol,'Lordinary')):
            try: codegen.asm_body(mutated,tokens)
            except ValueError: pass
            else: raise AssertionError('opaque MD5 identity regression accepted')
    print('MD5 opaque identity rejects ten wrapper/ordinary/ambiguous substitutions')

def main():
    opaque_identity()
    policy.validate()
    count=0
    with tempfile.TemporaryDirectory(prefix='brynja-md5-hardened-policy-') as directory:
        root=Path(directory)
        for name in set(policy.paths()) | set(policy.GATES) | {policy.REVIEW}:
            path=root/name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(policy.ordinary.read(policy.ROOT,name))
        for name,tokens in {**policy.CHECKS,**policy.GATES}.items():
            path=root/name; original=path.read_text()
            for token in tokens:
                # Normalize identically to policy, then remove the exact checked token.
                import re
                compact=re.sub(r'\s+','',original)
                needle=re.sub(r'\s+','',token)
                if needle not in compact: raise ValueError('mutation token absent')
                path.write_text(compact.replace(needle,'removed_boundary'))
                try: policy.validate(root,reviewed=False)
                except ValueError: count+=1
                else: raise AssertionError('hardened policy mutation accepted')
                finally: path.write_text(original)
    spec=importlib.util.spec_from_file_location('md5_hardened_asan',policy.ROOT/'scripts/md5/check-md5-hardened-asan.py')
    asan=importlib.util.module_from_spec(spec); spec.loader.exec_module(asan)
    for status in (0,1,23):
        def run(command, **kwargs):
            env=kwargs['env']
            assert env['ASAN_OPTIONS']=='detect_leaks=1:halt_on_error=1:exitcode=1'
            assert env['LSAN_OPTIONS']=='exitcode=23'
            assert env['BRYNJA_REQUIRE_HARDENED_MD5']=='1' and kwargs['check'] is True
            assert 'hardened-execution' in command and 'hardened_execution' in command
            if status: raise subprocess.CalledProcessError(status,command)
        with patch.dict(os.environ,{'ASAN_OPTIONS':'detect_leaks=0','LSAN_OPTIONS':'exitcode=0'}), \
             patch.object(asan.platform,'system',return_value='Linux'), \
             patch.object(asan.platform,'machine',return_value='x86_64'), \
             patch.object(Path,'read_text',return_value='flags : avx2'), \
             patch.object(asan.subprocess,'run',side_effect=run):
            try: asan.main()
            except subprocess.CalledProcessError:
                assert status != 0
            else: assert status == 0
    print(f'Hardened MD5 policy: {count} boundary removals rejected; enforced ASan/LSan fatal exits PASS')

if __name__=='__main__': main()
