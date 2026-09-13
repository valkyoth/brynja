#!/usr/bin/env python3
"""Require real child failure propagation and non-ambient ASan/LSan settings."""
import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('asan',Path(__file__).with_name('check-md5-execution-asan.py'))
asan=importlib.util.module_from_spec(spec); spec.loader.exec_module(asan)

def main():
    cases=0
    for hostile in ({},{'ASAN_OPTIONS':'detect_leaks=0','LSAN_OPTIONS':'exitcode=0','CARGO_ENCODED_RUSTFLAGS':'--cfg=bypass'}):
        for failure in (None,'leak detected','ptrace denied','heap overflow'):
            def run(command,**kwargs):
                env=kwargs['env']
                assert env['ASAN_OPTIONS']=='detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS']=='exitcode=23'
                assert env['RUSTFLAGS']=='-Zsanitizer=address -C target-feature=+avx2'
                assert env['BRYNJA_REQUIRE_MD5_EXECUTION']=='1'
                assert 'CARGO_ENCODED_RUSTFLAGS' not in env and kwargs['check'] is True
                assert '--test' in command and 'execution' in command
                if failure: raise subprocess.CalledProcessError(23,command,stderr=failure)
            with patch.dict(asan.os.environ,hostile,clear=True), patch.object(asan.platform,'system',return_value='Linux'), \
                 patch.object(asan.platform,'machine',return_value='x86_64'), patch.object(Path,'read_text',return_value='flags : avx2'), \
                 patch.object(asan.subprocess,'run',side_effect=run):
                try: asan.main()
                except subprocess.CalledProcessError:
                    assert failure is not None
                else: assert failure is None
            cases+=1
    print(f'MD5 ASan/LSan enforcement: {cases} clean/hostile environment and fatal child cases passed')

if __name__=='__main__': main()
