#!/usr/bin/env python3
"""Check both compiler endpoints and both kernels, including unwind builds."""
import tempfile
import argparse
import subprocess
import re
from pathlib import Path
import md5_hardened_codegen as codegen


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--native',action='store_true')
    args=parser.parse_args()
    compilers=('1.98.1',) if args.native else ('1.90.0','1.98.1')
    targets=('x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu')
    if args.native:
        identity=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True)
        targets=tuple(line.removeprefix('host: ') for line in identity.splitlines() if line.startswith('host: '))
        if len(targets)!=1 or targets[0] not in ('x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','aarch64-apple-darwin'):
            raise ValueError('unsupported native compiler host')
    with tempfile.TemporaryDirectory(prefix='brynja-md5-hardened-codegen-') as directory:
        for compiler in compilers:
            for target in targets:
                for panic in ('abort','unwind'):
                    contents = codegen.compile_and_check(Path(directory)/(compiler+target+panic),compiler,target,panic)
                    # Exact MIR field/call deletion must not retain an accepted receipt.
                    for old, new in (('Scratch::wipe(move _1)', 'Scratch::wipe(move _999)'),
                                     ('clear_owned_region(', 'omitted_clear('),
                                     ('((*_1).1: [[u8; 32]; 16])','((*_1).0: [[u8; 32]; 16])')):
                        if old not in contents[0]: raise ValueError('compiler mutation site missing')
                        try: codegen.mir_check(contents[0].replace(old,new),panic)
                        except (ValueError, codegen.flow.MirCleanupFlowError): pass
                        else: raise AssertionError('cleanup MIR mutation escaped')
                    instruction = 'vpaddd' if target.startswith('x86_64') else 'ushl'
                    for level, old, new in (
                        (2, instruction, 'omitted_simd'),
                        (2, 'clear_owned_region', 'omitted_clear'),
                        (1, r'\b96\b', '8'),
                    ):
                        mutated = list(contents)
                        if not re.search(old, mutated[level]):
                            raise ValueError('emitted-code mutation site missing')
                        mutated[level] = re.sub(old, new, mutated[level])
                        try: codegen.artifacts_check(*mutated,target,panic)
                        except (ValueError, codegen.flow.MirCleanupFlowError): pass
                        else: raise AssertionError('emitted-code mutation escaped')
                    print(f'MD5 hardened MIR/LLVM/SIMD assembly: PASS; {compiler}; {target}; panic={panic}')


if __name__ == '__main__': main()
