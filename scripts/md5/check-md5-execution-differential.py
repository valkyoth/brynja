#!/usr/bin/env python3
"""Independent bounded bit oracle with exact per-batch SIMD/scalar accounting."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import random
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'assurance/md5-execution/Cargo.toml'
spec = importlib.util.spec_from_file_location('md5_oracle', Path(__file__).with_name('check-md5-differential.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def campaign(binary, mode, width, prefix=()):
    rng = random.Random(0x2431321)
    requests, expected = [], []
    for case in range(384):
        fields, hashes, lengths = [], [], []
        for lane in range(8):
            if case < 256 and not (case & (1 << lane)):
                fields.append('~'); hashes.append('00'*16); lengths.append(None); continue
            bits = (rng.choice([0, 1, 447, 448, 511, 512, 513, 1024, 8192])
                    if case < 256 else rng.randrange(513,8193))
            data = bytearray(rng.randbytes((bits+7)//8))
            if bits % 8: data[-1] &= (255 << (8-bits%8)) & 255
            digest = oracle.oracle(data, bits)
            if bits % 8 == 0: assert digest == hashlib.md5(data, usedforsecurity=False).hexdigest()
            fields.append(f'{bits}:{data.hex() or "-"}')
            hashes.append(digest); lengths.append(bits)
        vectors = sum(min(0 if n is None else n//512 for n in lengths[i:i+width])*width
                      for i in range(0,8,width)) if width else 0
        scalar = sum((n+65+511)//512 for n in lengths if n is not None)-vectors
        if mode == 'require' and not vectors: continue
        requests.append(' '.join(fields)+'\n')
        expected.append(' '.join(hashes)+f' {width if vectors else 0} {vectors} {scalar}')
    result = subprocess.run([*prefix,str(binary),mode],input=''.join(requests),text=True,capture_output=True,timeout=180,check=True)
    if result.stdout.splitlines() != expected: raise ValueError('MD5 operational oracle or route accounting mismatch')
    for bad in ('~ '*7+'\n','~ '*9+'\n','8193:- '+'~ '*7+'\n',
                '18446744073709551615:- '+'~ '*7+'\n','99999999999999999999999:- '+'~ '*7+'\n',
                '1:01 '+'~ '*7+'\n','8:gg '+'~ '*7+'\n','x'*32768):
        result = subprocess.run([*prefix,str(binary),mode],input=bad,text=True,capture_output=True,timeout=15)
        if result.returncode == 0 or result.stdout or 'panicked' in result.stderr:
            raise ValueError('malformed operational request did not fail cleanly')
    print(f'MD5 operational independent oracle: {len(expected)} batches; mode={mode}; width={width}; 8 malformed requests rejected')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--width',type=int,choices=(0,4,8),default=0)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--qemu',action='store_true')
    args=parser.parse_args()
    binary=args.binary
    if binary is None:
        subprocess.run(['cargo','build','--locked','--offline','--release','--manifest-path',MANIFEST],cwd=ROOT,check=True)
        target=Path(os.environ.get('CARGO_TARGET_DIR',ROOT/'assurance/md5-execution/target'))
        binary=target/'release/brynja-md5-execution-fixture'
        if os.name=='nt': binary=binary.with_suffix('.exe')
    prefix=('qemu-aarch64','-cpu','max') if args.qemu else ()
    campaign(binary,'portable',0,prefix)
    campaign(binary,'prefer',args.width,prefix)
    campaign(binary,'hosted',args.width,prefix)
    if args.width: campaign(binary,'require',args.width,prefix)


if __name__=='__main__': main()
