"""Cross-build and test the unpublished RV64GC/V Poly1305 probe. No emulator timing."""
import argparse
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/repository'))
import facade_cargo_environment as cargo

TARGET = 'riscv64gc-unknown-linux-gnu'
SYMBOL = 'brynja_probe_poly1305_rvv_columns'


def corpus():
    # Identical public inputs and independent scalar big-integer answers to ARM.
    return runpy.run_path(str(Path(__file__).with_name('check-poly1305-neon-probe.py')))['corpus']()


def encode(rows):
    return ''.join(f'{k.hex()}\t{m.hex()}\t{t.hex()}\n' for _, k, m, t in rows).encode('ascii')


def screen(listing):
    ops = Counter(re.findall(r'^\s*[0-9a-f]+:\s+(\S+)', listing, re.M))
    counts = {'vsetivli': 2, 'vle32.v': 14, 'vwmulu.vv': 5, 'vwmaccu.vv': 20,
              'vredsum.vs': 5, 'vmv.x.s': 5, 'sd': 5}
    if listing.count(f'<{SYMBOL}>:') != 1 or any(ops[op] != n for op, n in counts.items()):
        raise ValueError('incomplete linked RVV column kernel')


def check(version, rows, linker, dest):
    with cargo.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'RUSTUP_HOME') if k in os.environ}
        env.update(CARGO_HOME=str(root / 'cargo'), CARGO_TARGET_DIR=str(root / 'target'),
                   CARGO_ENCODED_RUSTFLAGS='-Ctarget-feature=+crt-static', RUSTUP_AUTO_INSTALL='0',
                   CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=linker)
        cargo.check(root, env)
        subprocess.run(['cargo', '+' + version, 'build', '--offline', '--locked', '--release',
                        '--manifest-path', str(ROOT / 'assurance/poly1305/Cargo.toml'), '--target',
                        TARGET, '--example', 'rvv_four_block'], cwd=root, env=env, check=True, timeout=180)
        exe = root / 'target' / TARGET / 'release/examples/rvv_four_block'
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        listing = subprocess.check_output(['llvm-objdump', '-d', '--mattr=+v', '--no-show-raw-insn',
                                           '--disassemble-symbols=' + SYMBOL, exe], text=True)
        screen(listing)
        try:
            screen(listing.replace('vwmaccu.vv', 'nop'))
        except ValueError:
            pass
        else:
            raise ValueError('screen accepted missing vector products')

        def replay(cpu, data, status, stdout, stderr):
            r = subprocess.run(['qemu-riscv64', '-cpu', cpu, exe], input=data,
                               capture_output=True, timeout=120)
            if (r.returncode, r.stdout, r.stderr) != (status, stdout, stderr):
                raise ValueError(f'unexpected {version} {cpu} replay: {r.returncode}, {r.stderr[:240]!r}')

        label, k, m, t = rows[-1]
        wrong = encode([(label, k, m, bytes([t[0] ^ 1]) + t[1:])])
        for bits in (128, 256):
            cpu = f'rv64,v=true,vlen={bits},vext_spec=v1.0'
            replay(cpu, encode(rows), 0, f'matched {len(rows)} public vectors\n'.encode(), b'')
            replay(cpu, wrong, 1, b'', b'Error: "vector mismatch"\n')
        replay('rv64,v=false', encode(rows[:1]), 2, b'', b'RVV unavailable; no candidate run\n')
        if hashlib.sha256(exe.read_bytes()).hexdigest() != digest:
            raise ValueError('tested ELF changed')
        if dest:
            shutil.copy2(exe, dest / ('probe-' + version))
        print(f'{version}: {len(rows)} records at both VLENs, altered tag, no-V refusal and linked kernel passed; ELF {digest}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path, help='create a new directory containing the tested binaries and public input')
    args = parser.parse_args()
    linker = shutil.which('riscv64-linux-gnu-gcc') or shutil.which('riscv64-suse-linux-gcc')
    if not linker:
        raise SystemExit('static RV64GC Linux GNU cross-linker required')
    rows = corpus()
    if args.export:
        args.export.mkdir(mode=0o700)
    for compiler in ('1.90.0', '1.100.0'):
        check(compiler, rows, linker, args.export)
    if args.export:
        (args.export / 'public.tsv').write_bytes(encode(rows))
