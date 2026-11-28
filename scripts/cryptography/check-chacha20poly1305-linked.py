"""Review and replay normal-return AEAD open on two named Linux x86-64 builds."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

HERE = Path(__file__).resolve().parent
poly = runpy.run_path(str(HERE / 'check-poly1305-linked.py'))
vectors = runpy.run_path(str(HERE / 'check-chacha20poly1305-vectors.py'))
elf, environment, ROOT = (poly[k] for k in ('elf', 'environment', 'ROOT'))
ENTRY = 'chacha20poly1305_rfc_replay::public_api::public_api'
OPEN = 'brynja_aead_chacha20poly1305::Opener::'
PINS = {
    '1.90.0': (209, 'c7c96e057723d1831240bec577eb2e16ff30bf00c698b56a7fc313668ab69bd3'),
    '1.100.0': (205, 'a3806f15a693835da84e758352d49d6d6122af540b85214e01911ab10f81e7f8'),
}


def fingerprint(trace):
    return hashlib.sha256(json.dumps(trace, separators=(',', ':')).encode()).hexdigest()


def screen(exe, version):
    image = elf.load(exe)
    require = elf.require
    caller = elf.unique(image, ENTRY)
    receive = elf.unique(image, OPEN + 'receive')
    trace = []
    for name in (OPEN + 'open', OPEN + 'open_in_place'):
        entry = elf.unique(image, name)
        require(entry in image.calls(caller) and receive in image.calls(entry), 'disconnected ' + name)
        trace.append((name, poly['instructions'](image, name)))
    require(image.children(receive, poly['VERIFY']), 'AEAD no longer uses reviewed verifier')
    require(fingerprint([(n, poly['instructions'](image, n)) for n in poly['BODIES']])
            == poly['PINS'][version], 'verifier or comparison/cleanup helper changed')
    reloc = subprocess.check_output(['llvm-objdump', '-R', str(exe)], text=True, timeout=60)
    # The only external symbol in the reviewed receive prefix is the commit copy.
    slots = {int(m[1], 16): 'extern:memcpy' for m in re.finditer(
        r'^([a-f0-9]+)\s+R_X86_64_GLOB_DAT\s+memcpy$', reloc, re.M)}
    limit, expected = PINS[version]
    body = poly['instructions'](image, OPEN + 'receive', limit=limit, external_slots=slots)
    require(any('GOT:extern:memcpy' in operand for _, operand in body), 'no reviewed destination copy')
    trace.append((OPEN + 'receive', body))
    actual = fingerprint(trace)
    require(actual == expected, f'{version}: changed AEAD open instructions ({actual})')


def main():
    cases = vectors['records']()
    for version in PINS:
        with environment.private_directory(ROOT) as tmp:
            root = Path(tmp)
            env = {k: os.environ[k] for k in ('PATH', 'HOME', 'RUSTUP_HOME') if k in os.environ}
            env.update(CARGO_HOME=str(root / 'cargo-home'), CARGO_TARGET_DIR=str(root / 'target'),
                       CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
            environment.check(root, env)
            subprocess.run(['cargo', '+' + version, 'build', '--locked', '--offline', '--release',
                            '--target', 'x86_64-unknown-linux-gnu', '--manifest-path', str(vectors['MANIFEST'])],
                           cwd=root, env=env, check=True, timeout=180)
            exe = root / 'target/x86_64-unknown-linux-gnu/release/chacha20poly1305-rfc-replay'
            digest = elf.digest(exe)
            screen(exe, version)
            # This mode exercises the public AEAD only (including wrong-tag opens),
            # not the fixture's separate standalone primitive checks.
            rows = [(*r[:5], r[-1]) for r in cases]
            transcript = ''.join('\t'.join(field.hex() for field in row) + '\n' for row in rows)
            result = subprocess.run([str(exe), '--differential'], input=transcript, text=True,
                                    capture_output=True, check=True, timeout=60, cwd=root, env=env)
            if result.stdout != 'matched 2 differential AEAD records\n' or elf.digest(exe) != digest:
                raise ValueError('replay mismatch or executable changed')
            print(f'{version}: AEAD open/cleanup screen and replay passed; ELF sha256 {digest}')
    print('ChaCha20-Poly1305 linked open: both x86-64 endpoints passed')


if __name__ == '__main__':
    main()
