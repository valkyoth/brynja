"""Offline RFC 8439 composition fixtures. All bytes are public test data."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RFC = ROOT / 'rfc/rfc8439.txt'
MANIFEST = ROOT / 'assurance/chacha20poly1305/Cargo.toml'


def dump(section, label):
    # Match a whole heading and consecutive offset-prefixed hex rows only.
    match, = re.finditer(r'^ *' + re.escape(label) + r' *\n', section, re.M)
    result = bytearray()
    for line in section[match.end():].splitlines():
        row = re.fullmatch(r' *(\d{3})  ((?:[0-9a-f]{2} ){0,15}[0-9a-f]{2})  .*', line)
        if not row:
            break
        if int(row[1]) != len(result):
            raise ValueError('broken RFC row offset: ' + label)
        result.extend(bytes.fromhex(row[2]))
    if not result:
        raise ValueError('empty RFC field: ' + label)
    return bytes(result)


def records():
    raw = RFC.read_bytes()
    if hashlib.sha256(raw).hexdigest() != '25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c':
        raise ValueError('RFC source changed; review before updating vectors')
    text = raw.decode('ascii')
    seal = text.split('\n2.8.2.  Example and Test Vector', 1)[1].split('\n3.  Implementation Advice', 1)[0]
    opened = text.split('\nA.5.  ChaCha20-Poly1305 AEAD Decryption\n', 1)[1].split('\nAppendix B.', 1)[0]
    tag, = re.findall(r'^   Tag:\n   ([0-9a-f:]+)$', seal, re.M)
    return [
        [dump(seal, 'Key:'), dump(seal, '32-bit fixed-common part:') + dump(seal, 'IV:'),
         dump(seal, 'AAD:'), dump(seal, 'Plaintext:'), dump(seal, 'Ciphertext:'),
         dump(seal, 'Poly1305 Key:'), dump(seal, 'AEAD Construction for Poly1305:'),
         bytes.fromhex(tag.replace(':', ''))],
        [dump(opened, 'The ChaCha20 Key'), dump(opened, 'The nonce:'), dump(opened, 'The AAD:'),
         dump(opened, 'Plaintext::'), dump(opened, 'Ciphertext:'), dump(opened, 'Poly1305 one-time key:'),
         dump(opened, 'Poly1305 Input:'), dump(opened, 'Received Tag:')],
    ]


def differential(replay, paired=False):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    # The lengths vary independently. Cover every 16-byte padding residue,
    # and cross payload block boundaries with nonzero, deterministic data.
    aad_sizes = (*range(18), 31, 32, 33, 63, 64, 65, 127, 128, 129)
    payload_sizes = (*range(18), 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257)
    sizes = [(a, p) for a in aad_sizes for p in payload_sizes] + [(4097, 0), (0, 4097), (4097, 4097)]
    if paired:
        sizes.extend((a, p) for a in (0, 15, 1023, 1024, 1025) for p in (255, 256, 257, 1023, 1024, 1025, 1500))
    rows = []
    for index, (a, p) in enumerate(sizes):
        seed = b'Brynja public AEAD differential v1/' + index.to_bytes(4, 'big')
        def data(label, n):
            return hashlib.shake_256(seed + label).digest(n)
        key, nonce, aad, plain = data(b'key', 32), data(b'nonce', 12), data(b'aad', a), data(b'plain', p)
        encrypted = ChaCha20Poly1305(key).encrypt(nonce, plain, aad)
        rows.append([key, nonce, aad, plain, encrypted[:-16], encrypted[-16:]])
    result = replay(rows, ('--differential',))
    if result.returncode or result.stdout.strip() != f'matched {len(rows)} differential AEAD records':
        raise ValueError('differential replay failed: ' + result.stderr)
    # Corrupt one full-size row, preserving field widths and parseability.
    for field in range(6):
        wrong = rows[-1].copy()
        changed = bytearray(wrong[field])
        changed[-1] ^= 0x80
        wrong[field] = bytes(changed)
        bad = replay([wrong], ('--differential',))
        if bad.returncode != 1 or bad.stderr.strip() != 'Error: "AEAD differential mismatch"' or bad.stdout:
            raise ValueError(f'differential negative control failed for field {field}')
    print(f'{len(rows)} independent AEAD records in both layouts; six altered-answer controls passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', choices=['1.90.0', '1.100.0'])
    routes = parser.add_mutually_exclusive_group()
    routes.add_argument('--paired-neon', action='store_true', help='require the Linux or macOS AArch64 NEON AEAD owner')
    routes.add_argument('--paired-x86', action='store_true', help='require the Linux x86-64 SSE2/AVX2 AEAD owner')
    parser.add_argument('--oracle', action='store_true', help='also check with Python cryptography (test only)')
    parser.add_argument('--differential', action='store_true',
                        help='also run deterministic boundary records from Python cryptography (test only)')
    args = parser.parse_args()
    cases = records()
    if args.oracle:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.exceptions import InvalidTag
        for key, nonce, aad, pt, ct, _, _, tag in cases:
            aead = ChaCha20Poly1305(key)
            if aead.encrypt(nonce, pt, aad) != ct + tag or aead.decrypt(nonce, ct + tag, aad) != pt:
                raise ValueError('independent AEAD answer mismatch')
            try:
                aead.decrypt(nonce, ct + tag, aad + b'\0')
            except InvalidTag:
                pass
            else:
                raise ValueError('independent oracle accepted altered AAD')
    cargo = ['cargo'] + (['+' + args.rust] if args.rust else [])
    command = cargo + ['run', '--locked', '--offline', '--quiet', '--release', '--manifest-path', str(MANIFEST)]
    if args.paired_neon:
        command += ['--features', 'paired-neon']
    if args.paired_x86:
        command += ['--features', 'paired-x86']

    def replay(rows, mode=()):
        data = ''.join('\t'.join(value.hex() for value in row) + '\n' for row in rows)
        return subprocess.run(command + (['--', *mode] if mode else []), input=data, text=True,
                              capture_output=True, timeout=120)

    result = replay(cases)
    if result.returncode or result.stdout.strip() != 'matched 2 RFC AEAD records':
        raise ValueError('positive RFC replay failed: ' + result.stderr)
    # Alter every field independently; parse errors or build failures do not count.
    for i in range(8):
        changed = cases[0].copy()
        data = bytearray(changed[i])
        data[-1] ^= 1
        changed[i] = bytes(data)
        result = replay([changed])
        if result.returncode != 1 or result.stderr.strip() != 'Error: "RFC record mismatch"' or result.stdout:
            raise ValueError(f'wrong result for altered RFC field {i}')
    print('RFC 8439 AEAD: 2 composition records and 8 altered-field controls passed')
    if args.differential:
        differential(replay, args.paired_x86 or args.paired_neon)


if __name__ == '__main__':
    main()
