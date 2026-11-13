"""Live host OpenSSL corpus generation; emulated tests consume bytes only."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
KEYS = 128
BLOCKS = 16
TESTS = {'malformed_population_is_rejected', 'aes128_oracle', 'aes192_oracle', 'aes256_oracle'}
MARKERS = [f'AES_RISCV_ORACLE: {bits} 2048 inputs; independent encrypt/decrypt; both owners; public output'
           for bits in (128, 192, 256)]


def sample(width, index, block=None):
    """Fixed public synthetic corpus, not random key generation."""
    size = width // 8 if block is None else 16
    selector = index if block is None else block
    if selector == 0:
        return bytes(size)
    if selector == 1:
        return bytes([255]) * size
    if selector == 2:
        return bytes(range(size))
    if selector == 3:
        return bytes([0x55, 0xaa]) * (size // 2)
    domain = f'brynja-rv64-aes-oracle-v1:{width}:{index}:{block}'.encode('ascii')
    return hashlib.sha256(domain).digest()[:size]


def prepare(directory):
    source = ROOT / 'assurance/aes-riscv-oracle/oracle.rs'
    if not source.is_file() or any(p.is_symlink() for p in (source, *source.parents)):
        raise ValueError('missing or symlinked RISC-V oracle harness')
    (directory / 'tests').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, directory / 'tests/oracle.rs')


def answer(executable, env, bits, key, inputs, inverse):
    result = subprocess.run([str(executable), 'enc', f'-aes-{bits}-ecb', '-nopad', '-nosalt',
                             '-K', key.hex(), '-d' if inverse else '-e'],
                            input=inputs, env=env, check=True, capture_output=True, timeout=15)
    if len(result.stdout) != len(inputs):
        raise ValueError('OpenSSL corpus output length mismatch')
    return result.stdout


def generate(directory, executable, env):
    destination = directory / 'tests/fixtures'
    destination.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for bits in (128, 192, 256):
        corpus = bytearray()
        for index in range(KEYS):
            key = sample(bits, index)
            inputs = b''.join(sample(bits, index, block) for block in range(BLOCKS))
            encrypted = answer(executable, env, bits, key, inputs, False)
            # Decrypt the original independent inputs, NOT our ciphertext.
            decrypted = answer(executable, env, bits, key, inputs, True)
            for start in range(0, len(inputs), 16):
                corpus.extend(key + inputs[start:start + 16] + encrypted[start:start + 16]
                              + decrypted[start:start + 16])
        if len(corpus) != 2048 * (bits // 8 + 48):
            raise ValueError('oracle corpus population changed')
        name = f'oracle{bits}.bin'
        (destination / name).write_bytes(corpus)
        hashes[name] = hashlib.sha256(corpus).hexdigest()
    return hashes


def check_output(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    if len(rows) != 4 or {name for name, _ in rows} != TESTS or any(status != 'ok' for _, status in rows):
        raise ValueError('wrong oracle test population')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    if len(summaries) != 1 or not summaries[0].startswith(
            'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'):
        raise ValueError('wrong oracle summary')
    if any(output.splitlines().count(marker) != 1 for marker in MARKERS):
        raise ValueError('wrong oracle comparison population')
