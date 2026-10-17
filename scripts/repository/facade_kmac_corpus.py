"""Production-sized inputs using the existing independent SP 800-185 oracle."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('kmac128', 'kmac256', 'kmacxof128', 'kmacxof256')


def require(value, message):
    if not value:
        raise ValueError('facade KMAC corpus: ' + message)


def cases():
    directory = ROOT / 'scripts/kmac'
    sys.path.insert(0, str(directory))
    try:
        spec = importlib.util.spec_from_file_location('facade_kmac_oracle', directory / 'check-kmac-execution.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        oracle = module.oracle_module()
        oracle.verify_oracle()
        result = module.official(oracle)
        require(len(result) == 12, 'official population')
        for index, (name, _, _, custom, cb, message, mb, ob, _) in enumerate(oracle.cases()):
            strength = 128 if name.endswith('128') else 256
            kb = strength + (0, 1, 7, 8, 129, 257, 1024, 1025)[index % 8]
            key = oracle.oracle.canonical(0x40_0000 + index, kb)
            # Fixed secret/tag transitions require full strength; XOF retains
            # the original zero/short/partial/rate-crossing output cases.
            ob = max(ob, strength) if name in ('kmac128', 'kmac256') else ob
            answer = oracle.kmac(168 if strength == 128 else 136,
                oracle.oracle.byte_bits(key)[:kb], oracle.oracle.byte_bits(message)[:mb],
                oracle.oracle.byte_bits(custom)[:cb], ob, name.startswith('kmacxof'))
            result.append((name, key, kb, custom, cb, message, mb, ob, answer))
    finally:
        sys.path.pop(0)
    return result


def render(rows):
    counts = dict.fromkeys(NAMES, 0)
    requests, answers = [], []
    for name, key, kb, custom, cb, message, mb, ob, answer in rows:
        require(name in counts, 'identity')
        strength = 128 if name.endswith('128') else 256
        require(kb >= strength and (name.startswith('kmacxof') or ob >= strength), 'production sizes')
        for value, bits in ((key, kb), (custom, cb), (message, mb), (answer, ob)):
            require(0 <= bits <= 32768 and len(value) == (bits + 7) // 8 and
                    (not bits % 8 or value[-1] >> (bits % 8) == 0), 'canonical shape')
        require(ob <= 4095, 'output limit')
        counts[name] += 1
        requests.append(f'{name} {kb} {key.hex() or "-"} {cb} {custom.hex() or "-"} {mb} {message.hex() or "-"} {ob}')
        answers.append(answer.hex())
    require(len(rows) == 268 and set(counts.values()) == {67}, 'population')
    return '\n'.join(requests) + '\n', answers


def invalid():
    cases = [
        ('kmac128 1 80 0 - 0 - 128', 'InvalidData', 'noncanonical bit string'),
        ('kmacxof256 0 - 0 - 0 - 4096', 'InvalidData', 'length exceeds campaign limit'),
        ('unknown 0 - 0 - 0 - 128', 'Other', 'unknown algorithm'),
        ('kmac128 0 - 0 - 0 - 128 trailing', 'InvalidData', 'too many fields'),
        ('kmac128 0 - 0 - 0 - 18446744073709551616', 'InvalidData', 'invalid length'),
    ]
    for name in NAMES:
        cases.append((f'{name} 0 - 0 - 0 - 256', 'Other', 'KMAC execution rejected input: KeyTooShort'))
        strength = 128 if name.endswith('128') else 256
        key = bytes([1] * (strength // 8)).hex()
        cases.append((f'{name} {strength - 1} {key} 0 - 0 - 256', 'Other', 'KMAC execution rejected input: KeyTooShort'))
        if not name.startswith('kmacxof'):
            cases.append((f'{name} {strength} {key} 0 - 0 - 63', 'Other', 'KMAC execution rejected input: TagTooShort'))
            cases.append((f'{name} {strength} {key} 0 - 0 - {strength - 1}', 'Other', 'KMAC execution rejected input: TagTooShort'))
    return tuple(cases)
