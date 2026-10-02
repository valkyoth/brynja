"""Public-vector version-22 encoder for the private native VBS campaign."""
from pathlib import Path
import tempfile
import windows_enclave_keccak_simd_oracle as oracle
from windows_protection_probe import require

DIGEST, EXPORT, CANCEL = 100, 101, 102


def cases():
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-simd-vectors-') as temp:
        directory = Path(temp)
        require(oracle.generate(directory) == 520, 'complete independent source catalog')
        lines = (directory/'keccak-simd-vectors.txt').read_text().splitlines()
    rows = []
    # Spread selected native cases over all identities, bit boundaries and mixed
    # layouts. The ordinary-process campaign executes the complete 520 cases.
    for index in [i*519//51 for i in range(52)]:
        layout, payload, expected = [], [], bytearray()
        for line in lines[index*4:index*4+4]:
            f = line.split()
            identity, mb, nb, sb, ob = (int(f[i]) for i in (0, 1, 3, 5, 7))
            layout.append((identity, ob, mb, nb, sb))
            payload.extend(bytes.fromhex(f[i]) if f[i] != '-' else b'' for i in (2, 4, 6))
            answer = bytes.fromhex(f[8]) if f[8] != '-' else b''
            expected.extend(answer.ljust(256, b'\0'))
        rows.append((layout, payload, bytes(expected)))
    return rows


def failure_row():
    # All twelve payloads are nonempty. This row is only used for rejection,
    # never as a successful oracle. High unused message bits begin canonical.
    return ([(7, 257, 513, 8, 16)]*4,
            [item for _ in range(4) for item in (b'\0'*65, b'N', b'SS')], b'\0'*1024)


def words_for(op, sequence, layout, pointers):
    require(len(layout) == 4 and len(pointers) == 12, 'four complete source triples')
    words = [22, sequence, 1000 if op == DIGEST else 0, 2]
    for lane, (identity, output_bits, mb, nb, sb) in enumerate(layout):
        fields = [identity, output_bits] if op != CANCEL else [0, 0]
        for part, bits in enumerate((mb, nb, sb)):
            fields.extend([(bits+7)//8, 1+(bits-1)%8, pointers[lane*3+part]]
                          if op == DIGEST and bits else [0, 0, 0])
        words.extend(fields)
    require(len(words) == 48, 'complete version-22 header')
    return words


def copy_counts(op, fault, layout):
    present = [bits != 0 for _, _, mb, nb, sb in layout for bits in (mb, nb, sb)]
    payload = 0
    if op == DIGEST and (fault is None or fault in ('budget', 'bits')):
        payload = sum(present)
    elif fault and fault.startswith('payload-'):
        index = int(fault.split('-')[1])
        require(0 <= index < 12 and present[index], 'selected failure payload exists')
        payload = sum(present[:index])
    return [int(fault != 'header-copy'), payload, int(op == EXPORT and fault is None),
            int(fault in ('header-copy', 'output-copy') or bool(fault and fault.startswith('payload-')))]
