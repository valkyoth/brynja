#!/usr/bin/env python3
"""Compare HMAC with Python/OpenSSL, without adding a production dependency."""
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ALGORITHMS = (
    "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
)


def main():
    rows = []
    for algorithm in ALGORITHMS:
        block = hashlib.new(algorithm).block_size
        for key_size in (0, 1, 15, 16, 31, 32, block - 1, block, block + 1, 1024):
            key = bytes((i * 29 + 7) % 256 for i in range(key_size))
            for size in (0, 1, 7, 55, 56, 63, 64, block - 1, block, block + 1, 1025):
                message = bytes((i * 131 + 17) % 256 for i in range(size))
                expected = hmac.new(key, message, algorithm).hexdigest()
                rows.append(":".join((algorithm, key.hex(), message.hex(), expected)))
    assert len(rows) == 1100
    with tempfile.TemporaryDirectory(prefix="brynja-hmac-oracle-") as directory:
        path = Path(directory) / "oracle.txt"
        path.write_text("\n".join(rows) + "\n", encoding="ascii")
        environment = os.environ.copy()
        environment["BRYNJA_HMAC_ORACLE"] = str(path)
        result = subprocess.run(
            ["cargo", "test", "-p", "brynja-mac-hmac", "--locked", "--offline",
             "--test", "differential", "--", "--ignored", "--exact", "external_oracle", "--nocapture"],
            cwd=ROOT, env=environment, check=True, text=True, capture_output=True,
        )
        marker = "HMAC_ORACLE: 1100 cases; 10 algorithms; 4 partitions and truncation per case"
        if marker not in result.stdout.splitlines():
            raise RuntimeError("missing full HMAC oracle population marker")
        print(result.stdout, end="")


if __name__ == "__main__":
    main()
