#!/usr/bin/env python3
"""Fail closed until the four native hardened MD5 captures are reviewed."""
import md5_hardened_native
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
    from native_evidence_approval import validate as approve
    approve('md5-hardened')
    md5_hardened_native.validate()
