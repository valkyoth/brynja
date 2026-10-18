#!/usr/bin/env python3
"""Require fresh owner-reviewed operational MD5 native observations before tag."""
import md5_execution_native
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
    from native_evidence_approval import validate as approve
    approve('md5-execution')
    md5_execution_native.validate()
