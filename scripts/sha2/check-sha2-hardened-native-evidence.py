#!/usr/bin/env python3
"""Tag-only requirement; absent native observations block, never silently skip."""
import argparse
from pathlib import Path
import sys
import hardened_native_evidence as evidence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
from native_evidence_approval import validate as approve

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit')
    args = parser.parse_args()
    approve('sha2-hardened')
    evidence.validate(commit=args.commit)
