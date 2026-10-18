#!/usr/bin/env python3
"""Mandatory fresh three-lane native qualification before tagging."""
import keccak_hardened_native as evidence

if __name__ == '__main__':
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
    from native_evidence_approval import validate as approve
    approve('keccak-hardened')
    evidence.validate()
