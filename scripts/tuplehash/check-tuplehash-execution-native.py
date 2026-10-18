#!/usr/bin/env python3
"""Require reviewed native TupleHash operations on all three registered lanes."""
import tuplehash_execution_native as evidence

if __name__ == '__main__':
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
    from native_evidence_approval import validate as approve
    approve('tuplehash-execution')
    evidence.validate()
