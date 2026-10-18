#!/usr/bin/env python3
"""Release-only native evidence gate; ordinary CI does not require collected lanes."""
import parallelhash_execution_native

if __name__ == '__main__':
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
    from native_evidence_approval import validate as approve
    approve('parallelhash-execution')
    parallelhash_execution_native.validate()
