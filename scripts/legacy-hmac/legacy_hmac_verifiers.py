"""Reuse reviewed, isolated verifier setup without importing a cryptographic API."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('legacy_verifier_setup', ROOT / 'scripts/hmac/hmac_verifiers.py')
_shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_shared)
tool, environment, run = _shared.tool, _shared.environment, _shared.run
cargo_environment = _shared.cargo_environment
