#!/usr/bin/env python3
"""Exercise fail-closed v0.13.0 provider-contract fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import provider_contract_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(destination: Path) -> None:
    target = destination / provider_contract_policy.SOURCE_ROOT
    target.mkdir(parents=True, exist_ok=True)
    for relative in provider_contract_policy.SOURCES:
        shutil.copy2(
            ROOT / provider_contract_policy.SOURCE_ROOT / relative,
            target / relative,
        )


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        provider_contract_policy.validate(root)
    except provider_contract_policy.ProviderContractPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"provider fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-provider-contract-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        provider_contract_policy.validate(root)

        provider = root / provider_contract_policy.SOURCE_ROOT / "provider.rs"
        replace(provider, "    PendingCancel,", "")
        require_rejection(root, "exact-operation inventory")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        contract = root / provider_contract_policy.SOURCE_ROOT / "provider_contract.rs"
        replace(
            contract,
            "if self.provider.capabilities.contains(operation)",
            "if true",
        )
        require_rejection(root, "exact-operation authorization")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        contract = root / provider_contract_policy.SOURCE_ROOT / "provider_contract.rs"
        replace(contract, "provider: self.provider,", "provider: self.provider.or_else(),")
        require_rejection(root, "implicit fallback")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        replace(request, "primary: &'data [u8],", "primary: &'data mut [u8],")
        require_rejection(root, "mutable effect buffer")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        contract = root / provider_contract_policy.SOURCE_ROOT / "provider_contract.rs"
        replace(contract, "if destruction_targets.is_empty()", "if false")
        require_rejection(root, "destruction-target")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        request.write_text(
            request.read_text(encoding="utf-8") + "\nuse crate::ProtocolVersion;\n",
            encoding="utf-8",
        )
        require_rejection(root, "forbidden dependency")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        contract = root / provider_contract_policy.SOURCE_ROOT / "provider_contract.rs"
        contract.write_text(
            contract.read_text(encoding="utf-8") + "\nuse brynja_platform as platform;\n",
            encoding="utf-8",
        )
        require_rejection(root, "forbidden dependency")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        contract = root / provider_contract_policy.SOURCE_ROOT / "provider_contract.rs"
        replace(
            contract,
            "pub struct ProviderHandle<'provider>",
            "#[derive(Clone)]\npub struct ProviderHandle<'provider>",
        )
        require_rejection(root, "duplication or formatting")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        request.write_text(
            request.read_text(encoding="utf-8") + "\npub fn complete() {}\n",
            encoding="utf-8",
        )
        require_rejection(root, "manufacture a provider result")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        replace(
            request,
            "provider: &'provider InstalledProvider,",
            "resources: &'provider ResourceBudget,",
        )
        require_rejection(root, "detachable resource budget")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        request.write_text(
            request.read_text(encoding="utf-8") + "\n// work_units\n",
            encoding="utf-8",
        )
        require_rejection(root, "caller-supplied work claim")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        request = root / provider_contract_policy.SOURCE_ROOT / "provider_request.rs"
        replace(request, "operation.forbids_byte_output()", "false")
        require_rejection(root, "verification output prohibition")
        shutil.rmtree(root / provider_contract_policy.SOURCE_ROOT)
        copy_fixture(root)

        capability = root / provider_contract_policy.SOURCE_ROOT / "provider_capability.rs"
        capability.write_text(
            capability.read_text(encoding="utf-8") + "\n// unreviewed drift\n",
            encoding="utf-8",
        )
        require_rejection(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("provider policy rejects thirteen capability, fallback, mutability, duty, identity, result-forgery, work, dependency-inversion, token, and hash regressions")
