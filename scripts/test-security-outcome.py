#!/usr/bin/env python3
"""Exercise fail-closed v0.18.0 authority-contract fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import security_outcome_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(root: Path) -> None:
    for relative in security_outcome_policy.SOURCES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(root: Path, expected: str) -> None:
    try:
        security_outcome_policy.validate(root)
    except security_outcome_policy.SecurityOutcomePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"security-outcome fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-security-outcome-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        security_outcome_policy.validate(root)

        domain = root / security_outcome_policy.DOMAIN
        replace(
            domain,
            "AuthenticationDecision,\n    Authentication,",
            "MissingAuthDomain,\n    Authentication,",
        )
        reject(root, "decision-domain drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(state, "record: Cell<AuthorityRecord>", "record: AuthorityRecord")
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(state, "record.generation.checked_add(1)", "Some(record.generation)")
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "matches!(resolution, SecurityResolution::Approved)",
            "false",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "SecurityResolution::Accepted) && !positive_authorized",
            "SecurityResolution::Accepted) && false",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "D::KIND == SecurityDecisionKind::TerminalTransition",
            "false",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(state, "!rejection_matches_domain(D::KIND, reason)", "false")
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(state, "!failure_matches_domain(D::KIND, reason)", "false")
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(state, "pub fn resolve(", "pub fn resolve_changed(")
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "pub struct SecurityPending",
            "#[derive(Clone)]\npub struct SecurityPending",
        )
        reject(root, "gained duplication")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "self.fail_terminal(SecurityTerminal::Integrity)",
            "self.fail_terminal(SecurityTerminal::ContractInvariant)",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "SecurityTerminal::DecisionAbandoned",
            "SecurityTerminal::ContractInvariant",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "SecurityTerminal::OutcomeAbandoned",
            "SecurityTerminal::ContractInvariant",
        )
        reject(root, "state or result drift")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        replace(
            state,
            "pub struct SecurityCompletion",
            "#[derive(Clone)]\npub struct SecurityCompletion",
        )
        reject(root, "gained duplication")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(external, "pub const fn complete(self)", "pub const fn complete(&self)")
        reject(root, "external-key mandatory transition drift")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(
            external,
            "DestructionTarget::ExternalStore",
            "DestructionTarget::LocalMemory",
        )
        reject(root, "external-key mandatory transition drift")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(external, "token_issued: bool", "token_issued: ()")
        reject(root, "external-key mandatory transition drift")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(
            external,
            "proof.generation == pending.generation()",
            "true",
        )
        reject(root, "external-key mandatory transition drift")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(
            external,
            "pending.resolve_verified_accepted()",
            "pending.resolve(SecurityResolution::Pending)",
        )
        reject(root, "external-key mandatory transition drift")
        copy_fixture(root)

        external = root / security_outcome_policy.EXTERNAL_KEY
        replace(
            external,
            "pub struct ExternalKeyDestructionToken",
            "#[derive(Clone)]\npub struct ExternalKeyDestructionToken",
        )
        reject(root, "gained duplication")
        copy_fixture(root)

        module = root / security_outcome_policy.MODULE
        module.write_text(module.read_text(encoding="utf-8") + "\nfn native() { unsafe {} }\n", encoding="utf-8")
        reject(root, "forbidden boundary")
        copy_fixture(root)

        state = root / security_outcome_policy.STATE
        state.write_text(state.read_text(encoding="utf-8") + "\n" * 100, encoding="utf-8")
        reject(root, "exceeds 500 lines")
        copy_fixture(root)

        module = root / security_outcome_policy.MODULE
        module.write_text(module.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        reject(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("security-outcome policy rejects twenty-three domain, authority, evidence, commit, abandonment, self-test, destruction, low-level, size, and hash regressions")
