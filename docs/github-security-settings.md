# GitHub Security Settings

Status: main-branch ruleset active and machine checked

The repository has one active `Valkyoth Protect Main Branch` ruleset targeting
the default branch. `github-release-controls.toml` is the local source of truth,
and `scripts/check-github-release-controls.py` compares the live GitHub ruleset
before release and in CI. CI's read-only token checks every publicly visible
rule; the privileged local release gate additionally checks the exact bypass
identities and modes because GitHub hides those from read-only callers.

The ruleset blocks deletion, creation outside the authorized bypass path,
non-fast-forward updates, and ordinary direct updates. It requires linear
history, signed commits, one approving review, stale-review dismissal,
CODEOWNER review, approval by someone other than the last pusher, and clean
CodeQL results at all alert severities. The repository owner and organization
administrators retain explicit always-bypass authority so the documented
owner-driven release workflow remains possible; bypass use is a security-
relevant action and does not replace the applicable automated tag gate, green
CI and CodeQL, signed tag, or checkpoint pentest.

CODEOWNERS explicitly protects Cargo state, dependency and GitHub-control
policy, workflows, RFC evidence, release scripts, and security reports. GitHub
CodeQL remains on Default setup; no advanced CodeQL workflow is added.
Secret scanning, push protection, Dependabot alerts, and private vulnerability
reporting remain maintainer settings that must stay enabled and be reviewed
through GitHub because their full state is not represented by repository files.
