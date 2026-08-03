# Brynja v0.11.0 Development Milestone

Status: implementation in progress; not yet tagged

Brynja v0.11.0 is the first tagged development milestone in the five-minor
release train ending at public checkpoint v0.15.0. It advances the `brynja`
facade version and will receive a signed tag only after its complete automated
gate and green GitHub and CodeQL. It has no scheduled pentest report and
selects no crate for crates.io publication.

## Planned Scope

The implementation scope remains the owned-memory zeroization primitive in the
normative release and version plans. This governance transition does not claim
that primitive is implemented.

## Cumulative Pentest Coverage

The next scheduled assessment is v0.15.0. It will pentest backwards over all
changes after public tag v0.10.0 through the exact v0.15.0 candidate, including
v0.11.0 and every intervening minor or patch milestone. The following v0.20.0
assessment will cover changes after v0.15.0 through v0.20.0.

An exceptional security trigger may require an earlier assessment, but does
not remove any change from the next scheduled cumulative checkpoint.

## Publication

No package is selected. The latest crates.io facade remains `brynja 0.10.0`;
supporting crates retain their independently published versions.
