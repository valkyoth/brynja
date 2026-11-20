//! No compiler/target/profile combination has completed fault-model qualification.
//! Keep the private owner constructors closed in non-test builds until exact
//! linked-artifact evidence and a reviewed admission policy exist.

#[derive(Debug, Eq, PartialEq)]
pub(super) enum AdmissionError {
    UnqualifiedBuild,
}

pub(super) fn require(workbench_fixture: bool) -> Result<(), AdmissionError> {
    // `cfg(test)` is only a development-fixture switch. It is not a security
    // boundary against a builder controlling rustc arguments; no public profile
    // is exposed under it, and it must never authorize a release constructor.
    if cfg!(test) && workbench_fixture {
        Ok(())
    } else {
        Err(AdmissionError::UnqualifiedBuild)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_release_build_is_admitted() {
        assert_eq!(require(false), Err(AdmissionError::UnqualifiedBuild));
    }

    #[test]
    fn private_unit_fixture_can_run() {
        assert_eq!(require(true), Ok(()));
    }
}
