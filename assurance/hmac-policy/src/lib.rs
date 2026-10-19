//! Bounds only: this is not a proof of HMAC, hash correctness or constant time.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

// Compile the actual runtime predicates, not a duplicate mathematical model.
#[path = "../../../crates/brynja-mac-hmac/src/policy.rs"]
mod policy;

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn tag_length_matches_exact_public_policy() {
        let full: usize = kani::any();
        let selected: usize = kani::any();
        let admitted = super::policy::valid_tag_length(full, selected);
        assert_eq!(admitted, !(selected < 16 || selected > full));
    }

    #[kani::proof]
    fn output_length_never_admits_prefix_or_extension() {
        let selected: usize = kani::any();
        let actual: usize = kani::any();
        assert_eq!(
            super::policy::exact_output(selected, actual),
            selected == actual
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn policy_boundaries() {
        for full in [0, 15, 16, 28, 32, 48, 64, usize::MAX] {
            for selected in (0..=65).chain([usize::MAX]) {
                assert_eq!(
                    super::policy::valid_tag_length(full, selected),
                    selected >= 16 && selected <= full
                );
                for actual in [0, 15, 16, full, selected, usize::MAX] {
                    assert_eq!(
                        super::policy::exact_output(selected, actual),
                        selected == actual
                    );
                }
            }
        }
    }
}
