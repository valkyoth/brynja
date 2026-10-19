//! Public-length predicates shared by the engine and repository-only proofs.

pub(crate) const fn valid_tag_length(full: usize, selected: usize) -> bool {
    selected >= 16 && selected <= full
}

pub(crate) const fn exact_output(selected: usize, actual: usize) -> bool {
    selected == actual
}
