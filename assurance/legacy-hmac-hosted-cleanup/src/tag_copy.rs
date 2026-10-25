//! Copy status representation; not a native execution observation.
#[inline(never)]
pub fn success() -> Result<(), brynja_core::SecretMemoryError> {
    Ok(())
}

#[inline(never)]
pub fn empty() -> Result<(), brynja_core::SecretMemoryError> {
    Err(brynja_core::SecretMemoryError::EmptyRegion)
}

#[inline(never)]
pub fn overflow() -> Result<(), brynja_core::SecretMemoryError> {
    Err(brynja_core::SecretMemoryError::LengthOverflow)
}

#[inline(never)]
pub fn capacity() -> Result<(), brynja_core::SecretMemoryError> {
    Err(brynja_core::SecretMemoryError::InsufficientCapacity)
}

#[inline(never)]
pub fn incomplete() -> Result<(), brynja_core::SecretMemoryError> {
    Err(brynja_core::SecretMemoryError::IncompleteInitialization)
}
