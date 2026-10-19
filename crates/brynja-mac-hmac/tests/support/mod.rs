//! Assertion helpers that retain the workspace's no-unwrap test policy.
macro_rules! require_ok {
    ($value:expr) => {{
        let value = $value;
        assert!(value.is_ok(), "operation rejected");
        let Ok(value) = value else { return };
        value
    }};
}

macro_rules! require_some {
    ($value:expr) => {{
        let value = $value;
        assert!(value.is_some(), "missing value");
        let Some(value) = value else { return };
        value
    }};
}

pub fn decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}
