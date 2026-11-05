//! Consume actual public AES owners after an observer may unwind.
//! Dispatch probes only; neither scratch nor physical erasure is established.
#![no_std]
#![forbid(unsafe_code)]

use brynja_crypto::aes::{
    Aes128ExpandedKey, Aes128Key, Aes192ExpandedKey, Aes192Key, Aes256ExpandedKey, Aes256Key,
    SecretBlock,
};

/// Observe the live key, then exercise its ordinary field Drop.
#[inline(never)]
pub fn key_drop(owner: Aes128Key<'_>, observer: fn(&Aes128Key<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Observe the live output, then exercise its ordinary field Drop.
#[inline(never)]
pub fn block_drop(owner: SecretBlock<'_>, observer: fn(&SecretBlock<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Cached schedule owns the same clearing descriptor, covering all 176 bytes.
#[inline(never)]
pub fn expanded_drop(owner: Aes128ExpandedKey<'_>, observer: fn(&Aes128ExpandedKey<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Observe the actual 24-byte key owner before normal/unwind destruction.
#[inline(never)]
pub fn aes192_key_drop(owner: Aes192Key<'_>, observer: fn(&Aes192Key<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Observe the actual 208-byte cached schedule owner.
#[inline(never)]
pub fn aes192_expanded_drop(owner: Aes192ExpandedKey<'_>, observer: fn(&Aes192ExpandedKey<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Observe the actual 32-byte key owner before normal/unwind destruction.
#[inline(never)]
pub fn aes256_key_drop(owner: Aes256Key<'_>, observer: fn(&Aes256Key<'_>)) {
    observer(&owner);
    drop(owner);
}

/// Observe the actual 240-byte cached schedule owner.
#[inline(never)]
pub fn aes256_expanded_drop(owner: Aes256ExpandedKey<'_>, observer: fn(&Aes256ExpandedKey<'_>)) {
    observer(&owner);
    drop(owner);
}
