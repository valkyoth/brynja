//! Executable v0.24.30 contract model, NOT a production acceleration API.
//!
//! No crypto, CPU detection, execution authority, or production dependencies.
//! Ordinary downstream builds exercise the proposed selection vocabulary here;
//! actual activation belongs to the subsequent implementation milestones.
#![no_std]

mod selection;
mod vocabulary;

pub use selection::ContractSession;
pub use vocabulary::{Backend, Error, Fallback, Profile, Request, Route};

#[cfg(test)]
mod tests;
