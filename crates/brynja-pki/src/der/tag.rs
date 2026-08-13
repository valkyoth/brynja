//! Canonical DER tag identity.

/// ASN.1 tag class encoded in identifier bits 8 and 7.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TagClass {
    /// Universal class.
    Universal,
    /// Application class.
    Application,
    /// Context-specific class.
    ContextSpecific,
    /// Private class.
    Private,
}

/// One canonical identifier decoded without assigning ASN.1 value semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Tag {
    class: TagClass,
    constructed: bool,
    number: u64,
}

impl Tag {
    pub(crate) const fn new(class: TagClass, constructed: bool, number: u64) -> Self {
        Self {
            class,
            constructed,
            number,
        }
    }

    /// Returns the tag class.
    #[must_use]
    pub const fn class(self) -> TagClass {
        self.class
    }
    /// Returns whether the identifier declares constructed contents.
    #[must_use]
    pub const fn is_constructed(self) -> bool {
        self.constructed
    }
    /// Returns the decoded tag number.
    #[must_use]
    pub const fn number(self) -> u64 {
        self.number
    }
}
