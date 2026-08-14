//! Canonical DER UTCTime and GeneralizedTime values.

use super::{Asn1Error, require_primitive};
use crate::DerElement;

/// One validated DER UTCTime in exact `YYMMDDHHMMSSZ` form.
///
/// This type intentionally omits diagnostic formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UtcTime<'input> {
    encoded: &'input [u8],
    fields: TimeFields,
}

/// One validated DER GeneralizedTime in canonical UTC form.
///
/// This type intentionally omits diagnostic formatting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GeneralizedTime<'input> {
    encoded: &'input [u8],
    fraction: &'input [u8],
    fields: TimeFields,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TimeFields {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl<'input> UtcTime<'input> {
    /// Validates the exact DER UTCTime form and Gregorian calendar date.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 23)?;
        let encoded = element.contents();
        if encoded.len() != 13 || encoded.last().copied() != Some(b'Z') {
            return Err(Asn1Error::InvalidTime);
        }
        let short_year = decimal(encoded, 0, 2)?;
        let year = if short_year >= 50 {
            1900_u16
                .checked_add(u16::from(short_year))
                .ok_or(Asn1Error::ValueOverflow)?
        } else {
            2000_u16
                .checked_add(u16::from(short_year))
                .ok_or(Asn1Error::ValueOverflow)?
        };
        let fields = parse_fields(encoded, year, 2)?;
        Ok(Self { encoded, fields })
    }

    /// Borrows the exact canonical contents.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.encoded
    }

    /// Returns the normalized four-digit year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.fields.year
    }

    /// Returns `(month, day, hour, minute, second)`.
    #[must_use]
    pub const fn fields(self) -> (u8, u8, u8, u8, u8) {
        field_tuple(self.fields)
    }
}

impl<'input> GeneralizedTime<'input> {
    /// Validates DER UTC termination, seconds, fraction, and calendar rules.
    pub fn decode(element: DerElement<'input>) -> Result<Self, Asn1Error> {
        require_primitive(element, 24)?;
        let encoded = element.contents();
        if encoded.len() < 15 || encoded.last().copied() != Some(b'Z') {
            return Err(Asn1Error::InvalidTime);
        }
        let year = decimal_four(encoded, 0)?;
        let fields = parse_fields(encoded, year, 4)?;
        let fraction = if encoded.len() == 15 {
            encoded.get(..0).ok_or(Asn1Error::InvalidTime)?
        } else {
            if encoded.get(14).copied() != Some(b'.') {
                return Err(Asn1Error::InvalidTime);
            }
            let end = encoded
                .len()
                .checked_sub(1)
                .ok_or(Asn1Error::ValueOverflow)?;
            let digits = encoded.get(15..end).ok_or(Asn1Error::InvalidTime)?;
            if digits.is_empty()
                || !digits.iter().all(u8::is_ascii_digit)
                || digits.last().copied() == Some(b'0')
            {
                return Err(Asn1Error::InvalidTime);
            }
            digits
        };
        Ok(Self {
            encoded,
            fraction,
            fields,
        })
    }

    /// Borrows the exact canonical contents.
    #[must_use]
    pub const fn as_bytes(self) -> &'input [u8] {
        self.encoded
    }

    /// Borrows fractional-second digits without the decimal point.
    #[must_use]
    pub const fn fraction(self) -> &'input [u8] {
        self.fraction
    }

    /// Returns the four-digit year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.fields.year
    }

    /// Returns `(month, day, hour, minute, second)`.
    #[must_use]
    pub const fn fields(self) -> (u8, u8, u8, u8, u8) {
        field_tuple(self.fields)
    }
}

const fn field_tuple(fields: TimeFields) -> (u8, u8, u8, u8, u8) {
    (
        fields.month,
        fields.day,
        fields.hour,
        fields.minute,
        fields.second,
    )
}

fn parse_fields(encoded: &[u8], year: u16, offset: usize) -> Result<TimeFields, Asn1Error> {
    let month = decimal(encoded, offset, 2)?;
    let day = decimal(
        encoded,
        offset.checked_add(2).ok_or(Asn1Error::ValueOverflow)?,
        2,
    )?;
    let hour = decimal(
        encoded,
        offset.checked_add(4).ok_or(Asn1Error::ValueOverflow)?,
        2,
    )?;
    let minute = decimal(
        encoded,
        offset.checked_add(6).ok_or(Asn1Error::ValueOverflow)?,
        2,
    )?;
    let second = decimal(
        encoded,
        offset.checked_add(8).ok_or(Asn1Error::ValueOverflow)?,
        2,
    )?;
    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(Asn1Error::InvalidTime);
    }
    Ok(TimeFields {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

fn decimal(input: &[u8], start: usize, width: usize) -> Result<u8, Asn1Error> {
    let end = start.checked_add(width).ok_or(Asn1Error::ValueOverflow)?;
    let digits = input.get(start..end).ok_or(Asn1Error::InvalidTime)?;
    let mut value = 0_u8;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(Asn1Error::InvalidTime);
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(digit.wrapping_sub(b'0')))
            .ok_or(Asn1Error::ValueOverflow)?;
    }
    Ok(value)
}

fn decimal_four(input: &[u8], start: usize) -> Result<u16, Asn1Error> {
    let end = start.checked_add(4).ok_or(Asn1Error::ValueOverflow)?;
    let digits = input.get(start..end).ok_or(Asn1Error::InvalidTime)?;
    let mut value = 0_u16;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(Asn1Error::InvalidTime);
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u16::from(digit.wrapping_sub(b'0'))))
            .ok_or(Asn1Error::ValueOverflow)?;
    }
    Ok(value)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
