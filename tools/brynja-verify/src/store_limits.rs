//! Fixed artifact budgets, independent of untrusted saved state.
use crate::Result;
use serde::Serialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

// Enforce the global attempt count while parsing, before allocating the next
// row or resolving snapshots. Do not trust a deserializer's size_hint.
pub fn attempts<'de, D, S>(
    deserializer: D,
) -> std::result::Result<std::collections::BTreeMap<String, Vec<crate::model::Attempt<S>>>, D::Error>
where
    D: serde::Deserializer<'de>,
    S: serde::Deserialize<'de>,
{
    use crate::model::Attempt;
    use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
    use std::{collections::BTreeMap, fmt, marker::PhantomData};

    struct Rows<'a, S>(&'a mut usize, PhantomData<S>);
    struct Row<'a, S>(&'a mut usize, PhantomData<S>);
    struct Groups<S>(PhantomData<S>);

    impl<'de, S: serde::Deserialize<'de>> DeserializeSeed<'de> for Row<'_, S> {
        type Value = Attempt<S>;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            if *self.0 == 0 {
                return Err(D::Error::custom(
                    "attempt count exceeds storage limit (10000)",
                ));
            }
            *self.0 -= 1;
            serde::Deserialize::deserialize(d)
        }
    }
    impl<'de, S: serde::Deserialize<'de>> DeserializeSeed<'de> for Rows<'_, S> {
        type Value = Vec<Attempt<S>>;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de, S: serde::Deserialize<'de>> Visitor<'de> for Rows<'_, S> {
        type Value = Vec<Attempt<S>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded attempt rows")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            while let Some(row) = seq.next_element_seed(Row(&mut *self.0, PhantomData))? {
                rows.push(row);
            }
            Ok(rows)
        }
    }
    impl<'de, S: serde::Deserialize<'de>> Visitor<'de> for Groups<S> {
        type Value = BTreeMap<String, Vec<Attempt<S>>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("attempt groups")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut groups = BTreeMap::new();
            let mut remaining = LIMITS.attempts;
            while let Some(key) = map.next_key()? {
                if groups.contains_key(&key) {
                    return Err(A::Error::custom("duplicate attempt group key"));
                }
                let rows = map.next_value_seed(Rows(&mut remaining, PhantomData))?;
                groups.insert(key, rows);
            }
            Ok(groups)
        }
    }
    deserializer.deserialize_map(Groups(PhantomData))
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub index: usize,
    pub object: usize,
    pub total_objects: usize,
    pub attempts: usize,
}

pub const LIMITS: Limits = Limits {
    index: 64 * 1024 * 1024,
    object: 2 * 1024 * 1024,
    total_objects: 256 * 1024 * 1024,
    attempts: 10_000,
};

pub fn size(actual: usize, maximum: usize, kind: &str) -> Result<()> {
    if actual > maximum {
        return Err(format!("{kind} exceeds storage limit ({maximum})").into());
    }
    Ok(())
}

pub fn charge(total: &mut usize, amount: usize, maximum: usize, kind: &str) -> Result<()> {
    let next = total
        .checked_add(amount)
        .ok_or_else(|| format!("{kind} storage limit overflow"))?;
    size(next, maximum, kind)?;
    *total = next;
    Ok(())
}

// Limit the stream as well as its metadata: it may grow after metadata is read.
fn read_stream(reader: impl Read, maximum: usize) -> Result<Vec<u8>> {
    let probe = u64::try_from(maximum)?
        .checked_add(1)
        .ok_or("storage limit overflow")?;
    let mut bytes = Vec::new();
    reader.take(probe).read_to_end(&mut bytes)?;
    size(bytes.len(), maximum, "artifact bytes")?;
    Ok(bytes)
}

pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    // Reject pre-existing FIFOs/devices before open can block. The handle check
    // below remains necessary; this is not protection from hostile path races.
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err("verification artifact must be a regular file".into());
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("verification artifact must be a regular file".into());
    }
    if metadata.len() > u64::try_from(maximum)? {
        return Err(format!(
            "artifact bytes exceed storage limit ({maximum}): {}",
            path.display()
        )
        .into());
    }
    read_stream(file, maximum)
}

pub fn views<'de, D>(
    deserializer: D,
) -> std::result::Result<std::collections::BTreeMap<String, crate::model::View>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, MapAccess, Visitor};
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = std::collections::BTreeMap<String, crate::model::View>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique view keys")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut views = Self::Value::new();
            while let Some(key) = map.next_key()? {
                if views.contains_key(&key) {
                    return Err(A::Error::custom("duplicate view key"));
                }
                views.insert(key, map.next_value()?);
            }
            Ok(views)
        }
    }
    deserializer.deserialize_map(Unique)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "serialized artifact exceeds storage limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn encode(value: &impl Serialize, maximum: usize, pretty: bool) -> Result<Vec<u8>> {
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum,
    };
    if pretty {
        serde_json::to_writer_pretty(&mut output, value)?;
    } else {
        serde_json::to_writer(&mut output, value)?;
    }
    output.write_all(b"\n")?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_and_serialization_limits_include_boundary_and_trailing_newline() {
        assert_eq!(read_stream(&b"1234"[..], 4).unwrap(), b"1234");
        assert!(read_stream(&b"12345"[..], 4).is_err());
        assert_eq!(encode(&123, 4, false).unwrap(), b"123\n");
        assert!(encode(&123, 3, false).is_err());
        assert!(encode(&12345, 4, false).is_err());
        let mut total = usize::MAX;
        assert!(charge(&mut total, 1, usize::MAX, "test").is_err());
        assert_eq!(total, usize::MAX);
    }

    #[test]
    fn sparse_oversized_file_is_rejected_before_reading() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((LIMITS.index as u64) + 1).unwrap();
        assert!(
            read(file.path(), LIMITS.index)
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
    }
}
