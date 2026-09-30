//! Bounded public-image parsing. Signature enforcement is a separate OS step.
use super::{Error, ImagePolicy};
type Result<T> = core::result::Result<T, Error>;
fn need(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::Image) }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Image)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Image)
}
fn sub(a: usize, b: usize) -> Result<usize> {
    a.checked_sub(b).ok_or(Error::Image)
}
fn bytes(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..add(p, n)?).ok_or(Error::Image)
}
fn u16_at(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(b, p, 2)?.try_into().map_err(|_| Error::Image)?,
    ))
}
fn u32_at(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(b, p, 4)?.try_into().map_err(|_| Error::Image)?,
    ))
}
fn u64_at(b: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(b, p, 8)?.try_into().map_err(|_| Error::Image)?,
    ))
}
fn at(b: &[u8], p: usize) -> Result<usize> {
    usize::try_from(u32_at(b, p)?).map_err(|_| Error::Image)
}
struct Pe<'a> {
    b: &'a [u8],
    o: usize,
    sections: usize,
    count: usize,
    base: u64,
}
impl<'a> Pe<'a> {
    fn word(&self, p: usize, delta: usize) -> Result<usize> {
        at(self.b, add(p, delta)?)
    }
    fn new(b: &'a [u8]) -> Result<Self> {
        need((512..=16777216).contains(&b.len()) && bytes(b, 0, 2)? == b"MZ")?;
        let p = at(b, 60)?;
        need(p >= 64 && bytes(b, p, 4)? == b"PE\0\0")?;
        let o = add(p, 24)?;
        bytes(b, o, 240)?;
        need(
            u16_at(b, add(p, 4)?)? == 0x8664
                && u16_at(b, add(p, 20)?)? == 240
                && u16_at(b, o)? == 0x20b
                && u16_at(b, add(p, 22)?)? & 0x2022 == 0x2022
                && u32_at(b, add(o, 108)?)? == 16
                && u16_at(b, add(o, 70)?)? & 0x41e0 == 0x41e0,
        )?;
        let count = usize::from(u16_at(b, add(p, 6)?)?);
        need((1..=32).contains(&count))?;
        let sections = add(o, 240)?;
        let pe = Self {
            b,
            o,
            sections,
            count,
            base: u64_at(b, add(o, 24)?)?,
        };
        let header = pe.word(o, 60)?;
        let image = pe.word(o, 56)?;
        need(pe.base != 0 && header >= add(sections, mul(count, 40)?)? && header <= b.len())?;
        for i in 0..count {
            let s = pe.section(i)?;
            let (v, span, raw, size) = pe.spans(s)?;
            need(
                span > 0
                    && v >= header
                    && add(v, span)? <= image
                    && (size == 0 || (raw >= header && add(raw, size)? <= b.len()))
                    && pe.word(s, 36)? & 0xa0000000 != 0xa0000000,
            )?;
            for j in 0..i {
                let (tv, ts, tr, tn) = pe.spans(pe.section(j)?)?;
                need(add(v, span)? <= tv || add(tv, ts)? <= v)?;
                need(size == 0 || tn == 0 || add(raw, size)? <= tr || add(tr, tn)? <= raw)?;
            }
        }
        for i in [9, 11, 13, 14] {
            need(pe.dir(i)? == (0, 0))?;
        }
        let (cert, size) = pe.dir(4)?;
        need(cert % 8 == 0 && size >= 8 && add(cert, size)? == b.len())?;
        let length = at(b, cert)?;
        need(
            length >= 8
                && length <= size
                && add(length, 7)? & !7 == size
                && u16_at(b, add(cert, 4)?)? == 0x200
                && u16_at(b, add(cert, 6)?)? == 2,
        )?;
        need(
            bytes(b, add(cert, length)?, sub(size, length)?)?
                .iter()
                .all(|&x| x == 0),
        )?;
        for i in 0..count {
            let s = pe.section(i)?;
            need(add(pe.word(s, 20)?, pe.word(s, 16)?)? <= cert)?;
        }
        Ok(pe)
    }
    fn section(&self, i: usize) -> Result<usize> {
        add(self.sections, mul(i, 40)?)
    }
    fn spans(&self, s: usize) -> Result<(usize, usize, usize, usize)> {
        Ok((
            self.word(s, 12)?,
            self.word(s, 8)?.max(self.word(s, 16)?),
            self.word(s, 20)?,
            self.word(s, 16)?,
        ))
    }
    fn dir(&self, i: usize) -> Result<(usize, usize)> {
        let p = add(add(self.o, 112)?, mul(i, 8)?)?;
        Ok((at(self.b, p)?, self.word(p, 4)?))
    }
    fn offset(&self, rva: usize, length: usize) -> Result<usize> {
        let end = add(rva, length)?;
        for i in 0..self.count {
            let s = self.section(i)?;
            let v = self.word(s, 12)?;
            let span = self.word(s, 8)?.min(self.word(s, 16)?);
            if rva >= v && end <= add(v, span)? {
                let p = add(self.word(s, 20)?, sub(rva, v)?)?;
                bytes(self.b, p, length)?;
                return Ok(p);
            }
        }
        Err(Error::Image)
    }
    fn name(&self, rva: usize) -> Result<usize> {
        for (i, name) in [b"ucrtbase_enclave.dll\0".as_slice(), b"vertdll.dll\0"]
            .iter()
            .enumerate()
        {
            if let Ok(p) = self.offset(rva, name.len())
                && bytes(self.b, p, name.len())? == *name
            {
                return Ok(i);
            }
        }
        Err(Error::Image)
    }
    fn imports(&self) -> Result<(usize, [u32; 2])> {
        let (rva, size) = self.dir(1)?;
        need(size == 60)?;
        let p = self.offset(rva, size)?;
        need(bytes(self.b, add(p, 40)?, 20)?.iter().all(|&x| x == 0))?;
        let mut names = [false; 2];
        for i in 0..2 {
            let t = add(p, mul(i, 20)?)?;
            need(self.word(t, 4)? == 0 && self.word(t, 8)? == 0)?;
            let name = self.name(self.word(t, 12)?)?;
            let seen = names.get_mut(name).ok_or(Error::Image)?;
            need(!*seen)?;
            *seen = true;
            let lookup = at(self.b, t)?;
            let address = self.word(t, 16)?;
            need(lookup != 0 && address != 0)?;
            let mut terminated = false;
            for j in 0..=512 {
                let delta = mul(j, 8)?;
                let l = self.offset(add(lookup, delta)?, 8)?;
                let a = self.offset(add(address, delta)?, 8)?;
                let entry = u64_at(self.b, l)?;
                need(entry == u64_at(self.b, a)?)?;
                if entry == 0 {
                    need(j > 0)?;
                    terminated = true;
                    break;
                }
                let symbol = usize::try_from(u32::try_from(entry).map_err(|_| Error::Image)?)
                    .map_err(|_| Error::Image)?;
                self.offset(symbol, 3)?;
                let mut ended = false;
                for k in 2..=258 {
                    let at = self.offset(add(symbol, k)?, 1)?;
                    let ch = *self.b.get(at).ok_or(Error::Image)?;
                    if ch == 0 {
                        need(k > 2)?;
                        ended = true;
                        break;
                    }
                    need((33..=126).contains(&ch))?;
                }
                need(ended)?;
            }
            need(terminated)?;
        }
        need(names == [true, true])?;
        let (load, size) = self.dir(10)?;
        need((264..=4096).contains(&size))?;
        let load = self.offset(load, size)?;
        need(at(self.b, load)? == size)?;
        let config = u64_at(self.b, add(load, 248)?)?
            .checked_sub(self.base)
            .ok_or(Error::Image)?;
        let c = self.offset(
            usize::try_from(u32::try_from(config).map_err(|_| Error::Image)?)
                .map_err(|_| Error::Image)?,
            80,
        )?;
        need(
            at(self.b, c)? == 80
                && self.word(c, 4)? == 76
                && self.word(c, 12)? == 2
                && self.word(c, 20)? == 80,
        )?;
        let table = self.offset(self.word(c, 16)?, 160)?;
        let mut names = [false; 2];
        let mut minimum = [0; 2];
        for i in 0..2 {
            let t = add(table, mul(i, 80)?)?;
            let n = self.name(self.word(t, 72)?)?;
            let seen = names.get_mut(n).ok_or(Error::Image)?;
            need(!*seen)?;
            *seen = true;
            need(
                at(self.b, t)? == 2
                    && bytes(self.b, add(t, 8)?, 64)?.iter().all(|&x| x == 0)
                    && self.word(t, 76)? == 0,
            )?;
            *minimum.get_mut(n).ok_or(Error::Image)? = u32_at(self.b, add(t, 4)?)?;
        }
        need(names == [true, true])?;
        Ok((c, minimum))
    }
}
pub(super) fn admit(b: &[u8], policy: &ImagePolicy) -> Result<()> {
    need(policy.valid() && b.len() <= 16777216)?;
    let hash = brynja_hash_sha2::sha256(b).map_err(|_| Error::Image)?;
    need(hash.as_bytes() == &policy.digest)?;
    let pe = Pe::new(b)?;
    let (c, minimum) = pe.imports()?;
    need(
        bytes(b, add(c, 24)?, 16)? == policy.family
            && bytes(b, add(c, 40)?, 16)? == policy.image
            && u32_at(b, add(c, 56)?)? == policy.version
            && u32_at(b, add(c, 60)?)? == policy.security
            && u32_at(b, add(c, 8)?)? == 0
            && u64_at(b, add(c, 64)?)? == 0x10000000
            && u32_at(b, add(c, 72)?)? == 1
            && u32_at(b, add(c, 76)?)? == 1
            && minimum == policy.minimum_import_security,
    )
}

#[cfg(test)]
mod tests;
