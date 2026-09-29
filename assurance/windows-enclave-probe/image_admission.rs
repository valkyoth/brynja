//! Bounded PE64 admission for the separately reviewed Windows deployment image.
//! Public file metadata only. This is not a signature implementation or attestation.
use brynja_hash_sha2::sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub family: [u8; 16],
    pub image: [u8; 16],
    pub version: u32,
    pub security: u32,
    pub policy: u32,
    pub size: u64,
    pub threads: u32,
    pub minimum_import_security: [u32; 2],
}

pub struct Policy {
    pub digest: [u8; 32],
    pub identity: Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Format,
    Imports,
    Identity,
    Digest,
}
type Result<T> = core::result::Result<T, Error>;

fn bytes(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..p.checked_add(n).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)
}
fn u16_at(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(b, p, 2)?.try_into().map_err(|_| Error::Bounds)?,
    ))
}
fn u32_at(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(b, p, 4)?.try_into().map_err(|_| Error::Bounds)?,
    ))
}
fn u64_at(b: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(b, p, 8)?.try_into().map_err(|_| Error::Bounds)?,
    ))
}
fn need(value: bool, error: Error) -> Result<()> {
    if value { Ok(()) } else { Err(error) }
}

struct Pe<'a> {
    b: &'a [u8],
    sections: usize,
    count: usize,
    optional: usize,
    base: u64,
}
impl<'a> Pe<'a> {
    fn new(b: &'a [u8], unsigned: bool) -> Result<Self> {
        need((512..=16 * 1024 * 1024).contains(&b.len()), Error::Bounds)?;
        need(bytes(b, 0, 2)? == b"MZ", Error::Format)?;
        let p = u32_at(b, 60)? as usize;
        need(p >= 64 && bytes(b, p, 4)? == b"PE\0\0", Error::Format)?;
        let o = p.checked_add(24).ok_or(Error::Bounds)?;
        bytes(b, o, 240)?;
        need(
            u16_at(b, p + 4)? == 0x8664
                && u16_at(b, p + 20)? == 240
                && u16_at(b, o)? == 0x20b
                && u16_at(b, p + 22)? & 0x2022 == 0x2022,
            Error::Format,
        )?;
        need(u32_at(b, o + 108)? == 16, Error::Format)?;
        let flags = u16_at(b, o + 70)?;
        need(flags & 0x41e0 == 0x41e0, Error::Format)?; // CFG, NX, integrity, ASLR, high entropy.
        let count = u16_at(b, p + 6)? as usize;
        need((1..=32).contains(&count), Error::Bounds)?;
        let sections = o + 240;
        bytes(b, sections, count * 40)?;
        let header = u32_at(b, o + 60)? as usize;
        need(
            header >= sections + count * 40 && header <= b.len(),
            Error::Format,
        )?;
        let image_size = u32_at(b, o + 56)? as u64;
        for i in 0..count {
            let s = sections + i * 40;
            let v = u32_at(b, s + 12)? as u64;
            let vs = u32_at(b, s + 8)? as u64;
            let raw = u32_at(b, s + 20)? as u64;
            let size = u32_at(b, s + 16)? as u64;
            let span = vs.max(size);
            need(
                span > 0
                    && v >= header as u64
                    && v + span <= image_size
                    && (size == 0 || (raw >= header as u64 && raw + size <= b.len() as u64)),
                Error::Bounds,
            )?;
            need(u32_at(b, s + 36)? & 0xa0000000 != 0xa0000000, Error::Format)?;
            for j in 0..i {
                let t = sections + j * 40;
                let tv = u32_at(b, t + 12)? as u64;
                let ts = (u32_at(b, t + 8)? as u64).max(u32_at(b, t + 16)? as u64);
                let tr = u32_at(b, t + 20)? as u64;
                let tn = u32_at(b, t + 16)? as u64;
                need(v + span <= tv || tv + ts <= v, Error::Format)?;
                need(
                    size == 0 || tn == 0 || raw + size <= tr || tr + tn <= raw,
                    Error::Format,
                )?;
            }
        }
        let pe = Self {
            b,
            sections,
            count,
            optional: o,
            base: u64_at(b, o + 24)?,
        };
        need(pe.base != 0, Error::Format)?;
        // No delay-loading, bound imports, CLR or TLS initialization in this contract.
        for index in [9, 11, 13, 14] {
            need(pe.dir(index)? == (0, 0), Error::Imports)?;
        }
        // An embedded PKCS#7 certificate is required structurally; Windows verifies it.
        let (cert, size) = pe.dir(4)?;
        if unsigned && cert == 0 && size == 0 {
            return Ok(pe);
        }
        need(
            cert % 8 == 0 && size >= 8 && cert as u64 + size as u64 == b.len() as u64,
            Error::Format,
        )?;
        let c = cert as usize;
        bytes(b, c, size as usize)?;
        let length = u32_at(b, c)? as usize;
        need(
            length >= 8
                && length <= size as usize
                && (length + 7) & !7 == size as usize
                && u16_at(b, c + 4)? == 0x200
                && u16_at(b, c + 6)? == 2,
            Error::Format,
        )?;
        need(
            bytes(b, c + length, size as usize - length)?
                .iter()
                .all(|x| *x == 0),
            Error::Format,
        )?;
        for i in 0..count {
            let s = sections + i * 40;
            need(
                u32_at(b, s + 20)? as u64 + u32_at(b, s + 16)? as u64 <= cert as u64,
                Error::Format,
            )?;
        }
        Ok(pe)
    }
    fn dir(&self, index: usize) -> Result<(u32, u32)> {
        let p = self.optional + 112 + index * 8;
        Ok((u32_at(self.b, p)?, u32_at(self.b, p + 4)?))
    }
    fn offset(&self, rva: u32, length: usize) -> Result<usize> {
        let end = (rva as u64)
            .checked_add(length as u64)
            .ok_or(Error::Bounds)?;
        for i in 0..self.count {
            let s = self.sections + i * 40;
            let v = u32_at(self.b, s + 12)? as u64;
            let span = (u32_at(self.b, s + 8)? as u64).min(u32_at(self.b, s + 16)? as u64);
            if rva as u64 >= v && end <= v + span {
                let p = (u32_at(self.b, s + 20)? as u64 + rva as u64 - v) as usize;
                bytes(self.b, p, length)?;
                return Ok(p);
            }
        }
        Err(Error::Bounds)
    }
    fn system_name(&self, rva: u32) -> Result<usize> {
        for (index, name) in [b"ucrtbase_enclave.dll\0".as_slice(), b"vertdll.dll\0"]
            .iter()
            .enumerate()
        {
            if let Ok(p) = self.offset(rva, name.len()) {
                if bytes(self.b, p, name.len())? == *name {
                    return Ok(index);
                }
            }
        }
        Err(Error::Imports)
    }
    fn imports(&self) -> Result<[u32; 2]> {
        let (rva, size) = self.dir(1)?;
        need(size == 60, Error::Imports)?;
        let p = self.offset(rva, 60)?;
        need(
            bytes(self.b, p + 40, 20)?.iter().all(|x| *x == 0),
            Error::Imports,
        )?;
        let mut names = [false; 2];
        for i in 0..2 {
            let t = p + i * 20;
            need(
                u32_at(self.b, t + 4)? == 0 && u32_at(self.b, t + 8)? == 0,
                Error::Imports,
            )?;
            let name = self.system_name(u32_at(self.b, t + 12)?)?;
            need(!names[name], Error::Imports)?;
            names[name] = true;
            let lookup = u32_at(self.b, t)?;
            let address = u32_at(self.b, t + 16)?;
            need(lookup != 0 && address != 0, Error::Imports)?;
            let mut terminated = false;
            for j in 0..=512u32 {
                let delta = j * 8;
                let l = self.offset(lookup.checked_add(delta).ok_or(Error::Bounds)?, 8)?;
                let a = self.offset(address.checked_add(delta).ok_or(Error::Bounds)?, 8)?;
                let entry = u64_at(self.b, l)?;
                need(entry == u64_at(self.b, a)?, Error::Imports)?;
                if entry == 0 {
                    need(j > 0, Error::Imports)?;
                    terminated = true;
                    break;
                }
                need(entry <= u32::MAX as u64, Error::Imports)?; // named imports only
                let symbol = entry as u32;
                self.offset(symbol, 3)?;
                let mut ended = false;
                for k in 2..=258 {
                    let at = self.offset(symbol.checked_add(k).ok_or(Error::Bounds)?, 1)?;
                    let ch = self.b[at];
                    if ch == 0 {
                        need(k > 2, Error::Imports)?;
                        ended = true;
                        break;
                    }
                    need((33..=126).contains(&ch), Error::Imports)?;
                }
                need(ended, Error::Imports)?;
            }
            need(terminated, Error::Imports)?;
        }
        need(names == [true, true], Error::Imports)?;
        let (load_rva, load_size) = self.dir(10)?;
        need((264..=4096).contains(&load_size), Error::Format)?;
        let load = self.offset(load_rva, load_size as usize)?;
        need(u32_at(self.b, load)? == load_size, Error::Format)?;
        let config = u64_at(self.b, load + 248)?
            .checked_sub(self.base)
            .ok_or(Error::Bounds)?;
        let config = u32::try_from(config).map_err(|_| Error::Bounds)?;
        let c = self.offset(config, 80)?;
        need(
            u32_at(self.b, c)? == 80
                && u32_at(self.b, c + 4)? == 76
                && u32_at(self.b, c + 12)? == 2
                && u32_at(self.b, c + 20)? == 80,
            Error::Format,
        )?;
        let table = self.offset(u32_at(self.b, c + 16)?, 160)?;
        let mut seen = [false; 2];
        let mut minimum = [0; 2];
        for i in 0..2 {
            let t = table + i * 80;
            let name = self.system_name(u32_at(self.b, t + 72)?)?;
            need(!seen[name], Error::Imports)?;
            seen[name] = true;
            // Zero AUTHOR identity means Windows-installation component, not any signer.
            need(
                u32_at(self.b, t)? == 2
                    && bytes(self.b, t + 8, 64)?.iter().all(|x| *x == 0)
                    && u32_at(self.b, t + 76)? == 0,
                Error::Imports,
            )?;
            minimum[name] = u32_at(self.b, t + 4)?;
        }
        need(seen == names, Error::Imports)?;
        Ok(minimum)
    }
}

pub fn inspect(b: &[u8]) -> Result<Identity> {
    let pe = Pe::new(b, false)?;
    let minimum_import_security = pe.imports()?;
    let (rva, _) = pe.dir(10)?;
    let load = pe.offset(rva, 264)?;
    let config = u64_at(b, load + 248)?
        .checked_sub(pe.base)
        .ok_or(Error::Bounds)?;
    let c = pe.offset(u32::try_from(config).map_err(|_| Error::Bounds)?, 80)?;
    let identity = Identity {
        family: bytes(b, c + 24, 16)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
        image: bytes(b, c + 40, 16)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
        version: u32_at(b, c + 56)?,
        security: u32_at(b, c + 60)?,
        policy: u32_at(b, c + 8)?,
        size: u64_at(b, c + 64)?,
        threads: u32_at(b, c + 72)?,
        minimum_import_security,
    };
    need(
        matches!(identity.policy, 0 | 2)
            && identity.family != [0; 16]
            && identity.image != [0; 16]
            && identity.version > 0
            && identity.security > 0
            && identity.size == 0x10000000
            && identity.threads == 1
            && u32_at(b, c + 76)? == 1,
        Error::Identity,
    )?;
    Ok(identity)
}

pub fn admit(b: &[u8], policy: &Policy) -> Result<()> {
    need(b.len() <= 16 * 1024 * 1024, Error::Bounds)?;
    let hash = sha256(b).map_err(|_| Error::Digest)?;
    need(hash.as_bytes() == &policy.digest, Error::Digest)?;
    need(inspect(b)? == policy.identity, Error::Identity)
}

/// Offline build transform BEFORE VEIID/signing. Never admits or loads an image.
/// The returned length removes any old certificate; the caller writes a NEW file.
pub fn prepare_windows_imports(b: &mut [u8]) -> Result<usize> {
    let pe = Pe::new(b, true)?;
    let (rva, size) = pe.dir(10)?;
    need(size >= 264, Error::Format)?;
    let load = pe.offset(rva, size as usize)?;
    let config = u64_at(b, load + 248)?
        .checked_sub(pe.base)
        .ok_or(Error::Bounds)?;
    let c = pe.offset(u32::try_from(config).map_err(|_| Error::Bounds)?, 80)?;
    need(
        u32_at(b, c)? == 80 && u32_at(b, c + 12)? == 2 && u32_at(b, c + 20)? == 80,
        Error::Format,
    )?;
    let table = pe.offset(u32_at(b, c + 16)?, 160)?;
    let names = [
        pe.system_name(u32_at(b, table + 72)?)?,
        pe.system_name(u32_at(b, table + 152)?)?,
    ];
    need(names[0] != names[1], Error::Imports)?;
    let optional = pe.optional;
    let (cert, _) = pe.dir(4)?;
    let length = if cert == 0 { b.len() } else { cert as usize };
    for i in 0..2 {
        let t = table + i * 80;
        b[t..t + 4].copy_from_slice(&2u32.to_le_bytes());
        b[t + 8..t + 72].fill(0);
        b[t + 76..t + 80].fill(0);
    }
    // All normal import semantics and new identity constraints must still validate.
    Pe::new(b, true)?.imports()?;
    b[optional + 64..optional + 68].fill(0); // PE checksum regenerated by signing tools.
    b[optional + 144..optional + 152].fill(0); // Security directory: signature invalidated.
    Ok(length)
}
