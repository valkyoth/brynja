"""Public scoped SHA-2 lifecycle tests, without access to private owner bytes."""
RUST = r'''
use super::{Owner, checked, declassify, ensure};
use brynja_hash_sha2::{self as portable, BitString, Sha512TBits, hardened_execution::{self as api, in_place as scope}};
use std::error::Error;

macro_rules! recycle {
    ($workspace:ident, $verify:block) => {{
        for mode in 0..4 {
            let operation = || {
                checked($workspace.with(|mut state| -> Result<(),Box<dyn Error>> {
                    checked(state.update(b"abandoned synthetic state"))?;
                    match mode {
                        0 => state.cancel(),
                        1 => drop(state),
                        2 => std::mem::forget(state),
                        _ => { std::mem::forget(state); std::panic::resume_unwind(Box::new(())); }
                    }
                    Ok(())
                }))?
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
            if mode == 3 { ensure(result.is_err())?; } else { result.map_err(|_| "unexpected unwind")??; }
            $verify
        }
    }};
}

macro_rules! named {
    ($workspace:ident, $hash:ident, $wide:expr, $size:literal, $mode:expr) => {{
        let owner = Owner::new($mode,$wide)?;
        let mut w = checked(scope::$workspace::new(owner.execution()?))?;
        let expected = checked(portable::$hash(b"abc"))?;
        let mut out = [0xa5;$size];
        for width in 0..=65 {
            if width == $size { continue; }
            let mut wrong = vec![0xa5;width];
            for tail in [false,true] {
                let bits = checked(BitString::new(&[0x80],1))?;
                let result = checked(w.with(|state| if tail {state.finalize_bits_secret(bits,&mut wrong)} else {state.finalize_secret(&mut wrong)}))?;
                ensure(matches!(result,Err(api::Error::OutputLength)))?; drop(result);
                ensure(wrong.iter().all(|b| *b == 0))?;
                wrong.fill(0xa5);
                let result = checked(w.with(|state| if tail {state.finalize_bits_public(bits,&mut wrong,declassify())}
                                                           else {state.finalize_public(&mut wrong,declassify())}))?;
                ensure(matches!(result,Err(api::Error::OutputLength)))?;
                ensure(wrong.iter().all(|b| *b == 0xa5))?;
            }
        }
        recycle!(w, {
            let result = checked(w.with(|mut state| -> Result<_,Box<dyn Error>> {
                checked(state.update(b"abc"))?; checked(state.finalize_secret(&mut out))
            }))??;
            ensure(result.digest.expose() == expected.as_bytes())?; drop(result); ensure(out == [0;$size])?;
        });
        let result = checked(w.with(|mut state| -> Result<_,Box<dyn Error>> {
            checked(state.update(b"abc"))?; checked(state.finalize_secret(&mut out))
        }))??;
        ensure(result.digest.expose() == expected.as_bytes())?; drop(result); ensure(out == [0;$size])?;
        let accelerated = !matches!(w.route(),api::Route::Portable);
        if accelerated {
            for public in [false,true] { for tail in [false,true] { for update in [false,true] {
                let owner = Owner::new($mode,$wide)?;
                let mut w = checked(scope::$workspace::new(owner.execution()?))?;
                out.fill(0xa5);
                checked(w.with(|mut state| -> Result<(),Box<dyn Error>> {
                    checked(state.update(b"revoked synthetic state"))?; owner.quarantine();
                    if update { ensure(state.update(&[]).is_err())?; ensure(state.update(b"retry").is_err())?; }
                    let bits = checked(BitString::new(&[0x80],1))?;
                    if public {
                        let result = if tail {state.finalize_bits_public(bits,&mut out,declassify())} else {state.finalize_public(&mut out,declassify())};
                        ensure(result.is_err())?;
                    } else {
                        let result = if tail {state.finalize_bits_secret(bits,&mut out)} else {state.finalize_secret(&mut out)};
                        ensure(result.is_err())?;
                    }
                    Ok(())
                }))??;
                ensure(out == [if public {0xa5} else {0};$size])?;
                let mut called = false; out.fill(0xa5);
                ensure(w.with(|_| {called = true; out.fill(0);}).is_err())?;
                ensure(!called && out == [0xa5;$size])?;
            } } }
        }
        usize::from(accelerated)
    }};
}

fn general(mode: &str) -> Result<usize,Box<dyn Error>> {
    let mut revoked = 0;
    for t in [1,9,224,256,511] {
        let p = checked(Sha512TBits::new(t))?;
        let owner = Owner::new(mode,true)?;
        let mut w = checked(scope::Sha512TWorkspace::new(p,owner.execution()?))?;
        let mut out = vec![0xa5;p.output_bytes()];
        for width in 0..=65 {
            if width == p.output_bytes() {continue;}
            let mut wrong = vec![0xa5;width];
            for tail in [false,true] {
                wrong.fill(0xa5); let bits = checked(BitString::new(&[0x80],1))?;
                let result = checked(w.with(|state| if tail {state.finalize_bits_secret(bits,&mut wrong)} else {state.finalize_secret(&mut wrong)}))?;
                ensure(matches!(result,Err(api::Error::OutputLength)))?; drop(result);
                ensure(wrong.iter().all(|b| *b==0))?;
            }
        }
        let expected = checked(portable::sha512_t(p,b"abc"))?;
        recycle!(w, {
            let result = checked(w.with(|mut state| -> Result<_,Box<dyn Error>> {
                checked(state.update(b"abc"))?; checked(state.finalize_secret(&mut out))
            }))??;
            ensure(result.digest.parameter()==p && result.digest.as_bytes()==expected.as_bytes())?;
            drop(result); ensure(out.iter().all(|b| *b==0))?;
        });
        let result = checked(w.with(|mut state| -> Result<_,Box<dyn Error>> {
            checked(state.update(b"abc"))?; checked(state.finalize_secret(&mut out))
        }))??;
        ensure(result.digest.parameter()==p && result.digest.as_bytes()==expected.as_bytes())?;
        drop(result); ensure(out.iter().all(|b| *b==0))?;
        if !matches!(w.route(),api::Route::Portable) {
            revoked += 1;
            for public in [false,true] { for tail in [false,true] { for update in [false,true] {
                let owner = Owner::new(mode,true)?;
                let mut w = checked(scope::Sha512TWorkspace::new(p,owner.execution()?))?;
                out.fill(0xa5);
                checked(w.with(|mut state| -> Result<(),Box<dyn Error>> {
                    checked(state.update(b"revoked synthetic state"))?; owner.quarantine();
                    if update {ensure(state.update(&[]).is_err())?; ensure(state.update(b"retry").is_err())?;}
                    let bits = checked(BitString::new(&[0x80],1))?;
                    if public {
                        let result = if tail {state.finalize_bits_public(bits,declassify())} else {state.finalize_public(declassify())};
                        ensure(result.is_err())?;
                    } else {
                        let result = if tail {state.finalize_bits_secret(bits,&mut out)} else {state.finalize_secret(&mut out)};
                        ensure(result.is_err())?;
                    }
                    Ok(())
                }))??;
                ensure(out.iter().all(|b| *b==if public {0xa5} else {0}))?;
                let mut called = false;
                ensure(w.with(|_| called=true).is_err())?; ensure(!called)?;
            } } }
        }
    }
    Ok(revoked)
}

pub(super) fn run(mode: &str, narrow_only: bool) -> Result<usize,Box<dyn Error>> {
    let wide_mode = if narrow_only {"portable"} else {mode};
    let mut revoked = named!(Sha224Workspace,sha224,false,28,mode);
    revoked += named!(Sha256Workspace,sha256,false,32,mode);
    revoked += named!(Sha384Workspace,sha384,true,48,wide_mode);
    revoked += named!(Sha512Workspace,sha512,true,64,wide_mode);
    revoked += named!(Sha512_224Workspace,sha512_224,true,28,wide_mode);
    revoked += named!(Sha512_256Workspace,sha512_256,true,32,wide_mode);
    revoked += general(wide_mode)?;
    let narrow = Owner::new(mode,false)?;
    let wide = Owner::new(wide_mode,true)?;
    if !matches!(narrow.execution()?.route(),api::Route::Portable) {
        ensure(scope::Sha512Workspace::new(narrow.execution()?).is_err())?;
        ensure(scope::Sha512TWorkspace::new(checked(Sha512TBits::new(9))?,narrow.execution()?).is_err())?;
    }
    if !matches!(wide.execution()?.route(),api::Route::Portable) {
        ensure(scope::Sha256Workspace::new(wide.execution()?).is_err())?;
    }
    Ok(revoked)
}
'''
