"""Consumer-observable scoped lifecycle checks (not private-storage inspection)."""
RUST = r'''
#[test]
fn scoped_lifecycle_and_output_failures() -> Result<(), String> {
    let owner = authority()?.ok_or("missing required authority")?;
    let mut fixed = cpu::in_place::Sha3_256Workspace::new(session(&owner)?).map_err(error)?;
    let mut secret = [0xa5; 31];
    let mut public = [0xa5; 31];
    fixed.with(|state| { assert!(state.finalize_secret(&mut secret).is_err()); }).map_err(error)?;
    assert_eq!(secret,[0;31]);
    fixed.with(|state| { assert!(state.finalize_public(&mut public,cpu::Sha3PublicDeclassification::acknowledge()).is_err()); }).map_err(error)?;
    assert_eq!(public,[0xa5;31]);
    macro_rules! check { ($workspace:ident, $method:ident $(, $arg:expr)*) => {{
        let mut workspace = cpu::in_place::$workspace::new(session(&owner)?).map_err(error)?;
        let mut output = [0xa5; 201];
        let mut scratch = [0x93; 200];
        workspace.$method($($arg,)* |mut state| -> Result<(), String> {
            state.update(b"synthetic fixture").map_err(error)?;
            let mut reader = state.finalize_xof().map_err(error)?;
            assert!(reader.squeeze_public_with_scratch(&mut output,&mut scratch,cpu::Sha3PublicDeclassification::acknowledge()).is_err());
            assert_eq!(output,[0xa5;201]); assert_eq!(scratch,[0;200]);
            assert!(reader.squeeze_secret(&mut output).is_err()); assert_eq!(output,[0;201]);
            Ok(())
        }).map_err(error)??;
        workspace.$method($($arg,)* |state| -> Result<(), String> {
            output.fill(0xa5);
            let reader = state.finalize_xof().map_err(error)?;
            assert!(reader.squeeze_final_bits_secret(&mut output,9).is_err());
            assert_eq!(output,[0;201]); Ok(())
        }).map_err(error)??;
        workspace.$method($($arg,)* |mut state| -> Result<(), String> {
            state.update(b"forgotten synthetic state").map_err(error)?;
            std::mem::forget(state.finalize_xof().map_err(error)?); Ok(())
        }).map_err(error)??;
        let mut expected = [0;201];
        workspace.$method($($arg,)* |state| -> Result<(), String> {
            let mut reader = state.finalize_xof().map_err(error)?;
            let value = reader.squeeze_secret(&mut output).map_err(error)?;
            expected.copy_from_slice(value.expose()); Ok(())
        }).map_err(error)??;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workspace.$method($($arg,)* |mut state| {
                state.update(b"unwinding synthetic state").unwrap(); panic!("synthetic scoped unwind");
            }).unwrap();
        }));
        assert!(unwind.is_err());
        workspace.$method($($arg,)* |state| -> Result<(), String> {
            let mut reader = state.finalize_xof().map_err(error)?;
            assert_eq!(reader.squeeze_secret(&mut output).map_err(error)?.expose(), expected);
            Ok(())
        }).map_err(error)??;
        assert_eq!(output,[0;201]);
    }}; }
    check!(Shake128Workspace,with);
    check!(Shake256Workspace,with);
    check!(Cshake128Workspace,with,b"N",b"S");
    check!(Cshake256Workspace,with,b"N",b"S");
    Ok(())
}
#[test]
fn scoped_revocation_is_terminal() -> Result<(), String> {
    let owner = authority()?.ok_or("missing required authority")?;
    let mut workspace = cpu::in_place::Shake256Workspace::new(session(&owner)?).map_err(error)?;
    let mut output = [0xa5;32];
    let mut scratch = [0x93;32];
    workspace.with(|state| -> Result<(), String> {
        let mut reader = state.finalize_xof().map_err(error)?;
        owner.quarantine();
        assert!(reader.squeeze_public_with_scratch(&mut output,&mut scratch,cpu::Sha3PublicDeclassification::acknowledge()).is_err());
        assert_eq!(output,[0xa5;32]); assert_eq!(scratch,[0;32]);
        assert!(reader.squeeze_secret(&mut output).is_err()); assert_eq!(output,[0;32]); Ok(())
    }).map_err(error)??;
    let mut called = false;
    assert!(workspace.with(|_| called=true).is_err()); assert!(!called);
    Ok(())
}
'''
