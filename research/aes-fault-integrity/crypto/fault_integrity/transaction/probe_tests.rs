//! Single-call native debugger fixture. Test artifact only, NOT qualification.
extern crate std;
use super::*;

// A stable fixture call boundary for observing the otherwise unchanged private
// transaction. This does not add a barrier or guard to the transaction itself.
#[inline(never)]
fn public_call(owner: &mut Lifecycle, output: &mut [u8; 16]) -> Result<(), Error> {
    owner.public(
        output,
        PublicCiphertext::acknowledge(),
        |p, s, completion| {
            p.fill(0x42);
            s.fill(0x42);
            completion.mark_complete();
            Ok(())
        },
    )
}

#[test]
fn native_public_transaction_probe() {
    std::println!(
        "BRYNJA_TRANSACTION_EVIDENCE_CFG={}",
        cfg!(brynja_fault_evidence)
    );
    let mut owner = Lifecycle::new();
    let mut output = [0x91; 16];
    let result = public_call(&mut owner, &mut output);
    // The external experiment runner MUST require baseline success or the
    // specified injected rejection, not treat either as unconditional evidence.
    if result.is_ok() {
        assert_eq!(output, [0x42; 16]);
        assert_eq!(owner.word, HEALTHY);
        std::println!("BRYNJA_TRANSACTION_ACCEPTED");
    } else {
        assert_eq!(output, [0x91; 16]);
        assert_eq!(owner.word, TERMINAL);
        let mut calls = 0usize;
        assert!(
            owner
                .public(&mut output, PublicCiphertext::acknowledge(), |_, _, _| {
                    calls = calls.wrapping_add(1);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(calls, 0);
        assert_eq!(output, [0x91; 16]);
        std::println!("BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED");
    }
}

// Return the real private secret owner so the test can inspect the bytes before
// its ordinary clearing drop. No diagnostic copy stands in for that owner.
#[inline(never)]
fn secret_call<'out>(
    owner: &mut Lifecycle,
    output: &'out mut [u8; 16],
) -> Result<SecretBlock<'out>, Error> {
    owner.secret(output, |p, s, completion| {
        p.fill(0x42);
        s.fill(0x42);
        completion.mark_complete();
        Ok(())
    })
}

#[test]
fn native_secret_transaction_probe() {
    std::println!(
        "BRYNJA_TRANSACTION_EVIDENCE_CFG={}",
        cfg!(brynja_fault_evidence)
    );
    let mut owner = Lifecycle::new();
    let mut output = [0x91; 16];
    let accepted = match secret_call(&mut owner, &mut output) {
        Ok(block) => {
            assert_eq!(block.expose(), &[0x42; 16]);
            assert_eq!(owner.word, HEALTHY);
            drop(block);
            true
        }
        Err(_) => {
            assert_eq!(owner.word, TERMINAL);
            false
        }
    };
    assert_eq!(output, [0; 16]);
    if accepted {
        std::println!("BRYNJA_SECRET_ACCEPTED_CLEARED");
    } else {
        let mut calls = 0usize;
        // Even rejection at entry must clear newly admitted caller storage.
        output.fill(0x91);
        assert!(
            owner
                .secret(&mut output, |_, _, _| {
                    calls = calls.wrapping_add(1);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(calls, 0);
        assert_eq!(output, [0; 16]);
        std::println!("BRYNJA_SECRET_REJECTED_CLEARED_RETIRED");
    }
}
