use super::*;

#[test]
fn quarantined_model_clears_all_regions_without_instructions() {
    let session = Sha1BackendSession::quarantined_model_for_test();
    let mut owner = Sha1Owner::new();
    owner.chaining_state.fill(0xa5);
    owner.block.fill(0xa5);
    owner.schedule.fill(0xa5);
    owner.message_length.fill(0xa5);
    owner.buffered.fill(0xa5);
    owner.output_staging.fill(0xa5);
    let mut state = AcceleratedSha1 {
        owner,
        session: &session,
        failed: false,
    };
    assert_eq!(state.update(b"ignored"), Err(Sha1BackendError::Quarantined));
    assert!(state.failed);
    assert_eq!(state.owner.chaining_state, [0; 20]);
    assert_eq!(state.owner.block, [0; 64]);
    assert_eq!(state.owner.schedule, [0; 320]);
    assert_eq!(state.owner.message_length, [0; 8]);
    assert_eq!(state.owner.buffered, [0]);
    assert_eq!(state.owner.output_staging, [0; 20]);
    assert_eq!(state.finalize(), Err(Sha1BackendError::Quarantined));
}

fn selected() -> Option<Sha1BackendSession> {
    match Sha1BackendSession::for_compiled_target() {
        Ok(session) => Some(session),
        Err(Sha1BackendError::MissingFeatures) => None,
        Err(error) => {
            let expected = if cfg!(all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)) {
                Sha1BackendError::MissingFeatures
            } else {
                Sha1BackendError::NotAdmitted
            };
            assert_eq!(error, expected);
            None
        }
    }
}

#[test]
fn midstream_failure_clears_every_owned_region_and_latches() {
    let Some(session) = selected() else {
        return;
    };
    let result = AcceleratedSha1::new(&session);
    assert!(result.is_ok());
    let Ok(mut state) = result else {
        return;
    };
    assert_eq!(
        state.update(b"public bytes buffered before quarantine"),
        Ok(())
    );
    session.quarantine_for_test();
    assert_eq!(state.update(b"ignored"), Err(Sha1BackendError::Quarantined));
    assert!(state.failed);
    assert_eq!(state.owner.chaining_state, [0; 20]);
    assert_eq!(state.owner.block, [0; 64]);
    assert_eq!(state.owner.schedule, [0; 320]);
    assert_eq!(state.owner.message_length, [0; 8]);
    assert_eq!(state.owner.buffered, [0]);
    assert_eq!(state.owner.output_staging, [0; 20]);
    assert_eq!(state.update(&[]), Err(Sha1BackendError::Quarantined));
    assert_eq!(state.finalize(), Err(Sha1BackendError::Quarantined));
}

#[test]
fn length_failure_preserves_state_and_finalization_checks_health() {
    let Some(session) = selected() else {
        return;
    };
    let result = AcceleratedSha1::new(&session);
    assert!(result.is_ok());
    let Ok(mut state) = result else {
        return;
    };
    state.owner.message_length = (u64::MAX - 7).to_be_bytes();
    let before = state.owner.chaining_state;
    assert_eq!(state.update(&[1]), Err(Sha1BackendError::MessageTooLong));
    assert_eq!(state.owner.chaining_state, before);
    assert_eq!(state.message_bits(), u64::MAX - 7);
    assert_eq!(state.owner.block, [0; 64]);
    assert!(!state.failed);
    session.quarantine_for_test();
    assert_eq!(state.finalize(), Err(Sha1BackendError::Quarantined));
}
