//! Exhaustive caller-owned workspace and arena behavior.

use brynja_core::{
    Arena, ArenaDomain, ArenaError, ArenaKind, Workspace, WorkspaceArenas, WorkspaceError,
    WorkspaceLayout, WorkspaceLayoutBuilder,
};
use core::mem::size_of;

fn layout(lengths: [usize; 5]) -> Result<WorkspaceLayout, WorkspaceError> {
    let [secret, plaintext, transcript, certificate, output] = lengths;
    WorkspaceLayout::builder()
        .secret_bytes(secret)?
        .plaintext_bytes(plaintext)?
        .transcript_bytes(transcript)?
        .certificate_bytes(certificate)?
        .output_bytes(output)?
        .build()
}

fn assign(
    builder: WorkspaceLayoutBuilder,
    kind: ArenaKind,
    bytes: usize,
) -> Result<WorkspaceLayoutBuilder, WorkspaceError> {
    match kind {
        ArenaKind::Secret => builder.secret_bytes(bytes),
        ArenaKind::Plaintext => builder.plaintext_bytes(bytes),
        ArenaKind::Transcript => builder.transcript_bytes(bytes),
        ArenaKind::Certificate => builder.certificate_bytes(bytes),
        ArenaKind::Output => builder.output_bytes(bytes),
        _ => Err(WorkspaceError::Incomplete(kind)),
    }
}

fn complete_except(omitted: ArenaKind) -> Result<WorkspaceLayout, WorkspaceError> {
    let mut builder = WorkspaceLayoutBuilder::new();
    for kind in ArenaKind::ALL {
        if kind != omitted {
            builder = assign(builder, kind, 1)?;
        }
    }
    builder.build()
}

fn assert_empty_arena<Domain: ArenaDomain>(arena: &mut Arena<'_, Domain>) {
    assert_eq!(arena.allocate(0).map(|bytes| bytes.len()), Ok(0));
    assert_eq!(arena.used(), 0);
    assert_eq!(arena.high_water(), 0);
    assert_eq!(arena.allocation_count(), 0);
    assert_eq!(arena.remaining(), 0);
}

#[test]
fn exact_partition_has_named_disjoint_storage() {
    let result = layout([2, 3, 4, 5, 6]);
    assert!(result.is_ok());
    let Ok(layout) = result else {
        return;
    };
    let mut storage = [0xa5_u8; 20];
    let origin = storage.as_ptr();
    let result = Workspace::new(&mut storage, layout);
    assert!(result.is_ok());
    let Ok(mut workspace) = result else {
        return;
    };

    let arenas = workspace.arenas_mut();
    let secret = arenas.secret.allocate(2);
    let plaintext = arenas.plaintext.allocate(3);
    let transcript = arenas.transcript.allocate(4);
    let certificate = arenas.certificate.allocate(5);
    let output = arenas.output.allocate(6);
    assert!(secret.is_ok());
    assert!(plaintext.is_ok());
    assert!(transcript.is_ok());
    assert!(certificate.is_ok());
    assert!(output.is_ok());
    let Ok(secret) = secret else { return };
    let Ok(plaintext) = plaintext else { return };
    let Ok(transcript) = transcript else { return };
    let Ok(certificate) = certificate else {
        return;
    };
    let Ok(output) = output else { return };

    assert_eq!(secret.as_ptr(), origin);
    assert_eq!(plaintext.as_ptr(), origin.wrapping_add(2));
    assert_eq!(transcript.as_ptr(), origin.wrapping_add(5));
    assert_eq!(certificate.as_ptr(), origin.wrapping_add(9));
    assert_eq!(output.as_ptr(), origin.wrapping_add(14));
    secret.fill(1);
    plaintext.fill(2);
    transcript.fill(3);
    certificate.fill(4);
    output.fill(5);
    drop(workspace);

    assert_eq!(
        storage,
        [1, 1, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5]
    );
}

#[test]
fn named_getters_preserve_kind_and_capacity() {
    let result = layout([1, 2, 3, 4, 5]);
    let Ok(layout) = result else {
        return;
    };
    assert_eq!(layout.total_bytes(), 15);
    for (kind, bytes) in ArenaKind::ALL.into_iter().zip([1, 2, 3, 4, 5]) {
        assert_eq!(layout.arena_bytes(kind), bytes);
    }

    let mut storage = [0_u8; 15];
    let result = Workspace::new(&mut storage, layout);
    let Ok(mut workspace) = result else {
        return;
    };
    assert_eq!(workspace.secret().kind(), ArenaKind::Secret);
    assert_eq!(workspace.secret().capacity(), 1);
    assert_eq!(workspace.plaintext().kind(), ArenaKind::Plaintext);
    assert_eq!(workspace.plaintext().capacity(), 2);
    assert_eq!(workspace.transcript().kind(), ArenaKind::Transcript);
    assert_eq!(workspace.transcript().capacity(), 3);
    assert_eq!(workspace.certificate().kind(), ArenaKind::Certificate);
    assert_eq!(workspace.certificate().capacity(), 4);
    assert_eq!(workspace.output().kind(), ArenaKind::Output);
    assert_eq!(workspace.output().capacity(), 5);
}

#[test]
fn every_duplicate_and_omitted_domain_is_rejected() {
    for kind in ArenaKind::ALL {
        let result = assign(WorkspaceLayoutBuilder::new(), kind, 1);
        let Ok(builder) = result else {
            return;
        };
        assert!(matches!(
            assign(builder, kind, 2),
            Err(WorkspaceError::Duplicate(found)) if found == kind
        ));
        assert!(matches!(
            complete_except(kind),
            Err(WorkspaceError::Incomplete(found)) if found == kind
        ));
    }
}

#[test]
fn default_builder_is_empty_and_fail_closed() {
    assert!(matches!(
        WorkspaceLayoutBuilder::default().build(),
        Err(WorkspaceError::Incomplete(ArenaKind::Secret))
    ));
}

#[test]
fn aggregate_overflow_is_rejected_before_storage_borrow() {
    assert!(matches!(
        layout([usize::MAX, 1, 0, 0, 0]),
        Err(WorkspaceError::LengthOverflow)
    ));
    assert!(matches!(
        layout([0, usize::MAX, 1, 0, 0]),
        Err(WorkspaceError::LengthOverflow)
    ));
    assert!(matches!(
        layout([0, 0, usize::MAX, 1, 0]),
        Err(WorkspaceError::LengthOverflow)
    ));
    assert!(matches!(
        layout([0, 0, 0, usize::MAX, 1]),
        Err(WorkspaceError::LengthOverflow)
    ));
}

#[test]
fn non_exact_backing_lengths_fail_without_mutation() {
    let result = layout([1, 1, 1, 1, 1]);
    let Ok(layout) = result else {
        return;
    };
    let mut short = [0x33_u8; 4];
    assert!(matches!(
        Workspace::new(&mut short, layout),
        Err(WorkspaceError::CapacityMismatch)
    ));
    assert_eq!(short, [0x33; 4]);

    let mut long = [0x44_u8; 6];
    assert!(matches!(
        Workspace::new(&mut long, layout),
        Err(WorkspaceError::CapacityMismatch)
    ));
    assert_eq!(long, [0x44; 6]);
}

#[test]
fn every_small_layout_partitions_exactly() {
    for secret in 0..=2 {
        for plaintext in 0..=2 {
            for transcript in 0..=2 {
                for certificate in 0..=2 {
                    for output in 0..=2 {
                        let lengths = [secret, plaintext, transcript, certificate, output];
                        let total = lengths.into_iter().sum::<usize>();
                        let result = layout(lengths);
                        let Ok(layout) = result else {
                            return;
                        };
                        assert_eq!(layout.total_bytes(), total);
                        let mut storage = [0x61_u8; 10];
                        let Some(exact) = storage.get_mut(..total) else {
                            return;
                        };
                        let result = Workspace::new(exact, layout);
                        assert!(result.is_ok());
                        let Ok(mut workspace) = result else {
                            return;
                        };
                        let arenas = workspace.arenas_mut();
                        assert_eq!(arenas.secret.capacity(), secret);
                        assert_eq!(arenas.plaintext.capacity(), plaintext);
                        assert_eq!(arenas.transcript.capacity(), transcript);
                        assert_eq!(arenas.certificate.capacity(), certificate);
                        assert_eq!(arenas.output.capacity(), output);
                    }
                }
            }
        }
    }
}

#[test]
fn empty_workspace_and_empty_allocations_are_exact() {
    let result = layout([0; 5]);
    let Ok(layout) = result else {
        return;
    };
    let mut storage = [];
    let result = Workspace::new(&mut storage, layout);
    let Ok(mut workspace) = result else {
        return;
    };
    assert_empty_arena(workspace.secret());
    assert_empty_arena(workspace.plaintext());
    assert_empty_arena(workspace.transcript());
    assert_empty_arena(workspace.certificate());
    assert_empty_arena(workspace.output());
}

#[test]
fn allocation_accounting_changes_only_after_success() {
    let result = layout([4, 0, 0, 0, 0]);
    let Ok(layout) = result else {
        return;
    };
    let mut storage = [0x77_u8; 4];
    let result = Workspace::new(&mut storage, layout);
    let Ok(mut workspace) = result else {
        return;
    };
    let arena = workspace.secret();
    assert_eq!(arena.allocate(2).map(|bytes| bytes.len()), Ok(2));
    assert_eq!(arena.allocate(0).map(|bytes| bytes.len()), Ok(0));
    assert_eq!(arena.used(), 2);
    assert_eq!(arena.high_water(), 2);
    assert_eq!(arena.allocation_count(), 1);
    assert_eq!(arena.remaining(), 2);

    assert_eq!(arena.allocate(3), Err(ArenaError::InsufficientCapacity));
    assert_eq!(arena.allocate(usize::MAX), Err(ArenaError::LengthOverflow));
    assert_eq!(arena.used(), 2);
    assert_eq!(arena.high_water(), 2);
    assert_eq!(arena.allocation_count(), 1);
    assert_eq!(arena.remaining(), 2);

    assert_eq!(arena.allocate(2).map(|bytes| bytes.len()), Ok(2));
    assert_eq!(arena.used(), 4);
    assert_eq!(arena.high_water(), 4);
    assert_eq!(arena.allocation_count(), 2);
    assert_eq!(arena.remaining(), 0);
}

#[test]
fn every_position_and_request_has_transactional_accounting() {
    const CAPACITY: usize = 8;
    for consumed in 0..=CAPACITY {
        for requested in 0..=CAPACITY.saturating_add(1) {
            let result = layout([CAPACITY, 0, 0, 0, 0]);
            let Ok(layout) = result else {
                return;
            };
            let mut storage = [0x91_u8; CAPACITY];
            let result = Workspace::new(&mut storage, layout);
            let Ok(mut workspace) = result else {
                return;
            };
            let arena = workspace.secret();
            assert!(arena.allocate(consumed).is_ok());
            let before = (
                arena.used(),
                arena.high_water(),
                arena.allocation_count(),
                arena.remaining(),
            );
            let result = arena.allocate(requested);
            if requested <= CAPACITY.saturating_sub(consumed) {
                assert!(result.is_ok());
                assert_eq!(arena.used(), consumed.saturating_add(requested));
                assert_eq!(arena.high_water(), consumed.saturating_add(requested));
                let expected_count =
                    usize::from(consumed != 0).saturating_add(usize::from(requested != 0));
                assert_eq!(arena.allocation_count(), expected_count);
            } else {
                assert_eq!(result, Err(ArenaError::InsufficientCapacity));
                assert_eq!(
                    (
                        arena.used(),
                        arena.high_water(),
                        arena.allocation_count(),
                        arena.remaining(),
                    ),
                    before
                );
            }
        }
    }
}

#[test]
fn arena_allocations_are_disjoint_and_retain_caller_bytes() {
    let result = layout([6, 0, 0, 0, 0]);
    let Ok(layout) = result else {
        return;
    };
    let mut storage = [1, 2, 3, 4, 5, 6];
    let origin = storage.as_ptr();
    let result = Workspace::new(&mut storage, layout);
    let Ok(mut workspace) = result else {
        return;
    };
    let arena = workspace.secret();
    let first = arena.allocate(2);
    let Ok(first) = first else { return };
    assert_eq!(first, [1, 2]);
    assert_eq!(first.as_ptr(), origin);
    first.fill(9);
    let second = arena.allocate(3);
    let Ok(second) = second else { return };
    assert_eq!(second, [3, 4, 5]);
    assert_eq!(second.as_ptr(), origin.wrapping_add(2));
    second.fill(8);
    drop(workspace);
    assert_eq!(storage, [9, 9, 8, 8, 8, 6]);
}

#[test]
fn errors_are_closed_and_value_free() {
    assert_eq!(
        format!("{:?}", WorkspaceError::LengthOverflow),
        "LengthOverflow"
    );
    assert_eq!(
        format!("{:?}", WorkspaceError::CapacityMismatch),
        "CapacityMismatch"
    );
    assert_eq!(
        format!("{:?}", ArenaError::LengthOverflow),
        "LengthOverflow"
    );
    assert_eq!(
        format!("{:?}", ArenaError::InsufficientCapacity),
        "InsufficientCapacity"
    );
    assert!(size_of::<WorkspaceError>() <= 2);
    assert_eq!(size_of::<ArenaError>(), 1);
}

#[test]
fn arena_domains_have_no_hidden_runtime_storage() {
    assert_eq!(
        size_of::<Arena<'_, brynja_core::SecretDomain>>(),
        size_of::<&mut [u8]>().saturating_add(size_of::<usize>().saturating_mul(3))
    );
    assert_eq!(
        size_of::<Arena<'_, brynja_core::OutputDomain>>(),
        size_of::<Arena<'_, brynja_core::SecretDomain>>()
    );
    assert_eq!(
        size_of::<WorkspaceArenas<'_, '_>>(),
        size_of::<&mut Arena<'_, brynja_core::SecretDomain>>().saturating_mul(5)
    );
    assert_eq!(
        size_of::<WorkspaceLayout>(),
        size_of::<usize>().saturating_mul(6)
    );
}
