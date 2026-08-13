//! Exact security-outcome commitment tests.

use brynja_core::{
    PolicyDecision, SecurityAuthority, SecurityAuthorityError, SecurityDecisionKind,
    SecurityOutcome, SecurityResolution, SecurityTerminal, TicketDecision,
};

#[test]
fn awaiting_commit_blocks_new_work_until_exact_completion_is_consumed() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<TicketDecision>() else {
        unreachable!();
    };
    let SecurityOutcome::Canceled(completion) = pending.resolve(SecurityResolution::Canceled)
    else {
        unreachable!();
    };
    assert_eq!(
        authority.begin::<PolicyDecision>().err(),
        Some(SecurityAuthorityError::Busy(SecurityDecisionKind::Ticket))
    );
    let receipt = completion.commit();
    assert!(receipt.belongs_to(&authority));
    let Ok(pending) = authority.begin::<PolicyDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Policy)),
        SecurityOutcome::Terminal(_)
    ));
}
