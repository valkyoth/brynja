//! Positive controls for every production method-set negative.
#![allow(dead_code)]

use brynja_mac_kmac::conformance as portable;
use execution::in_place as scoped_execution;
use portable::execution;
use portable::hardened_in_place as scoped;

fn control_0() {
    let _ = portable::Kmac128::new_conformance;
}

fn control_1() {
    let _ = portable::Kmac128::new_bits_conformance;
}

fn control_2() {
    let _ = portable::Kmac128::finalize_tag_conformance;
}

fn control_3() {
    let _ = portable::Kmac128::finalize_tag_bits_conformance;
}

fn control_4() {
    let _ = portable::Kmac128::finalize_secret_bits_conformance;
}

fn control_5() {
    let _ = portable::Kmac128::verify_conformance;
}

fn control_6() {
    let _ = portable::Kmac128::verify_bits_conformance;
}

fn control_7() {
    let _ = portable::Kmac256::new_conformance;
}

fn control_8() {
    let _ = portable::Kmac256::new_bits_conformance;
}

fn control_9() {
    let _ = portable::Kmac256::finalize_tag_conformance;
}

fn control_10() {
    let _ = portable::Kmac256::finalize_tag_bits_conformance;
}

fn control_11() {
    let _ = portable::Kmac256::finalize_secret_bits_conformance;
}

fn control_12() {
    let _ = portable::Kmac256::verify_conformance;
}

fn control_13() {
    let _ = portable::Kmac256::verify_bits_conformance;
}

fn control_14() {
    let _ = portable::KmacXof128::new_conformance;
}

fn control_15() {
    let _ = portable::KmacXof128::new_bits_conformance;
}

fn control_16() {
    let _ = portable::KmacXof128::finalize_xof_conformance;
}

fn control_17() {
    let _ = portable::KmacXof128::finalize_bits_xof_conformance;
}

fn control_18() {
    let _ = portable::KmacXof256::new_conformance;
}

fn control_19() {
    let _ = portable::KmacXof256::new_bits_conformance;
}

fn control_20() {
    let _ = portable::KmacXof256::finalize_xof_conformance;
}

fn control_21() {
    let _ = portable::KmacXof256::finalize_bits_xof_conformance;
}

fn control_22() {
    let _ = execution::Kmac128::new_conformance;
}

fn control_23() {
    let _ = execution::Kmac128::new_bits_conformance;
}

fn control_24() {
    let _ = execution::Kmac128::finalize_tag_conformance;
}

fn control_25() {
    let _ = execution::Kmac128::finalize_tag_bits_conformance;
}

fn control_26() {
    let _ = execution::Kmac128::finalize_secret_conformance;
}

fn control_27() {
    let _ = execution::Kmac128::finalize_secret_bits_conformance;
}

fn control_28() {
    let _ = execution::Kmac128::verify_conformance;
}

fn control_29() {
    let _ = execution::Kmac128::verify_bits_conformance;
}

fn control_30() {
    let _ = execution::Kmac256::new_conformance;
}

fn control_31() {
    let _ = execution::Kmac256::new_bits_conformance;
}

fn control_32() {
    let _ = execution::Kmac256::finalize_tag_conformance;
}

fn control_33() {
    let _ = execution::Kmac256::finalize_tag_bits_conformance;
}

fn control_34() {
    let _ = execution::Kmac256::finalize_secret_conformance;
}

fn control_35() {
    let _ = execution::Kmac256::finalize_secret_bits_conformance;
}

fn control_36() {
    let _ = execution::Kmac256::verify_conformance;
}

fn control_37() {
    let _ = execution::Kmac256::verify_bits_conformance;
}

fn control_38() {
    let _ = execution::KmacXof128::new_conformance;
}

fn control_39() {
    let _ = execution::KmacXof128::new_bits_conformance;
}

fn control_40() {
    let _ = execution::KmacXof128::finalize_xof_conformance;
}

fn control_41() {
    let _ = execution::KmacXof128::finalize_bits_xof_conformance;
}

fn control_42() {
    let _ = execution::KmacXof256::new_conformance;
}

fn control_43() {
    let _ = execution::KmacXof256::new_bits_conformance;
}

fn control_44() {
    let _ = execution::KmacXof256::finalize_xof_conformance;
}

fn control_45() {
    let _ = execution::KmacXof256::finalize_bits_xof_conformance;
}

fn control_46() {
    let _ = scoped::Kmac128::finalize_tag_conformance;
}

fn control_47() {
    let _ = scoped::Kmac128::finalize_tag_bits_conformance;
}

fn control_48() {
    let _ = scoped::Kmac128::finalize_secret_conformance;
}

fn control_49() {
    let _ = scoped::Kmac128::finalize_secret_bits_conformance;
}

fn control_50() {
    let _ = scoped::Kmac128::verify_conformance;
}

fn control_51() {
    let _ = scoped::Kmac128::verify_bits_conformance;
}

fn control_52(workspace: &mut scoped::Kmac128Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_53(workspace: &mut scoped::Kmac128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_54() {
    let _ = scoped::Kmac256::finalize_tag_conformance;
}

fn control_55() {
    let _ = scoped::Kmac256::finalize_tag_bits_conformance;
}

fn control_56() {
    let _ = scoped::Kmac256::finalize_secret_conformance;
}

fn control_57() {
    let _ = scoped::Kmac256::finalize_secret_bits_conformance;
}

fn control_58() {
    let _ = scoped::Kmac256::verify_conformance;
}

fn control_59() {
    let _ = scoped::Kmac256::verify_bits_conformance;
}

fn control_60(workspace: &mut scoped::Kmac256Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_61(workspace: &mut scoped::Kmac256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_62() {
    let _ = scoped::KmacXof128::finalize_xof_conformance;
}

fn control_63() {
    let _ = scoped::KmacXof128::finalize_bits_xof_conformance;
}

fn control_64(workspace: &mut scoped::KmacXof128Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_65(workspace: &mut scoped::KmacXof128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_66() {
    let _ = scoped::KmacXof256::finalize_xof_conformance;
}

fn control_67() {
    let _ = scoped::KmacXof256::finalize_bits_xof_conformance;
}

fn control_68(workspace: &mut scoped::KmacXof256Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_69(workspace: &mut scoped::KmacXof256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_70() {
    let _ = scoped_execution::Kmac128::finalize_tag_conformance;
}

fn control_71() {
    let _ = scoped_execution::Kmac128::finalize_tag_bits_conformance;
}

fn control_72() {
    let _ = scoped_execution::Kmac128::finalize_secret_conformance;
}

fn control_73() {
    let _ = scoped_execution::Kmac128::finalize_secret_bits_conformance;
}

fn control_74() {
    let _ = scoped_execution::Kmac128::verify_conformance;
}

fn control_75() {
    let _ = scoped_execution::Kmac128::verify_bits_conformance;
}

fn control_76(workspace: &mut scoped_execution::Kmac128Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_77(workspace: &mut scoped_execution::Kmac128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_78(workspace: &mut scoped_execution::Kmac128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_and_scratch_conformance(bits, bits, &mut [], |_| ());
    }
}

fn control_79() {
    let _ = scoped_execution::Kmac256::finalize_tag_conformance;
}

fn control_80() {
    let _ = scoped_execution::Kmac256::finalize_tag_bits_conformance;
}

fn control_81() {
    let _ = scoped_execution::Kmac256::finalize_secret_conformance;
}

fn control_82() {
    let _ = scoped_execution::Kmac256::finalize_secret_bits_conformance;
}

fn control_83() {
    let _ = scoped_execution::Kmac256::verify_conformance;
}

fn control_84() {
    let _ = scoped_execution::Kmac256::verify_bits_conformance;
}

fn control_85(workspace: &mut scoped_execution::Kmac256Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_86(workspace: &mut scoped_execution::Kmac256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_87(workspace: &mut scoped_execution::Kmac256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_and_scratch_conformance(bits, bits, &mut [], |_| ());
    }
}

fn control_88() {
    let _ = scoped_execution::KmacXof128::finalize_xof_conformance;
}

fn control_89() {
    let _ = scoped_execution::KmacXof128::finalize_bits_xof_conformance;
}

fn control_90(workspace: &mut scoped_execution::KmacXof128Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_91(workspace: &mut scoped_execution::KmacXof128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_92(workspace: &mut scoped_execution::KmacXof128Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_and_scratch_conformance(bits, bits, &mut [], |_| ());
    }
}

fn control_93() {
    let _ = scoped_execution::KmacXof256::finalize_xof_conformance;
}

fn control_94() {
    let _ = scoped_execution::KmacXof256::finalize_bits_xof_conformance;
}

fn control_95(workspace: &mut scoped_execution::KmacXof256Workspace) {
    let _ = workspace.with_conformance(&[], &[], |_| ());
}

fn control_96(workspace: &mut scoped_execution::KmacXof256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_conformance(bits, bits, |_| ());
    }
}

fn control_97(workspace: &mut scoped_execution::KmacXof256Workspace) {
    if let Ok(bits) = brynja_mac_kmac::Fips202BitString::new(&[], 0) {
        let _ = workspace.with_bits_and_scratch_conformance(bits, bits, &mut [], |_| ());
    }
}
