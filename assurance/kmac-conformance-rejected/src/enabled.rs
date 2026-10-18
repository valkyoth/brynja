//! Production method-set negatives with leaf conformance enabled.

use brynja_mac_kmac::hardened_in_place::accelerated as scoped_execution;

fn reject_0() {
    let _ = brynja_mac_kmac::Kmac128::new_conformance;
}

fn reject_1() {
    let _ = brynja_mac_kmac::Kmac128::new_bits_conformance;
}

fn reject_2() {
    let _ = brynja_mac_kmac::Kmac128::finalize_tag_conformance;
}

fn reject_3() {
    let _ = brynja_mac_kmac::Kmac128::finalize_tag_bits_conformance;
}

fn reject_4() {
    let _ = brynja_mac_kmac::Kmac128::finalize_secret_bits_conformance;
}

fn reject_5() {
    let _ = brynja_mac_kmac::Kmac128::verify_conformance;
}

fn reject_6() {
    let _ = brynja_mac_kmac::Kmac128::verify_bits_conformance;
}

fn reject_7() {
    let _ = brynja_mac_kmac::Kmac256::new_conformance;
}

fn reject_8() {
    let _ = brynja_mac_kmac::Kmac256::new_bits_conformance;
}

fn reject_9() {
    let _ = brynja_mac_kmac::Kmac256::finalize_tag_conformance;
}

fn reject_10() {
    let _ = brynja_mac_kmac::Kmac256::finalize_tag_bits_conformance;
}

fn reject_11() {
    let _ = brynja_mac_kmac::Kmac256::finalize_secret_bits_conformance;
}

fn reject_12() {
    let _ = brynja_mac_kmac::Kmac256::verify_conformance;
}

fn reject_13() {
    let _ = brynja_mac_kmac::Kmac256::verify_bits_conformance;
}

fn reject_14() {
    let _ = brynja_mac_kmac::KmacXof128::new_conformance;
}

fn reject_15() {
    let _ = brynja_mac_kmac::KmacXof128::new_bits_conformance;
}

fn reject_16() {
    let _ = brynja_mac_kmac::KmacXof128::finalize_xof_conformance;
}

fn reject_17() {
    let _ = brynja_mac_kmac::KmacXof128::finalize_bits_xof_conformance;
}

fn reject_18() {
    let _ = brynja_mac_kmac::KmacXof256::new_conformance;
}

fn reject_19() {
    let _ = brynja_mac_kmac::KmacXof256::new_bits_conformance;
}

fn reject_20() {
    let _ = brynja_mac_kmac::KmacXof256::finalize_xof_conformance;
}

fn reject_21() {
    let _ = brynja_mac_kmac::KmacXof256::finalize_bits_xof_conformance;
}

fn reject_22() {
    let _ = brynja_mac_kmac::execution::Kmac128::new_conformance;
}

fn reject_23() {
    let _ = brynja_mac_kmac::execution::Kmac128::new_bits_conformance;
}

fn reject_24() {
    let _ = brynja_mac_kmac::execution::Kmac128::finalize_tag_conformance;
}

fn reject_25() {
    let _ = brynja_mac_kmac::execution::Kmac128::finalize_tag_bits_conformance;
}

fn reject_26() {
    let _ = brynja_mac_kmac::execution::Kmac128::finalize_secret_conformance;
}

fn reject_27() {
    let _ = brynja_mac_kmac::execution::Kmac128::finalize_secret_bits_conformance;
}

fn reject_28() {
    let _ = brynja_mac_kmac::execution::Kmac128::verify_conformance;
}

fn reject_29() {
    let _ = brynja_mac_kmac::execution::Kmac128::verify_bits_conformance;
}

fn reject_30() {
    let _ = brynja_mac_kmac::execution::Kmac256::new_conformance;
}

fn reject_31() {
    let _ = brynja_mac_kmac::execution::Kmac256::new_bits_conformance;
}

fn reject_32() {
    let _ = brynja_mac_kmac::execution::Kmac256::finalize_tag_conformance;
}

fn reject_33() {
    let _ = brynja_mac_kmac::execution::Kmac256::finalize_tag_bits_conformance;
}

fn reject_34() {
    let _ = brynja_mac_kmac::execution::Kmac256::finalize_secret_conformance;
}

fn reject_35() {
    let _ = brynja_mac_kmac::execution::Kmac256::finalize_secret_bits_conformance;
}

fn reject_36() {
    let _ = brynja_mac_kmac::execution::Kmac256::verify_conformance;
}

fn reject_37() {
    let _ = brynja_mac_kmac::execution::Kmac256::verify_bits_conformance;
}

fn reject_38() {
    let _ = brynja_mac_kmac::execution::KmacXof128::new_conformance;
}

fn reject_39() {
    let _ = brynja_mac_kmac::execution::KmacXof128::new_bits_conformance;
}

fn reject_40() {
    let _ = brynja_mac_kmac::execution::KmacXof128::finalize_xof_conformance;
}

fn reject_41() {
    let _ = brynja_mac_kmac::execution::KmacXof128::finalize_bits_xof_conformance;
}

fn reject_42() {
    let _ = brynja_mac_kmac::execution::KmacXof256::new_conformance;
}

fn reject_43() {
    let _ = brynja_mac_kmac::execution::KmacXof256::new_bits_conformance;
}

fn reject_44() {
    let _ = brynja_mac_kmac::execution::KmacXof256::finalize_xof_conformance;
}

fn reject_45() {
    let _ = brynja_mac_kmac::execution::KmacXof256::finalize_bits_xof_conformance;
}

fn reject_46() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::finalize_tag_conformance;
}

fn reject_47() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::finalize_tag_bits_conformance;
}

fn reject_48() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::finalize_secret_conformance;
}

fn reject_49() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::finalize_secret_bits_conformance;
}

fn reject_50() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::verify_conformance;
}

fn reject_51() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::verify_bits_conformance;
}

fn reject_52() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128Workspace::with_conformance;
}

fn reject_53() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128Workspace::with_bits_conformance;
}

fn reject_54() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::finalize_tag_conformance;
}

fn reject_55() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::finalize_tag_bits_conformance;
}

fn reject_56() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::finalize_secret_conformance;
}

fn reject_57() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::finalize_secret_bits_conformance;
}

fn reject_58() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::verify_conformance;
}

fn reject_59() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::verify_bits_conformance;
}

fn reject_60() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256Workspace::with_conformance;
}

fn reject_61() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256Workspace::with_bits_conformance;
}

fn reject_62() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128::finalize_xof_conformance;
}

fn reject_63() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128::finalize_bits_xof_conformance;
}

fn reject_64() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128Workspace::with_conformance;
}

fn reject_65() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128Workspace::with_bits_conformance;
}

fn reject_66() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256::finalize_xof_conformance;
}

fn reject_67() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256::finalize_bits_xof_conformance;
}

fn reject_68() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256Workspace::with_conformance;
}

fn reject_69() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256Workspace::with_bits_conformance;
}

fn reject_70() {
    let _ = scoped_execution::Kmac128::finalize_tag_conformance;
}

fn reject_71() {
    let _ = scoped_execution::Kmac128::finalize_tag_bits_conformance;
}

fn reject_72() {
    let _ = scoped_execution::Kmac128::finalize_secret_conformance;
}

fn reject_73() {
    let _ = scoped_execution::Kmac128::finalize_secret_bits_conformance;
}

fn reject_74() {
    let _ = scoped_execution::Kmac128::verify_conformance;
}

fn reject_75() {
    let _ = scoped_execution::Kmac128::verify_bits_conformance;
}

fn reject_76() {
    let _ = scoped_execution::Kmac128Workspace::with_conformance;
}

fn reject_77() {
    let _ = scoped_execution::Kmac128Workspace::with_bits_conformance;
}

fn reject_78() {
    let _ = scoped_execution::Kmac128Workspace::with_bits_and_scratch_conformance;
}

fn reject_79() {
    let _ = scoped_execution::Kmac256::finalize_tag_conformance;
}

fn reject_80() {
    let _ = scoped_execution::Kmac256::finalize_tag_bits_conformance;
}

fn reject_81() {
    let _ = scoped_execution::Kmac256::finalize_secret_conformance;
}

fn reject_82() {
    let _ = scoped_execution::Kmac256::finalize_secret_bits_conformance;
}

fn reject_83() {
    let _ = scoped_execution::Kmac256::verify_conformance;
}

fn reject_84() {
    let _ = scoped_execution::Kmac256::verify_bits_conformance;
}

fn reject_85() {
    let _ = scoped_execution::Kmac256Workspace::with_conformance;
}

fn reject_86() {
    let _ = scoped_execution::Kmac256Workspace::with_bits_conformance;
}

fn reject_87() {
    let _ = scoped_execution::Kmac256Workspace::with_bits_and_scratch_conformance;
}

fn reject_88() {
    let _ = scoped_execution::KmacXof128::finalize_xof_conformance;
}

fn reject_89() {
    let _ = scoped_execution::KmacXof128::finalize_bits_xof_conformance;
}

fn reject_90() {
    let _ = scoped_execution::KmacXof128Workspace::with_conformance;
}

fn reject_91() {
    let _ = scoped_execution::KmacXof128Workspace::with_bits_conformance;
}

fn reject_92() {
    let _ = scoped_execution::KmacXof128Workspace::with_bits_and_scratch_conformance;
}

fn reject_93() {
    let _ = scoped_execution::KmacXof256::finalize_xof_conformance;
}

fn reject_94() {
    let _ = scoped_execution::KmacXof256::finalize_bits_xof_conformance;
}

fn reject_95() {
    let _ = scoped_execution::KmacXof256Workspace::with_conformance;
}

fn reject_96() {
    let _ = scoped_execution::KmacXof256Workspace::with_bits_conformance;
}

fn reject_97() {
    let _ = scoped_execution::KmacXof256Workspace::with_bits_and_scratch_conformance;
}
