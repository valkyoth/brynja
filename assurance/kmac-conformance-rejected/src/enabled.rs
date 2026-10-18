//! Production method-set negatives with leaf conformance enabled.

use brynja_mac_kmac::hardened_in_place::accelerated as scoped_execution;

fn reject_2() {
    let _ = brynja_mac_kmac::Kmac128::new_conformance;
}

fn reject_6() {
    let _ = brynja_mac_kmac::Kmac128::new_bits_conformance;
}

fn reject_10() {
    let _ = brynja_mac_kmac::Kmac128::finalize_tag_conformance;
}

fn reject_14() {
    let _ = brynja_mac_kmac::Kmac256::new_conformance;
}

fn reject_18() {
    let _ = brynja_mac_kmac::Kmac256::new_bits_conformance;
}

fn reject_22() {
    let _ = brynja_mac_kmac::Kmac256::finalize_tag_conformance;
}

fn reject_26() {
    let _ = brynja_mac_kmac::KmacXof128::new_conformance;
}

fn reject_30() {
    let _ = brynja_mac_kmac::KmacXof128::new_bits_conformance;
}

fn reject_34() {
    let _ = brynja_mac_kmac::KmacXof128::finalize_xof_conformance;
}

fn reject_38() {
    let _ = brynja_mac_kmac::KmacXof256::new_conformance;
}

fn reject_42() {
    let _ = brynja_mac_kmac::KmacXof256::new_bits_conformance;
}

fn reject_46() {
    let _ = brynja_mac_kmac::KmacXof256::finalize_xof_conformance;
}

fn reject_50() {
    let _ = brynja_mac_kmac::execution::Kmac128::new_conformance;
}

fn reject_54() {
    let _ = brynja_mac_kmac::execution::Kmac128::new_bits_conformance;
}

fn reject_58() {
    let _ = brynja_mac_kmac::execution::Kmac128::finalize_tag_conformance;
}

fn reject_62() {
    let _ = brynja_mac_kmac::execution::Kmac256::new_conformance;
}

fn reject_66() {
    let _ = brynja_mac_kmac::execution::Kmac256::new_bits_conformance;
}

fn reject_70() {
    let _ = brynja_mac_kmac::execution::Kmac256::finalize_tag_conformance;
}

fn reject_74() {
    let _ = brynja_mac_kmac::execution::KmacXof128::new_conformance;
}

fn reject_78() {
    let _ = brynja_mac_kmac::execution::KmacXof128::new_bits_conformance;
}

fn reject_82() {
    let _ = brynja_mac_kmac::execution::KmacXof128::finalize_xof_conformance;
}

fn reject_86() {
    let _ = brynja_mac_kmac::execution::KmacXof256::new_conformance;
}

fn reject_90() {
    let _ = brynja_mac_kmac::execution::KmacXof256::new_bits_conformance;
}

fn reject_94() {
    let _ = brynja_mac_kmac::execution::KmacXof256::finalize_xof_conformance;
}

fn reject_98() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128Workspace::with_conformance;
}

fn reject_102() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128Workspace::with_bits_conformance;
}

fn reject_106() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac128::finalize_tag_conformance;
}

fn reject_110() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256Workspace::with_conformance;
}

fn reject_114() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256Workspace::with_bits_conformance;
}

fn reject_118() {
    let _ = brynja_mac_kmac::hardened_in_place::Kmac256::finalize_tag_conformance;
}

fn reject_122() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128Workspace::with_conformance;
}

fn reject_126() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128Workspace::with_bits_conformance;
}

fn reject_130() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof128::finalize_xof_conformance;
}

fn reject_134() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256Workspace::with_conformance;
}

fn reject_138() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256Workspace::with_bits_conformance;
}

fn reject_142() {
    let _ = brynja_mac_kmac::hardened_in_place::KmacXof256::finalize_xof_conformance;
}

fn reject_146() {
    let _ = scoped_execution::Kmac128Workspace::with_conformance;
}

fn reject_150() {
    let _ = scoped_execution::Kmac128Workspace::with_bits_conformance;
}

fn reject_154() {
    let _ = scoped_execution::Kmac128Workspace::with_bits_and_scratch_conformance;
}

fn reject_158() {
    let _ = scoped_execution::Kmac128::finalize_tag_conformance;
}

fn reject_162() {
    let _ = scoped_execution::Kmac256Workspace::with_conformance;
}

fn reject_166() {
    let _ = scoped_execution::Kmac256Workspace::with_bits_conformance;
}

fn reject_170() {
    let _ = scoped_execution::Kmac256Workspace::with_bits_and_scratch_conformance;
}

fn reject_174() {
    let _ = scoped_execution::Kmac256::finalize_tag_conformance;
}

fn reject_178() {
    let _ = scoped_execution::KmacXof128Workspace::with_conformance;
}

fn reject_182() {
    let _ = scoped_execution::KmacXof128Workspace::with_bits_conformance;
}

fn reject_186() {
    let _ = scoped_execution::KmacXof128Workspace::with_bits_and_scratch_conformance;
}

fn reject_190() {
    let _ = scoped_execution::KmacXof128::finalize_xof_conformance;
}

fn reject_194() {
    let _ = scoped_execution::KmacXof256Workspace::with_conformance;
}

fn reject_198() {
    let _ = scoped_execution::KmacXof256Workspace::with_bits_conformance;
}

fn reject_202() {
    let _ = scoped_execution::KmacXof256Workspace::with_bits_and_scratch_conformance;
}

fn reject_206() {
    let _ = scoped_execution::KmacXof256::finalize_xof_conformance;
}
