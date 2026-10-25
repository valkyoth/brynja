//! Independent typed report-field and backend-width probes, not native evidence.
use brynja_legacy_hmac::md5_batch::{Md5Backend, Report};

macro_rules! field {
    ($name:ident, $kind:ty, $($path:ident).+) => {
        #[inline(never)]
        pub fn $name(report: &Report) -> $kind {
            report.$($path).+
        }
    };
}

field!(backend, Md5Backend, backend);
field!(width, usize, vector_width);
field!(inner_active, usize, inner.active_lanes);
field!(outer_active, usize, outer.active_lanes);
field!(inner_vector, usize, inner.vector_blocks);
field!(outer_vector, usize, outer.vector_blocks);

#[inline(never)]
pub fn backend_width(backend: Md5Backend) -> usize {
    backend.lane_width()
}

macro_rules! slot {
    ($name:ident, $index:literal) => {
        #[inline(never)]
        pub fn $name(inputs: &[Option<super::host::Md5BatchInput<'_>>; 8]) -> bool {
            inputs[$index].is_some()
        }
    };
}
slot!(slot0, 0);
slot!(slot1, 1);
slot!(slot2, 2);
slot!(slot3, 3);
slot!(slot4, 4);
slot!(slot5, 5);
slot!(slot6, 6);
slot!(slot7, 7);
