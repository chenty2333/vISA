//! Feature-gated runtime behavior-injection controls.

#[cfg(feature = "test-control")]
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPoint {
    SkipExternalSourceFence = 1,
}

#[cfg(feature = "test-control")]
static NEXT: AtomicU8 = AtomicU8::new(0);
#[cfg(feature = "test-control")]
static LAST: AtomicU8 = AtomicU8::new(0);
#[cfg(feature = "test-control")]
static FIRED: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "test-control")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultObservation {
    pub point: FaultPoint,
    pub count: u64,
}

#[cfg(feature = "test-control")]
pub fn inject_once(point: FaultPoint) {
    NEXT.store(point as u8, Ordering::SeqCst);
}

#[cfg(feature = "test-control")]
pub fn observation() -> Option<FaultObservation> {
    match LAST.load(Ordering::SeqCst) {
        1 => Some(FaultObservation {
            point: FaultPoint::SkipExternalSourceFence,
            count: FIRED.load(Ordering::SeqCst),
        }),
        _ => None,
    }
}

#[inline(always)]
pub(crate) fn take_once(point: FaultPoint) -> bool {
    #[cfg(not(feature = "test-control"))]
    let _ = point;
    #[cfg(feature = "test-control")]
    {
        if NEXT.compare_exchange(point as u8, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            LAST.store(point as u8, Ordering::SeqCst);
            FIRED.fetch_add(1, Ordering::SeqCst);
            return true;
        }
    }
    false
}
