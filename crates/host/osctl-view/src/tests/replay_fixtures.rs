// Replay trace fixtures used by osctl replay tests.
// Paths use CARGO_MANIFEST_DIR so they are stable across
// file moves, crate renames, and directory restructures.
pub(crate) const WAIT_PENDING_RESUME: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/replay/wait_pending_resume_v1.json"
));

pub(crate) const CAPABILITY_REVOKE_GENERATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/replay/capability_revoke_generation_v1.json"
));

pub(crate) const DRIVER_FAULT_CLEANUP_GENERATION_SAFE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/replay/driver_fault_cleanup_generation_safe_v1.json"
));
