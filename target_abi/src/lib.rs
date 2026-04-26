#![cfg_attr(not(test), no_std)]

pub mod artifact;
pub mod control_plane;
pub mod fake_aot;
pub mod hostcall;
pub mod profile;
pub mod signature;
pub mod trap;

pub use artifact::{
    SectionKindV1, TargetArtifactError, TargetArtifactHeaderV1, TargetArtifactImage,
    TargetSectionHeaderV1, canonical_zero_field_image_hash, verify_canonical_zero_field_image_hash,
};
pub use control_plane::{
    ControlPlaneError, JsonlFrameRefV1, JsonlWriteOutcome, OsctlCursorV1, OsctlStreamV1,
    PANIC_RECORD_MAX_LEN, PANIC_RING_ALIGN, PANIC_RING_MAGIC, PANIC_RING_SIZE, PanicRecordHeaderV1,
    PanicRecordKindV1, PanicRingHeaderV1, PanicRingV1, PanicWriteOutcome, write_jsonl_frame,
};
pub use fake_aot::{
    ArtifactRelocationUnsupportedEventV1, FakeAotBlob, FakeAotEntryKindV1, FakeAotEntryV1,
    FakeAotError, FakeAotHeaderV1, FakeAotSectionKindV1, FakeHostcallStubV1, FakePatchEntryV1,
    FakePatchKindV1, FakeTrapStubV1, RV64_ENTRY_HOSTCALL_TAIL_BYTES,
    RV64_ENTRY_HOSTCALL_TAIL_OFFSET, RV64_ENTRY_RETURN_OK_BYTES, RV64_ENTRY_RETURN_OK_OFFSET,
    RV64_ENTRY_TRAP_EBREAK_BYTES, RV64_ENTRY_TRAP_EBREAK_OFFSET, RelocationEntryV1,
    RelocationKindV1, apply_fake_patch, validate_real_aot_relocation,
};
pub use hostcall::{
    ActivationScratchRegion, ActiveHostcallIdentity, CapabilityHandleRaw,
    FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A0, FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A1,
    FakeHostcallTailInvocation, HOSTCALL_FRAME_ARG_CAPACITY, HOSTCALL_FRAME_MAGIC,
    HOSTCALL_FRAME_RET_CAPACITY, HOSTCALL_FRAME_VERSION, HostcallFrameError, HostcallFrameV1,
    HostcallStatusV1, OBJECT_KIND_ACTIVATION_V1, OBJECT_KIND_CAPABILITY_V1,
    OBJECT_KIND_CODE_OBJECT_V1, OBJECT_KIND_STORE_V1, ObjectRefRaw, validate_trampoline_frame,
};
pub use profile::{
    CodePublishProfileV1, DmaProfileV1, DmwProfileV1, EndianV1, TargetArchV1,
    TargetSubstrateProfileV1,
};
pub use signature::{
    DevKeyRecordV1, SignatureRecordV1, SignatureSchemeV1, SignatureShapeError, SignatureStatusV1,
};
pub use trap::{
    CodeRangeStateV1, PcRangeEntryV1, PcRangeRuntimeEntryV1, TrapAttributionV1, TrapKindV1,
    TrapMapEntryV1, classify_trap_pc,
};
