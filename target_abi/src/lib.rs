#![cfg_attr(not(test), no_std)]

pub mod artifact;
pub mod fake_aot;
pub mod profile;
pub mod signature;

pub use artifact::{
    SectionKindV1, TargetArtifactError, TargetArtifactHeaderV1, TargetArtifactImage,
    TargetSectionHeaderV1, canonical_zero_field_image_hash, verify_canonical_zero_field_image_hash,
};
pub use fake_aot::{
    ArtifactRelocationUnsupportedEventV1, FakeAotBlob, FakeAotEntryKindV1, FakeAotEntryV1,
    FakeAotError, FakeAotHeaderV1, FakeAotSectionKindV1, FakeHostcallStubV1, FakePatchEntryV1,
    FakePatchKindV1, FakeTrapStubV1, RV64_ENTRY_HOSTCALL_TAIL_BYTES,
    RV64_ENTRY_HOSTCALL_TAIL_OFFSET, RV64_ENTRY_RETURN_OK_BYTES, RV64_ENTRY_RETURN_OK_OFFSET,
    RV64_ENTRY_TRAP_EBREAK_BYTES, RV64_ENTRY_TRAP_EBREAK_OFFSET, RelocationEntryV1,
    RelocationKindV1, apply_fake_patch, validate_real_aot_relocation,
};
pub use profile::{
    CodePublishProfileV1, DmaProfileV1, DmwProfileV1, EndianV1, TargetArchV1,
    TargetSubstrateProfileV1,
};
pub use signature::{
    DevKeyRecordV1, SignatureRecordV1, SignatureSchemeV1, SignatureShapeError, SignatureStatusV1,
};
