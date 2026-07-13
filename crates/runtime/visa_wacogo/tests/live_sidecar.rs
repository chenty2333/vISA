use std::{env, fs};

use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::canonical_digest;
use visa_wacogo::{
    AdapterError, AdapterFailureKind, PATCHSET_SHA256, PreflightExpectations, TARGET,
    WacogoRuntime, component_digest,
};

const SAME_NAME_EMPTY_WORKLOAD_HEX: &str = "0061736d0d00010007030142000a4402001f766973613a636f6e74696e756974792f6b65792d76616c756540302e312e300500001c766973613a636f6e74696e756974792f74696d65727340302e312e30050005030101000b2401001e766973613a636f6e74696e756974792f776f726b6c6f616440302e312e3005020000330e636f6d706f6e656e742d6e616d65010903010005656d7074790117050300026b76010574696d65720208776f726b6c6f6164";
const SAME_NAME_EMPTY_WORKLOAD_SHA256: &str =
    "f8d32de44e12533b51fd0539e24145910ca2b584a542227b8e3ea85f3bfed869";

/// Explicit live gate for the separately built, source-lock-bound Go sidecar.
/// Ordinary Cargo tests remain independent of an external Go artifact.
#[test]
#[ignore = "requires VISA_WACOGO_BIN and VISA_WACOGO_TEST_COMPONENT"]
fn pinned_sidecar_preflights_the_exact_component_without_instantiating_it() {
    let component_path = env::var_os("VISA_WACOGO_TEST_COMPONENT")
        .expect("VISA_WACOGO_TEST_COMPONENT must name the exact Component");
    let component = fs::read(component_path).expect("read exact Component");
    let profile = CooperativeHandoffProfile::v1(Vec::new());
    let support = ProviderSupport::cooperative_handoff_v1(Vec::new());
    let expectations = PreflightExpectations {
        component_digest: component_digest(&component),
        profile_digest: canonical_digest(&profile).expect("encode profile identity"),
    };

    let prepared = WacogoRuntime::preflight(&component, &profile, &support, expectations)
        .expect("the pinned sidecar must return a non-executing Prepared token");
    assert_eq!(prepared.component_digest(), expectations.component_digest);
    assert_eq!(prepared.profile_digest(), expectations.profile_digest);
    assert_eq!(prepared.runtime_identity(), &WacogoRuntime::runtime_identity_static());
    assert_eq!(prepared.provenance().patchset_sha256, PATCHSET_SHA256);
    assert_eq!(prepared.provenance().target, TARGET);
}

/// Crosses the production Rust-to-Go startup boundary with the exact Component
/// that previously passed name-only surface validation and crashed on `status`.
#[test]
#[ignore = "requires VISA_WACOGO_BIN"]
fn pinned_sidecar_classifies_an_alternate_component_as_unsupported() {
    let component = hex::decode(SAME_NAME_EMPTY_WORKLOAD_HEX).expect("decode regression Component");
    assert_eq!(component.len(), 179);
    let component_digest = component_digest(&component);
    assert_eq!(hex::encode(component_digest.0), SAME_NAME_EMPTY_WORKLOAD_SHA256);

    let profile = CooperativeHandoffProfile::v1(Vec::new());
    let support = ProviderSupport::cooperative_handoff_v1(Vec::new());
    let expectations = PreflightExpectations {
        component_digest,
        profile_digest: canonical_digest(&profile).expect("encode profile identity"),
    };
    let error = WacogoRuntime::preflight(&component, &profile, &support, expectations)
        .expect_err("an alternate Component must not produce a Prepared token");

    assert_eq!(error.kind(), AdapterFailureKind::UnsupportedRuntimeFeature);
    let AdapterError::UnsupportedRuntimeFeature(detail) = error else {
        unreachable!("failure kind and AdapterError variant diverged")
    };
    assert!(detail.contains("unsupported Component identity"), "{detail}");
    assert!(
        detail.contains(&format!("size=179 sha256={SAME_NAME_EMPTY_WORKLOAD_SHA256}")),
        "{detail}"
    );
}
