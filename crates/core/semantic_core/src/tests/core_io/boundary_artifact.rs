use super::*;

#[test]
pub(super) fn runtime_modes_publish_contract_policies() {
    let graph = SemanticGraph::with_runtime_mode(RuntimeMode::Replay);

    assert_eq!(graph.runtime_mode(), RuntimeMode::Replay);
    assert_eq!(graph.runtime_mode().event_log_policy(), "deterministic");
    assert!(graph.runtime_mode().deterministic_boundary());
    assert!(!graph.runtime_mode().fast_path_enabled());
}

#[test]
pub(super) fn boundary_status_is_queryable_and_versioned() {
    let mut graph = SemanticGraph::new();
    let boundary = graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::NotLinked,
        "runtime-only-executor-v1",
        Some("code-publish"),
    );

    assert_eq!(graph.boundary_count(), 1);
    assert_eq!(graph.boundaries()[0].id, boundary);
    assert_eq!(graph.boundaries()[0].status, BoundaryStatus::NotLinked);

    let same_boundary = graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::RuntimeContract,
        "runtime-only-executor-v1",
        Some("hostcall-trampoline"),
    );

    assert_eq!(same_boundary, boundary);
    assert_eq!(graph.boundary_count(), 1);
    assert_eq!(graph.boundaries()[0].generation, 2);
    assert_eq!(
        graph.boundaries()[0].summary(),
        "boundary target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BoundaryPublished boundary=1 name=target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
    );
}

#[test]
pub(super) fn artifact_verification_is_queryable_and_versioned() {
    let mut graph = SemanticGraph::new();
    let artifact = graph.record_artifact_verification(
        "vfs_service",
        "vfs",
        "binding-a",
        "cwasm-a",
        "manifest-bound",
        "abi-a",
        "prototype-self-signed-sha256",
        "profile-bound-unverified",
        false,
        "target_executor",
        ArtifactVerificationState::ManifestVerified,
        Some("target-cwasm-loader-not-linked"),
    );
    let same_artifact = graph.record_artifact_verification(
        "vfs_service",
        "vfs",
        "binding-a",
        "cwasm-a",
        "manifest-bound",
        "abi-a",
        "prototype-self-signed-sha256",
        "profile-bound-unverified",
        false,
        "target_executor",
        ArtifactVerificationState::HostValidated,
        Some("target-runtime-only-loader"),
    );

    assert_eq!(same_artifact, artifact);
    assert_eq!(graph.artifact_verification_count(), 1);
    assert_eq!(graph.artifact_verifications()[0].generation, 2);
    assert_eq!(
        graph.artifact_verifications()[0].summary(),
        "artifact vfs_service name=vfs state=host-validated binding=binding-a artifact_hash=cwasm-a hash_status=manifest-bound abi=abi-a signature=prototype-self-signed-sha256 signature_status=profile-bound-unverified signature_verified=false signer=target_executor blocked=target-runtime-only-loader generation=2"
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ArtifactVerificationRecorded artifact=1 package=vfs_service name=vfs state=host-validated binding=binding-a blocked=target-runtime-only-loader generation=2"
    );
}
