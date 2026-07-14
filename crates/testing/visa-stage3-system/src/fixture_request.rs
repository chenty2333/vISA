use std::{
    fs,
    path::{Path, PathBuf},
};

use contract_core::{
    AuthorityGrant, CanonicalState, DeliveryPolicy, Digest, EntityRef, ExtensionSupport,
    Generation, Identity, KeyValueClaim, LeaseEpoch, NodeIdentity, ResourceClaims, Rights,
    SchemaVersion, TimerClaim, TimerClock,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{AuthorityPolicy, AuthorityPort, JournalScope};
use substrate_host::{FaultPoint, LoopbackLogicalPeer, SqliteProvider};
use visa_profile::{
    ContinuityDisposition, CooperativeHandoffProfile, LOGICAL_REQUEST_EXTENSION_ID,
    LOGICAL_REQUEST_EXTENSION_VERSION, LogicalRequestClaim, LogicalRequestIdempotency,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestState,
    LogicalRequestTransport, LogicalResponseMetadata, logical_request_extension,
};
use visa_runtime::{AuthorityPlan, ProfileAuthorityPlan, canonical_digest};

use crate::component;

const ID_DOMAIN: &[u8] = b"visa-stage3b-fixture-v1\0";
pub const INITIAL_LEASE_EPOCH: LeaseEpoch = LeaseEpoch(1);
pub const STAGE3B_INITIAL_LEASE_EPOCH: LeaseEpoch = INITIAL_LEASE_EPOCH;
pub const STAGE3B_DEFAULT_PEER_IDENTITY: &[u8] = b"visa-stage3b-loopback-peer";
pub const STAGE3B_DEFAULT_CREDENTIAL_MATERIAL: &[u8] = b"visa-stage3b-loopback-credential";

pub struct Stage3bFixture {
    pub case_id: String,
    pub paths: Stage3bFixturePaths,
    pub ids: Stage3bFixtureIds,
    pub source_state: CanonicalState,
    pub profile: CooperativeHandoffProfile,
    pub profile_digest: Digest,
    pub logical_request: LogicalRequestState,
    pub request_bytes: Vec<u8>,
    pub handoff_authority: AuthorityPlan,
    pub timer_authority: AuthorityPlan,
    pub key_value_authority: AuthorityPlan,
    pub request_authority: ProfileAuthorityPlan,
    pub source: SqliteProvider,
    pub destination: SqliteProvider,
}

#[derive(Clone, Debug)]
pub struct Stage3bFixturePaths {
    pub case_root: PathBuf,
    pub database: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct Stage3bFixtureIds {
    pub source_node: NodeIdentity,
    pub destination_node: NodeIdentity,
    pub source_component: EntityRef,
    pub destination_component: EntityRef,
    pub timer: EntityRef,
    pub key_value: EntityRef,
    pub key_value_namespace: Identity,
    pub request: EntityRef,
    pub credential_reference: Identity,
    pub logical_operation: Identity,
    pub source_handoff_authority: EntityRef,
    pub destination_handoff_authority: EntityRef,
    pub attenuated_handoff_authority: EntityRef,
    pub source_timer_authority: EntityRef,
    pub destination_timer_authority: EntityRef,
    pub attenuated_timer_authority: EntityRef,
    pub source_key_value_authority: EntityRef,
    pub destination_key_value_authority: EntityRef,
    pub attenuated_key_value_authority: EntityRef,
    pub source_request_authority: EntityRef,
    pub destination_request_authority: EntityRef,
    pub attenuated_request_authority: EntityRef,
    pub handoff: Identity,
    pub snapshot: Identity,
}

#[derive(Clone, Debug)]
pub struct Stage3bFixtureOptions {
    pub destination_request_policy: bool,
    pub destination_peer_available: bool,
    pub destination_credential_available: bool,
    pub source_fault: Option<FaultPoint>,
    pub transport: LogicalRequestTransport,
    pub delivery: DeliveryPolicy,
    pub replay: LogicalRequestReplay,
    pub idempotency: LogicalRequestIdempotency,
    pub timeout_millis: u64,
    pub phase: LogicalRequestPhase,
    pub source_peer_identity: Vec<u8>,
    pub destination_peer_identity: Vec<u8>,
    pub source_credential_material: Vec<u8>,
    pub destination_credential_material: Vec<u8>,
}

impl Default for Stage3bFixtureOptions {
    fn default() -> Self {
        Self::standard()
    }
}

impl Stage3bFixtureOptions {
    pub fn standard() -> Self {
        Self {
            destination_request_policy: true,
            destination_peer_available: true,
            destination_credential_available: true,
            source_fault: None,
            transport: LogicalRequestTransport::Reconnectable,
            delivery: DeliveryPolicy::Deduplicated,
            replay: LogicalRequestReplay::WithOperationId,
            idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
            timeout_millis: 1_000,
            phase: LogicalRequestPhase::Ready,
            source_peer_identity: STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
            destination_peer_identity: STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
            source_credential_material: STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
            destination_credential_material: STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        }
    }
}

impl Stage3bFixture {
    pub fn create(
        artifact_root: &Path,
        case_id: &str,
        request_bytes: &[u8],
        peer: &LoopbackLogicalPeer,
        options: Stage3bFixtureOptions,
    ) -> Result<Self, String> {
        let paths = Stage3bFixturePaths::create(artifact_root, case_id)?;
        let ids = Stage3bFixtureIds::for_case(case_id);
        let request_rights = profile_rights();
        let response = response_for_phase(options.phase)?;
        let rejection = rejection_for_phase(options.phase);
        let logical_request = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: ids.request,
                peer_identity: options.source_peer_identity.clone(),
                credential_reference: ids.credential_reference,
                required_rights: request_rights,
                transport: options.transport,
                delivery: options.delivery,
                replay: options.replay,
                idempotency: options.idempotency,
                timeout_millis: options.timeout_millis,
                max_request_size: visa_profile::MAX_LOGICAL_REQUEST_BYTES,
                max_response_size: visa_profile::MAX_LOGICAL_RESPONSE_BYTES,
            },
            operation_id: ids.logical_operation,
            request_size: u32::try_from(request_bytes.len())
                .map_err(|_| "initial logical request is too large")?,
            request_digest: contract_core::canonical_digest(request_bytes)
                .map_err(|_| "cannot digest initial logical request")?,
            phase: options.phase,
            response_cursor: 0,
            response,
            rejection,
            disposition: disposition_for(options.phase),
            last_operation: None,
        };
        let extension = logical_request_extension(&logical_request)
            .map_err(|error| format!("cannot encode logical-request extension: {error:?}"))?;
        let profile = CooperativeHandoffProfile::v1(vec![ExtensionSupport {
            id: LOGICAL_REQUEST_EXTENSION_ID,
            version: LOGICAL_REQUEST_EXTENSION_VERSION,
        }]);
        let profile_digest = canonical_digest(&profile)
            .map_err(|error| format!("cannot digest Stage 3B profile: {error:?}"))?;
        let claims = ResourceClaims {
            timer: TimerClaim {
                resource: ids.timer,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: timer_rights(),
            },
            key_value: KeyValueClaim {
                resource: ids.key_value,
                namespace: ids.key_value_namespace,
                required_rights: key_value_rights(),
                delivery: DeliveryPolicy::Deduplicated,
            },
        };
        let source_roots = vec![
            AuthorityGrant::active_root(
                ids.source_handoff_authority,
                ids.source_component,
                ids.source_component,
                Rights::HANDOFF,
            ),
            AuthorityGrant::active_root(
                ids.source_timer_authority,
                ids.source_component,
                ids.timer,
                timer_rights(),
            ),
            AuthorityGrant::active_root(
                ids.source_key_value_authority,
                ids.source_component,
                ids.key_value,
                key_value_rights(),
            ),
            AuthorityGrant::active_root(
                ids.source_request_authority,
                ids.source_component,
                ids.request,
                request_rights,
            ),
        ];
        let source_state = CanonicalState::dormant_with_extensions(
            ids.source_component,
            ids.source_node,
            component::stage3b_digest(),
            profile_digest,
            SchemaVersion::new(profile.version.major, profile.version.minor),
            claims,
            source_roots.clone(),
            vec![extension],
        );

        let source_scope =
            JournalScope { node: ids.source_node, component: ids.source_component.identity };
        let destination_scope = JournalScope {
            node: ids.destination_node,
            component: ids.destination_component.identity,
        };
        let mut source =
            SqliteProvider::open(&paths.database, source_scope).map_err(provider_error)?;
        let mut destination =
            SqliteProvider::open(&paths.database, destination_scope).map_err(provider_error)?;

        for (resource, rights) in [
            (ids.source_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.request, request_rights),
        ] {
            source
                .install_policy(AuthorityPolicy {
                    subject: ids.source_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(provider_error)?;
        }
        for grant in &source_roots {
            source.install_grant(grant).map_err(provider_error)?;
        }

        for (resource, rights) in [
            (ids.destination_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
        ] {
            destination
                .install_policy(AuthorityPolicy {
                    subject: ids.destination_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(provider_error)?;
        }
        if options.destination_request_policy {
            destination
                .install_policy(AuthorityPolicy {
                    subject: ids.destination_component,
                    resource: ids.request,
                    allowed_rights: request_rights,
                })
                .map_err(provider_error)?;
        }

        source
            .provision_key_value_namespace(ids.key_value, ids.key_value_namespace)
            .map_err(provider_error)?;
        destination
            .provision_key_value_namespace_availability(
                ids.destination_node,
                ids.key_value_namespace,
            )
            .map_err(provider_error)?;
        source
            .provision_logical_request(
                &logical_request,
                peer.address(),
                &options.source_credential_material,
            )
            .map_err(provider_error)?;
        if options.destination_peer_available {
            destination
                .provision_logical_request_peer(
                    ids.destination_node,
                    &options.destination_peer_identity,
                    peer.address(),
                    ids.credential_reference,
                    &options.destination_credential_material,
                )
                .map_err(provider_error)?;
            if !options.destination_credential_available {
                drop(destination);
                destination = SqliteProvider::open(&paths.database, destination_scope)
                    .map_err(provider_error)?;
            }
        }
        if let Some(fault) = options.source_fault {
            source.inject_failure_once(fault);
        }

        Ok(Self {
            case_id: case_id.to_owned(),
            paths,
            ids,
            source_state,
            profile,
            profile_digest,
            logical_request,
            request_bytes: request_bytes.to_vec(),
            handoff_authority: AuthorityPlan {
                source_authority: ids.source_handoff_authority,
                destination_authority: ids.destination_handoff_authority,
                attenuated_authority: ids.attenuated_handoff_authority,
            },
            timer_authority: AuthorityPlan {
                source_authority: ids.source_timer_authority,
                destination_authority: ids.destination_timer_authority,
                attenuated_authority: ids.attenuated_timer_authority,
            },
            key_value_authority: AuthorityPlan {
                source_authority: ids.source_key_value_authority,
                destination_authority: ids.destination_key_value_authority,
                attenuated_authority: ids.attenuated_key_value_authority,
            },
            request_authority: ProfileAuthorityPlan {
                profile: LOGICAL_REQUEST_EXTENSION_ID,
                resource: ids.request,
                authority: AuthorityPlan {
                    source_authority: ids.source_request_authority,
                    destination_authority: ids.destination_request_authority,
                    attenuated_authority: ids.attenuated_request_authority,
                },
            },
            source,
            destination,
        })
    }
}

impl Stage3bFixturePaths {
    fn create(artifact_root: &Path, case_id: &str) -> Result<Self, String> {
        validate_case_id(case_id)?;
        let case_root = artifact_root.join("cases").join(case_id);
        fs::create_dir_all(&case_root)
            .map_err(|error| format!("cannot create {}: {error}", case_root.display()))?;
        Ok(Self { database: case_root.join("provider.sqlite3"), case_root })
    }
}

impl Stage3bFixtureIds {
    fn for_case(case_id: &str) -> Self {
        let component = derive_identity(case_id, "component");
        Self {
            source_node: NodeIdentity::new(derive_identity(case_id, "source-node")),
            destination_node: NodeIdentity::new(derive_identity(case_id, "destination-node")),
            source_component: EntityRef::initial(component),
            destination_component: EntityRef::new(component, Generation(1)),
            timer: entity(case_id, "timer"),
            key_value: entity(case_id, "key-value"),
            key_value_namespace: derive_identity(case_id, "key-value-namespace"),
            request: entity(case_id, "logical-request"),
            credential_reference: derive_identity(case_id, "credential-reference"),
            logical_operation: derive_identity(case_id, "logical-operation"),
            source_handoff_authority: entity(case_id, "source-handoff-authority"),
            destination_handoff_authority: entity(case_id, "destination-handoff-authority"),
            attenuated_handoff_authority: entity(case_id, "attenuated-handoff-authority"),
            source_timer_authority: entity(case_id, "source-timer-authority"),
            destination_timer_authority: entity(case_id, "destination-timer-authority"),
            attenuated_timer_authority: entity(case_id, "attenuated-timer-authority"),
            source_key_value_authority: entity(case_id, "source-key-value-authority"),
            destination_key_value_authority: entity(case_id, "destination-key-value-authority"),
            attenuated_key_value_authority: entity(case_id, "attenuated-key-value-authority"),
            source_request_authority: entity(case_id, "source-request-authority"),
            destination_request_authority: entity(case_id, "destination-request-authority"),
            attenuated_request_authority: entity(case_id, "attenuated-request-authority"),
            handoff: derive_identity(case_id, "handoff"),
            snapshot: derive_identity(case_id, "snapshot"),
        }
    }
}

pub fn derive_stage3b_identity(case_id: &str, label: &str) -> Identity {
    derive_identity(case_id, label)
}

fn derive_identity(case_id: &str, label: &str) -> Identity {
    let mut digest = Sha256::new();
    digest.update(ID_DOMAIN);
    digest.update((case_id.len() as u64).to_be_bytes());
    digest.update(case_id.as_bytes());
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label.as_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    Identity::from_bytes(identity)
}

fn entity(case_id: &str, label: &str) -> EntityRef {
    EntityRef::initial(derive_identity(case_id, label))
}

fn validate_case_id(case_id: &str) -> Result<(), String> {
    if case_id.is_empty()
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid Stage 3 case ID".to_owned());
    }
    Ok(())
}

fn response_for_phase(
    phase: LogicalRequestPhase,
) -> Result<Option<LogicalResponseMetadata>, String> {
    if phase != LogicalRequestPhase::Completed {
        return Ok(None);
    }
    Ok(Some(LogicalResponseMetadata {
        size: 0,
        digest: contract_core::canonical_digest(&[] as &[u8])
            .map_err(|_| "cannot digest empty logical response")?,
    }))
}

const fn rejection_for_phase(phase: LogicalRequestPhase) -> Option<LogicalRequestRejection> {
    if matches!(phase, LogicalRequestPhase::Rejected) {
        Some(LogicalRequestRejection::PolicyDenied)
    } else {
        None
    }
}

const fn disposition_for(phase: LogicalRequestPhase) -> ContinuityDisposition {
    match phase {
        LogicalRequestPhase::Pending
        | LogicalRequestPhase::PartialResponse
        | LogicalRequestPhase::Cancelling => ContinuityDisposition::Reconnect,
        LogicalRequestPhase::Replaying => ContinuityDisposition::Replay,
        LogicalRequestPhase::Rejected => ContinuityDisposition::Reject,
        LogicalRequestPhase::Ready
        | LogicalRequestPhase::UnknownCompletion
        | LogicalRequestPhase::Reconciling
        | LogicalRequestPhase::Completed
        | LogicalRequestPhase::TimedOut
        | LogicalRequestPhase::Cancelled => ContinuityDisposition::Revalidate,
    }
}

const fn timer_rights() -> Rights {
    Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
}

const fn key_value_rights() -> Rights {
    Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
}

const fn profile_rights() -> Rights {
    Rights::PROFILE_READ
        .union(Rights::PROFILE_WRITE)
        .union(Rights::PROFILE_CONTROL)
        .union(Rights::REBIND)
}

fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("provider error {:?} (retryable={})", error.kind, error.retryable)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use substrate_host::LoopbackLogicalPeerBehavior;
    use visa_profile::logical_request_state;

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("visa-stage3b-fixture-{label}-{}-{sequence}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn peer() -> LoopbackLogicalPeer {
        LoopbackLogicalPeer::spawn(
            STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
            STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
            LoopbackLogicalPeerBehavior::Echo,
        )
        .unwrap()
    }

    #[test]
    fn standard_fixture_binds_component_profile_claims_and_authority() {
        let root = TestRoot::new("standard");
        let peer = peer();
        let fixture = Stage3bFixture::create(
            &root.0,
            "standard",
            b"request-body",
            &peer,
            Stage3bFixtureOptions::standard(),
        )
        .unwrap();
        assert_eq!(fixture.source_state.component_digest, component::stage3b_digest());
        assert_eq!(fixture.source_state.extensions.len(), 1);
        assert_eq!(
            logical_request_state(&fixture.source_state.extensions[0]).unwrap(),
            fixture.logical_request
        );
        assert_eq!(fixture.request_authority.profile, LOGICAL_REQUEST_EXTENSION_ID);
        assert_eq!(fixture.request_authority.resource, fixture.ids.request);
        assert_eq!(fixture.request_bytes, b"request-body");
        assert_eq!(fixture.profile.required_extensions.len(), 1);
    }

    #[test]
    fn phase_variants_are_canonical_but_raw_tcp_and_invalid_policy_fail_closed() {
        let root = TestRoot::new("phases");
        let peer = peer();
        for (index, phase) in [
            LogicalRequestPhase::Ready,
            LogicalRequestPhase::Pending,
            LogicalRequestPhase::PartialResponse,
            LogicalRequestPhase::UnknownCompletion,
            LogicalRequestPhase::Reconciling,
            LogicalRequestPhase::Replaying,
            LogicalRequestPhase::Cancelling,
            LogicalRequestPhase::Completed,
            LogicalRequestPhase::TimedOut,
            LogicalRequestPhase::Cancelled,
            LogicalRequestPhase::Rejected,
        ]
        .into_iter()
        .enumerate()
        {
            let mut options = Stage3bFixtureOptions::standard();
            options.phase = phase;
            let fixture = Stage3bFixture::create(
                &root.0,
                &format!("phase-{index}"),
                b"request-body",
                &peer,
                options,
            )
            .unwrap();
            assert_eq!(fixture.logical_request.phase, phase);
        }

        let mut raw = Stage3bFixtureOptions::standard();
        raw.transport = LogicalRequestTransport::RawLiveTcp;
        assert!(Stage3bFixture::create(&root.0, "raw-tcp", b"body", &peer, raw).is_err());

        let mut invalid = Stage3bFixtureOptions::standard();
        invalid.idempotency = LogicalRequestIdempotency::NonIdempotent;
        assert!(
            Stage3bFixture::create(&root.0, "invalid-policy", b"body", &peer, invalid).is_err()
        );
    }

    #[test]
    fn destination_credential_unavailable_keeps_peer_config_but_drops_material() {
        let root = TestRoot::new("credential-unavailable");
        let peer = peer();
        let mut options = Stage3bFixtureOptions::standard();
        options.destination_credential_available = false;
        let mut fixture = Stage3bFixture::create(
            &root.0,
            "credential-unavailable",
            b"request-body",
            &peer,
            options,
        )
        .unwrap();

        // The endpoint/reference row survived the destination reopen, while
        // new material can be acquired because no credential bytes reopened.
        fixture
            .destination
            .provision_logical_request_peer(
                fixture.ids.destination_node,
                &fixture.logical_request.claim.peer_identity,
                peer.address(),
                fixture.ids.credential_reference,
                b"fresh-destination-material",
            )
            .unwrap();
    }
}
