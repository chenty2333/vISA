//! Fixture for the composite cell.
//!
//! One dormant component claims a timer, a key-value namespace, a regular
//! file, and a logical request at the same time. The two profile extensions
//! are carried in a fixed order so the canonical digest is reproducible.

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
use substrate_host::{LoopbackLogicalPeer, SqliteProvider};
use visa_profile::{
    ContinuityDisposition, CooperativeHandoffProfile, FileAccessMode, FileDurability,
    FileLockPolicy, FileLockState, LOGICAL_REQUEST_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_VERSION,
    LogicalRequestClaim, LogicalRequestIdempotency, LogicalRequestPhase, LogicalRequestReplay,
    LogicalRequestState, LogicalRequestTransport, REGULAR_FILE_EXTENSION_ID,
    REGULAR_FILE_EXTENSION_VERSION, RegularFileClaim, RegularFileState, logical_request_extension,
    regular_file_extension,
};
use visa_runtime::{AuthorityPlan, ProfileAuthorityPlan, canonical_digest};

use crate::component;

const ID_DOMAIN: &[u8] = b"visa-composite-fixture-v1\0";
pub const INITIAL_LEASE_EPOCH: LeaseEpoch = LeaseEpoch(1);
pub const DEFAULT_PEER_IDENTITY: &[u8] = b"visa-composite-loopback-peer";
pub const DEFAULT_CREDENTIAL_MATERIAL: &[u8] = b"visa-composite-loopback-credential";
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 1_000;

pub struct CompositeFixture {
    pub case_id: String,
    pub paths: CompositeFixturePaths,
    pub ids: CompositeFixtureIds,
    pub source_state: CanonicalState,
    pub profile: CooperativeHandoffProfile,
    pub profile_digest: Digest,
    pub regular_file: RegularFileState,
    pub logical_request: LogicalRequestState,
    pub request_bytes: Vec<u8>,
    pub handoff_authority: AuthorityPlan,
    pub timer_authority: AuthorityPlan,
    pub key_value_authority: AuthorityPlan,
    pub file_authority: ProfileAuthorityPlan,
    pub request_authority: ProfileAuthorityPlan,
    pub source: SqliteProvider,
    pub destination: SqliteProvider,
}

#[derive(Clone, Debug)]
pub struct CompositeFixturePaths {
    pub case_root: PathBuf,
    pub database: PathBuf,
    pub file_root: PathBuf,
    pub file_path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct CompositeFixtureIds {
    pub source_node: NodeIdentity,
    pub destination_node: NodeIdentity,
    pub source_component: EntityRef,
    pub destination_component: EntityRef,
    pub timer: EntityRef,
    pub key_value: EntityRef,
    pub key_value_namespace: Identity,
    pub file: EntityRef,
    pub file_namespace: Identity,
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
    pub source_file_authority: EntityRef,
    pub destination_file_authority: EntityRef,
    pub attenuated_file_authority: EntityRef,
    pub source_request_authority: EntityRef,
    pub destination_request_authority: EntityRef,
    pub attenuated_request_authority: EntityRef,
    pub handoff: Identity,
    pub snapshot: Identity,
}

impl CompositeFixture {
    pub fn create(
        artifact_root: &Path,
        case_id: &str,
        initial_content: &[u8],
        request_bytes: &[u8],
        peer: &LoopbackLogicalPeer,
    ) -> Result<Self, String> {
        let paths = CompositeFixturePaths::create(artifact_root, case_id, initial_content)?;
        let ids = CompositeFixtureIds::for_case(case_id);
        let rights = profile_rights();

        let regular_file = RegularFileState {
            claim: RegularFileClaim {
                resource: ids.file,
                namespace: ids.file_namespace,
                relative_path: b"data.bin".to_vec(),
                required_rights: rights,
                access_mode: FileAccessMode::ReadWrite,
                durability: FileDurability::Visible,
                lock_policy: FileLockPolicy::ExclusiveLease,
                max_size: visa_profile::MAX_REGULAR_FILE_BYTES,
            },
            logical_offset: 0,
            version: 1,
            size: u64::try_from(initial_content.len()).map_err(|_| "initial file too large")?,
            content_digest: canonical_digest(&initial_content.to_vec())
                .map_err(|error| format!("cannot digest initial file: {error:?}"))?,
            durable_through: FileDurability::Visible,
            lock_state: FileLockState::Unlocked,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let logical_request = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: ids.request,
                peer_identity: DEFAULT_PEER_IDENTITY.to_vec(),
                credential_reference: ids.credential_reference,
                required_rights: rights,
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: DEFAULT_TIMEOUT_MILLIS,
                max_request_size: visa_profile::MAX_LOGICAL_REQUEST_BYTES,
                max_response_size: visa_profile::MAX_LOGICAL_RESPONSE_BYTES,
            },
            operation_id: ids.logical_operation,
            request_size: u32::try_from(request_bytes.len())
                .map_err(|_| "initial logical request is too large")?,
            request_digest: contract_core::canonical_digest(request_bytes)
                .map_err(|_| "cannot digest initial logical request")?,
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };

        let file_extension = regular_file_extension(&regular_file)
            .map_err(|error| format!("cannot encode regular-file extension: {error:?}"))?;
        let request_extension = logical_request_extension(&logical_request)
            .map_err(|error| format!("cannot encode logical-request extension: {error:?}"))?;
        let profile = CooperativeHandoffProfile::v1(vec![
            ExtensionSupport {
                id: REGULAR_FILE_EXTENSION_ID,
                version: REGULAR_FILE_EXTENSION_VERSION,
            },
            ExtensionSupport {
                id: LOGICAL_REQUEST_EXTENSION_ID,
                version: LOGICAL_REQUEST_EXTENSION_VERSION,
            },
        ]);
        let profile_digest = canonical_digest(&profile)
            .map_err(|error| format!("cannot digest composite profile: {error:?}"))?;

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
                ids.source_file_authority,
                ids.source_component,
                ids.file,
                rights,
            ),
            AuthorityGrant::active_root(
                ids.source_request_authority,
                ids.source_component,
                ids.request,
                rights,
            ),
        ];
        let source_state = CanonicalState::dormant_with_extensions(
            ids.source_component,
            ids.source_node,
            component::composite_digest(),
            profile_digest,
            SchemaVersion::new(profile.version.major, profile.version.minor),
            claims,
            source_roots.clone(),
            vec![file_extension, request_extension],
        );

        let mut source = SqliteProvider::open(
            &paths.database,
            JournalScope { node: ids.source_node, component: ids.source_component.identity },
        )
        .map_err(provider_error)?;
        let mut destination = SqliteProvider::open(
            &paths.database,
            JournalScope {
                node: ids.destination_node,
                component: ids.destination_component.identity,
            },
        )
        .map_err(provider_error)?;

        for (resource, allowed) in [
            (ids.source_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.file, rights),
            (ids.request, rights),
        ] {
            source
                .install_policy(AuthorityPolicy {
                    subject: ids.source_component,
                    resource,
                    allowed_rights: allowed,
                })
                .map_err(provider_error)?;
        }
        for grant in &source_roots {
            source.install_grant(grant).map_err(provider_error)?;
        }
        for (resource, allowed) in [
            (ids.destination_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.file, rights),
            (ids.request, rights),
        ] {
            destination
                .install_policy(AuthorityPolicy {
                    subject: ids.destination_component,
                    resource,
                    allowed_rights: allowed,
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
        source.provision_regular_file(&regular_file, &paths.file_root).map_err(provider_error)?;
        destination
            .provision_regular_file_namespace_availability(
                ids.destination_node,
                ids.file_namespace,
                &paths.file_root,
            )
            .map_err(provider_error)?;
        source
            .provision_logical_request(
                &logical_request,
                peer.address(),
                DEFAULT_CREDENTIAL_MATERIAL,
            )
            .map_err(provider_error)?;
        destination
            .provision_logical_request_peer(
                ids.destination_node,
                DEFAULT_PEER_IDENTITY,
                peer.address(),
                ids.credential_reference,
                DEFAULT_CREDENTIAL_MATERIAL,
            )
            .map_err(provider_error)?;

        Ok(Self {
            case_id: case_id.to_owned(),
            paths,
            ids,
            source_state,
            profile,
            profile_digest,
            regular_file,
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
            file_authority: ProfileAuthorityPlan {
                profile: REGULAR_FILE_EXTENSION_ID,
                resource: ids.file,
                authority: AuthorityPlan {
                    source_authority: ids.source_file_authority,
                    destination_authority: ids.destination_file_authority,
                    attenuated_authority: ids.attenuated_file_authority,
                },
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

impl CompositeFixturePaths {
    fn create(artifact_root: &Path, case_id: &str, content: &[u8]) -> Result<Self, String> {
        if case_id.is_empty()
            || !case_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("invalid composite case ID".to_owned());
        }
        let case_root = artifact_root.join("cases").join(case_id);
        let requested_file_root = case_root.join("live-file-root");
        fs::create_dir_all(&requested_file_root)
            .map_err(|error| format!("cannot create {}: {error}", requested_file_root.display()))?;
        let file_root = fs::canonicalize(&requested_file_root).map_err(|error| {
            format!("cannot resolve {}: {error}", requested_file_root.display())
        })?;
        let file_path = file_root.join("data.bin");
        fs::write(&file_path, content)
            .map_err(|error| format!("cannot write {}: {error}", file_path.display()))?;
        Ok(Self { database: case_root.join("provider.sqlite3"), case_root, file_root, file_path })
    }
}

impl CompositeFixtureIds {
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
            file: entity(case_id, "regular-file"),
            file_namespace: derive_identity(case_id, "regular-file-namespace"),
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
            source_file_authority: entity(case_id, "source-file-authority"),
            destination_file_authority: entity(case_id, "destination-file-authority"),
            attenuated_file_authority: entity(case_id, "attenuated-file-authority"),
            source_request_authority: entity(case_id, "source-request-authority"),
            destination_request_authority: entity(case_id, "destination-request-authority"),
            attenuated_request_authority: entity(case_id, "attenuated-request-authority"),
            handoff: derive_identity(case_id, "handoff"),
            snapshot: derive_identity(case_id, "snapshot"),
        }
    }
}

pub fn derive_identity(case_id: &str, label: &str) -> Identity {
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
