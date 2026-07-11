use std::{fmt, path::Path};

use contract_core::{
    AuthorityGrant, CanonicalState, DeliveryPolicy, Digest, EntityRef, Generation, Identity,
    KeyValueClaim, LeaseEpoch, NodeIdentity, ResourceClaims, Rights, SchemaVersion, TimerClaim,
    TimerClock,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, JournalScope, ProviderError, ProviderErrorKind,
};
use substrate_host::SqliteProvider;
use visa_profile::CooperativeHandoffProfile;
use visa_runtime::{AuthorityPlan, EncodeError, canonical_digest};

const ID_DOMAIN: &[u8] = b"visa-system-stage1-fixture-v1\0";
const INITIAL_LEASE_EPOCH: LeaseEpoch = LeaseEpoch(1);
const WORKLOAD_DELAY_NS: u64 = 50_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceAvailability {
    #[default]
    Correct,
    Missing,
    Wrong,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPolicyMode {
    #[default]
    Sufficient,
    Missing,
    Broader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureOptions {
    pub case_id: String,
    pub namespace_availability: NamespaceAvailability,
    pub authority_policy: AuthorityPolicyMode,
}

impl FixtureOptions {
    pub fn new(case_id: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            namespace_availability: NamespaceAvailability::Correct,
            authority_policy: AuthorityPolicyMode::Sufficient,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalScopeSpec {
    pub node: NodeIdentity,
    pub component: Identity,
}

impl JournalScopeSpec {
    pub const fn to_runtime(&self) -> JournalScope {
        JournalScope { node: self.node, component: self.component }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPlanSpec {
    pub source_authority: EntityRef,
    pub destination_authority: EntityRef,
    pub attenuated_authority: EntityRef,
}

impl AuthorityPlanSpec {
    pub const fn to_runtime(&self) -> AuthorityPlan {
        AuthorityPlan {
            source_authority: self.source_authority,
            destination_authority: self.destination_authority,
            attenuated_authority: self.attenuated_authority,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleSpec {
    pub subject: EntityRef,
    pub resource: EntityRef,
    pub allowed_rights: Rights,
}

impl PolicyRuleSpec {
    const fn as_provider(&self) -> AuthorityPolicy {
        AuthorityPolicy {
            subject: self.subject,
            resource: self.resource,
            allowed_rights: self.allowed_rights,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfigDigestInput {
    pub source_scope: JournalScopeSpec,
    pub destination_scope: JournalScopeSpec,
    pub key_value_resource: EntityRef,
    pub logical_namespace: Identity,
    pub destination_namespace: Option<Identity>,
    pub namespace_availability: NamespaceAvailability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDigestInput {
    pub mode: AuthorityPolicyMode,
    pub source_policies: Vec<PolicyRuleSpec>,
    pub destination_policies: Vec<PolicyRuleSpec>,
    pub source_roots: Vec<AuthorityGrant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub command: Identity,
    pub source_node: NodeIdentity,
    pub component: EntityRef,
    pub source_authority: EntityRef,
    pub initial_lease_epoch: LeaseEpoch,
    pub session_id: String,
    pub key: String,
    pub initial_value: Vec<u8>,
    pub completion_value: Vec<u8>,
    pub delay_ns: u64,
    pub baseline_idempotency_key: String,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
}

impl ActivationRequest {
    pub fn to_wasmtime(&self) -> visa_wasmtime::ActivationRequest {
        visa_wasmtime::ActivationRequest {
            session_id: self.session_id.clone(),
            key: self.key.clone(),
            initial_value: self.initial_value.clone(),
            completion_value: self.completion_value.clone(),
            delay_ns: self.delay_ns,
            baseline_idempotency_key: self.baseline_idempotency_key.clone(),
            timer_idempotency_key: self.timer_idempotency_key.clone(),
            completion_idempotency_key: self.completion_idempotency_key.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureIds {
    pub source_node: NodeIdentity,
    pub destination_node: NodeIdentity,
    pub source_component: EntityRef,
    pub destination_component: EntityRef,
    pub timer_resource: EntityRef,
    pub key_value_resource: EntityRef,
    pub key_value_namespace: Identity,
    pub wrong_key_value_namespace: Identity,
    pub source_handoff_authority: EntityRef,
    pub destination_handoff_authority: EntityRef,
    pub attenuated_handoff_authority: EntityRef,
    pub source_timer_authority: EntityRef,
    pub destination_timer_authority: EntityRef,
    pub attenuated_timer_authority: EntityRef,
    pub source_key_value_authority: EntityRef,
    pub destination_key_value_authority: EntityRef,
    pub attenuated_key_value_authority: EntityRef,
    pub activation_command: Identity,
    pub handoff: Identity,
    pub snapshot: Identity,
}

impl FixtureIds {
    fn for_case(case_id: &str) -> Self {
        let component = derive_identity(case_id, "component");
        Self {
            source_node: NodeIdentity::new(derive_identity(case_id, "source-node")),
            destination_node: NodeIdentity::new(derive_identity(case_id, "destination-node")),
            source_component: EntityRef::initial(component),
            destination_component: EntityRef::new(component, Generation(1)),
            timer_resource: entity(case_id, "timer-resource"),
            key_value_resource: entity(case_id, "key-value-resource"),
            key_value_namespace: derive_identity(case_id, "key-value-namespace"),
            wrong_key_value_namespace: derive_identity(case_id, "wrong-key-value-namespace"),
            source_handoff_authority: entity(case_id, "source-handoff-authority"),
            destination_handoff_authority: entity(case_id, "destination-handoff-authority"),
            attenuated_handoff_authority: entity(case_id, "attenuated-handoff-authority"),
            source_timer_authority: entity(case_id, "source-timer-authority"),
            destination_timer_authority: entity(case_id, "destination-timer-authority"),
            attenuated_timer_authority: entity(case_id, "attenuated-timer-authority"),
            source_key_value_authority: entity(case_id, "source-key-value-authority"),
            destination_key_value_authority: entity(case_id, "destination-key-value-authority"),
            attenuated_key_value_authority: entity(case_id, "attenuated-key-value-authority"),
            activation_command: derive_identity(case_id, "activation-command"),
            handoff: derive_identity(case_id, "handoff"),
            snapshot: derive_identity(case_id, "snapshot"),
        }
    }

    pub fn all_identities(&self) -> Vec<Identity> {
        vec![
            self.source_node.0,
            self.destination_node.0,
            self.source_component.identity,
            self.timer_resource.identity,
            self.key_value_resource.identity,
            self.key_value_namespace,
            self.wrong_key_value_namespace,
            self.source_handoff_authority.identity,
            self.destination_handoff_authority.identity,
            self.attenuated_handoff_authority.identity,
            self.source_timer_authority.identity,
            self.destination_timer_authority.identity,
            self.attenuated_timer_authority.identity,
            self.source_key_value_authority.identity,
            self.destination_key_value_authority.identity,
            self.attenuated_key_value_authority.identity,
            self.activation_command,
            self.handoff,
            self.snapshot,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    pub options: FixtureOptions,
    pub ids: FixtureIds,
    pub component_digest: Digest,
    pub profile: CooperativeHandoffProfile,
    pub profile_digest: Digest,
    pub claims: ResourceClaims,
    pub source_state: CanonicalState,
    pub handoff_authority: AuthorityPlanSpec,
    pub timer_authority: AuthorityPlanSpec,
    pub key_value_authority: AuthorityPlanSpec,
    pub activation: ActivationRequest,
    pub config_digest_input: ProviderConfigDigestInput,
    pub policy_digest_input: PolicyDigestInput,
}

impl FixtureSpec {
    pub fn new(case_id: impl Into<String>) -> Result<Self, FixtureError> {
        Self::with_options(FixtureOptions::new(case_id))
    }

    pub fn with_options(options: FixtureOptions) -> Result<Self, FixtureError> {
        let ids = FixtureIds::for_case(&options.case_id);
        let profile = CooperativeHandoffProfile::v1(Vec::new());
        let profile_digest = canonical_digest(&profile)?;
        let component_digest = crate::component::digest();
        let timer_rights = timer_rights();
        let key_value_rights = key_value_rights();
        let claims = ResourceClaims {
            timer: TimerClaim {
                resource: ids.timer_resource,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: timer_rights,
            },
            key_value: KeyValueClaim {
                resource: ids.key_value_resource,
                namespace: ids.key_value_namespace,
                required_rights: key_value_rights,
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
                ids.timer_resource,
                timer_rights,
            ),
            AuthorityGrant::active_root(
                ids.source_key_value_authority,
                ids.source_component,
                ids.key_value_resource,
                key_value_rights,
            ),
        ];
        let source_state = CanonicalState::dormant(
            ids.source_component,
            ids.source_node,
            component_digest,
            profile_digest,
            SchemaVersion::new(profile.version.major, profile.version.minor),
            claims.clone(),
            source_roots.clone(),
        );
        let source_policies = vec![
            PolicyRuleSpec {
                subject: ids.source_component,
                resource: ids.source_component,
                allowed_rights: Rights::HANDOFF,
            },
            PolicyRuleSpec {
                subject: ids.source_component,
                resource: ids.timer_resource,
                allowed_rights: timer_rights,
            },
            PolicyRuleSpec {
                subject: ids.source_component,
                resource: ids.key_value_resource,
                allowed_rights: key_value_rights,
            },
        ];
        let destination_policies = destination_policies(&ids, options.authority_policy);
        let destination_namespace = match options.namespace_availability {
            NamespaceAvailability::Correct => Some(ids.key_value_namespace),
            NamespaceAvailability::Missing => None,
            NamespaceAvailability::Wrong => Some(ids.wrong_key_value_namespace),
        };
        let activation = ActivationRequest {
            command: ids.activation_command,
            source_node: ids.source_node,
            component: ids.source_component,
            source_authority: ids.source_handoff_authority,
            initial_lease_epoch: INITIAL_LEASE_EPOCH,
            session_id: format!("{}:session", options.case_id),
            key: "stage1-value".to_owned(),
            initial_value: b"started".to_vec(),
            completion_value: b"completed".to_vec(),
            delay_ns: WORKLOAD_DELAY_NS,
            baseline_idempotency_key: format!("{}:baseline", options.case_id),
            timer_idempotency_key: format!("{}:timer", options.case_id),
            completion_idempotency_key: format!("{}:completion", options.case_id),
        };

        Ok(Self {
            config_digest_input: ProviderConfigDigestInput {
                source_scope: JournalScopeSpec {
                    node: ids.source_node,
                    component: ids.source_component.identity,
                },
                destination_scope: JournalScopeSpec {
                    node: ids.destination_node,
                    component: ids.destination_component.identity,
                },
                key_value_resource: ids.key_value_resource,
                logical_namespace: ids.key_value_namespace,
                destination_namespace,
                namespace_availability: options.namespace_availability,
            },
            policy_digest_input: PolicyDigestInput {
                mode: options.authority_policy,
                source_policies,
                destination_policies,
                source_roots,
            },
            handoff_authority: AuthorityPlanSpec {
                source_authority: ids.source_handoff_authority,
                destination_authority: ids.destination_handoff_authority,
                attenuated_authority: ids.attenuated_handoff_authority,
            },
            timer_authority: AuthorityPlanSpec {
                source_authority: ids.source_timer_authority,
                destination_authority: ids.destination_timer_authority,
                attenuated_authority: ids.attenuated_timer_authority,
            },
            key_value_authority: AuthorityPlanSpec {
                source_authority: ids.source_key_value_authority,
                destination_authority: ids.destination_key_value_authority,
                attenuated_authority: ids.attenuated_key_value_authority,
            },
            options,
            ids,
            component_digest,
            profile,
            profile_digest,
            claims,
            source_state,
            activation,
        })
    }

    pub fn config_digest(&self) -> Result<Digest, FixtureError> {
        canonical_digest(&self.config_digest_input).map_err(Into::into)
    }

    pub fn policy_digest(&self) -> Result<Digest, FixtureError> {
        canonical_digest(&self.policy_digest_input).map_err(Into::into)
    }

    pub fn open_providers(&self, path: impl AsRef<Path>) -> Result<OpenProviders, FixtureError> {
        let path = path.as_ref();
        let mut source =
            SqliteProvider::open(path, self.config_digest_input.source_scope.to_runtime())?;
        let mut destination =
            SqliteProvider::open(path, self.config_digest_input.destination_scope.to_runtime())?;

        for policy in &self.policy_digest_input.source_policies {
            source.install_policy(policy.as_provider())?;
        }
        for grant in &self.policy_digest_input.source_roots {
            match source.install_grant(grant) {
                Ok(()) => {}
                Err(error) if error.kind == ProviderErrorKind::StaleGeneration => {
                    // A durable tombstone or later active generation means the
                    // fixture root was already provisioned and evolved.
                }
                Err(error) => return Err(error.into()),
            }
        }
        source.provision_key_value_namespace(
            self.config_digest_input.key_value_resource,
            self.config_digest_input.logical_namespace,
        )?;

        for policy in &self.policy_digest_input.destination_policies {
            destination.install_policy(policy.as_provider())?;
        }
        if let Some(namespace) = self.config_digest_input.destination_namespace {
            destination
                .provision_key_value_namespace_availability(self.ids.destination_node, namespace)?;
        }

        Ok(OpenProviders { source, destination })
    }
}

pub struct OpenProviders {
    pub source: SqliteProvider,
    pub destination: SqliteProvider,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureError {
    CanonicalEncoding,
    Provider(ProviderError),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding => formatter.write_str("fixture canonical encoding failed"),
            Self::Provider(error) => write!(
                formatter,
                "fixture provider failed: {:?} (retryable: {})",
                error.kind, error.retryable
            ),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<EncodeError> for FixtureError {
    fn from(_: EncodeError) -> Self {
        Self::CanonicalEncoding
    }
}

impl From<ProviderError> for FixtureError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

pub fn derive_identity(case_id: &str, field_label: &str) -> Identity {
    let mut hasher = Sha256::new();
    hasher.update(ID_DOMAIN);
    hasher.update((case_id.len() as u64).to_be_bytes());
    hasher.update(case_id.as_bytes());
    hasher.update((field_label.len() as u64).to_be_bytes());
    hasher.update(field_label.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    Identity::from_bytes(bytes)
}

fn entity(case_id: &str, field_label: &str) -> EntityRef {
    EntityRef::initial(derive_identity(case_id, field_label))
}

const fn timer_rights() -> Rights {
    Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
}

const fn key_value_rights() -> Rights {
    Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
}

const fn all_rights() -> Rights {
    timer_rights().union(key_value_rights()).union(Rights::HANDOFF)
}

fn destination_policies(ids: &FixtureIds, mode: AuthorityPolicyMode) -> Vec<PolicyRuleSpec> {
    if mode == AuthorityPolicyMode::Missing {
        return Vec::new();
    }
    let (handoff, timer, key_value) = match mode {
        AuthorityPolicyMode::Sufficient => (Rights::HANDOFF, timer_rights(), key_value_rights()),
        AuthorityPolicyMode::Broader => (all_rights(), all_rights(), all_rights()),
        AuthorityPolicyMode::Missing => unreachable!(),
    };
    vec![
        PolicyRuleSpec {
            subject: ids.destination_component,
            resource: ids.destination_component,
            allowed_rights: handoff,
        },
        PolicyRuleSpec {
            subject: ids.destination_component,
            resource: ids.timer_resource,
            allowed_rights: timer,
        },
        PolicyRuleSpec {
            subject: ids.destination_component,
            resource: ids.key_value_resource,
            allowed_rights: key_value,
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::{CONTRACT_VERSION, Event, EventKind, JournalEntry, JournalPosition};
    use substrate_api::{
        AuthorityPort, BindingKind, BindingPort, BindingRequest, JournalPort, LeasePort,
        LeaseRecord, ProviderErrorKind, ReauthorizationRequest,
    };

    use super::*;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-system-fixture-{label}-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            remove_database_files(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            remove_database_files(&self.0);
        }
    }

    fn remove_database_files(path: &Path) {
        let _ = fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }

    #[test]
    fn ids_and_digest_inputs_are_deterministic_and_nonzero() {
        let first = FixtureSpec::new("deterministic-case").unwrap();
        let repeated = FixtureSpec::new("deterministic-case").unwrap();
        let different = FixtureSpec::new("different-case").unwrap();

        assert_eq!(first, repeated);
        assert_ne!(first.ids, different.ids);
        assert!(first.ids.all_identities().into_iter().all(|identity| !identity.is_zero()));
        assert_eq!(first.profile_digest, canonical_digest(&first.profile).unwrap());
        assert_eq!(first.config_digest().unwrap(), repeated.config_digest().unwrap());
        assert_eq!(first.policy_digest().unwrap(), repeated.policy_digest().unwrap());
        assert_ne!(first.config_digest().unwrap(), different.config_digest().unwrap());
        assert_ne!(first.policy_digest().unwrap(), different.policy_digest().unwrap());

        let encoded = serde_json::to_vec(&first).unwrap();
        assert_eq!(serde_json::from_slice::<FixtureSpec>(&encoded).unwrap(), first);
        assert_eq!(first.activation.to_wasmtime().session_id, "deterministic-case:session");
    }

    #[test]
    fn source_and_destination_journals_are_scope_isolated() {
        let database = TestDatabase::new("scope");
        let fixture = FixtureSpec::new("scope-case").unwrap();
        let mut providers = fixture.open_providers(database.path()).unwrap();
        let entry = JournalEntry {
            version: CONTRACT_VERSION,
            position: JournalPosition(1),
            input_state: fixture.profile_digest,
            output_state: fixture.component_digest,
            event: Event::new(
                derive_identity("scope-case", "scope-event"),
                EventKind::HandoffStarted,
            ),
        };

        providers.source.append_entry(&entry).unwrap();
        assert_eq!(providers.source.entry(JournalPosition(1)).unwrap(), Some(entry.clone()));
        assert_eq!(providers.destination.entry(JournalPosition(1)).unwrap(), None);
        providers.destination.append_entry(&entry).unwrap();
        assert_eq!(providers.destination.entry(JournalPosition(1)).unwrap(), Some(entry));
    }

    #[test]
    fn source_namespace_mapping_is_stable_and_setup_is_idempotent() {
        let database = TestDatabase::new("idempotent");
        let fixture = FixtureSpec::new("idempotent-case").unwrap();
        {
            let mut providers = fixture.open_providers(database.path()).unwrap();
            providers
                .source
                .provision_key_value_namespace(
                    fixture.ids.key_value_resource,
                    fixture.ids.key_value_namespace,
                )
                .unwrap();
            assert_eq!(
                providers
                    .source
                    .provision_key_value_namespace(
                        fixture.ids.key_value_resource,
                        fixture.ids.wrong_key_value_namespace,
                    )
                    .unwrap_err()
                    .kind,
                ProviderErrorKind::Conflict
            );
        }
        fixture.open_providers(database.path()).unwrap();
    }

    #[test]
    fn namespace_modes_preserve_the_claim_and_control_destination_availability() {
        for (mode, expected) in [
            (NamespaceAvailability::Correct, None),
            (NamespaceAvailability::Missing, Some(ProviderErrorKind::NotFound)),
            (NamespaceAvailability::Wrong, Some(ProviderErrorKind::NotFound)),
        ] {
            let database = TestDatabase::new(&format!("namespace-{mode:?}"));
            let fixture = FixtureSpec::with_options(FixtureOptions {
                case_id: format!("namespace-{mode:?}"),
                namespace_availability: mode,
                authority_policy: AuthorityPolicyMode::Sufficient,
            })
            .unwrap();
            let mut providers = fixture.open_providers(database.path()).unwrap();
            let result = prepare_key_value_binding(
                &mut providers,
                &fixture,
                fixture.ids.key_value_namespace,
            );
            match expected {
                None => assert!(result.is_ok(), "correct namespace must bind: {result:?}"),
                Some(kind) => assert_eq!(result.unwrap_err().kind, kind),
            }

            if mode == NamespaceAvailability::Wrong {
                let wrong = prepare_key_value_binding(
                    &mut providers,
                    &fixture,
                    fixture.ids.wrong_key_value_namespace,
                );
                assert_eq!(wrong.unwrap_err().kind, ProviderErrorKind::Conflict);
                assert_eq!(fixture.claims.key_value.namespace, fixture.ids.key_value_namespace);
            }
        }
    }

    #[test]
    fn authority_modes_install_missing_exact_or_broader_destination_policy() {
        for mode in [
            AuthorityPolicyMode::Sufficient,
            AuthorityPolicyMode::Missing,
            AuthorityPolicyMode::Broader,
        ] {
            let database = TestDatabase::new(&format!("authority-{mode:?}"));
            let fixture = FixtureSpec::with_options(FixtureOptions {
                case_id: format!("authority-{mode:?}"),
                namespace_availability: NamespaceAvailability::Correct,
                authority_policy: mode,
            })
            .unwrap();
            let mut providers = fixture.open_providers(database.path()).unwrap();
            let request = key_value_reauthorization(&fixture);
            let result = providers.destination.reauthorize(request);
            match mode {
                AuthorityPolicyMode::Missing => {
                    assert_eq!(result.unwrap_err().kind, ProviderErrorKind::Denied);
                    assert!(fixture.policy_digest_input.destination_policies.is_empty());
                }
                AuthorityPolicyMode::Sufficient => {
                    assert_eq!(result.unwrap().rights, key_value_rights());
                    assert_eq!(
                        fixture.policy_digest_input.destination_policies[2].allowed_rights,
                        key_value_rights()
                    );
                }
                AuthorityPolicyMode::Broader => {
                    assert_eq!(result.unwrap().rights, key_value_rights());
                    assert_eq!(
                        fixture.policy_digest_input.destination_policies[2].allowed_rights,
                        all_rights()
                    );
                }
            }
        }
    }

    fn key_value_reauthorization(fixture: &FixtureSpec) -> ReauthorizationRequest {
        ReauthorizationRequest {
            handoff: fixture.ids.handoff,
            snapshot: fixture.ids.snapshot,
            source_authority: fixture.key_value_authority.source_authority,
            destination_authority: fixture.key_value_authority.destination_authority,
            destination_subject: fixture.ids.destination_component,
            resource: fixture.ids.key_value_resource,
            required_rights: key_value_rights(),
        }
    }

    fn prepare_key_value_binding(
        providers: &mut OpenProviders,
        fixture: &FixtureSpec,
        requested_namespace: Identity,
    ) -> Result<contract_core::BindingReceipt, ProviderError> {
        providers.source.initialize_lease(LeaseRecord {
            resource: fixture.ids.key_value_resource,
            owner: fixture.ids.source_node,
            epoch: fixture.activation.initial_lease_epoch,
        })?;
        let authority = providers.destination.reauthorize(key_value_reauthorization(fixture))?;
        providers.destination.prepare_binding(BindingRequest {
            handoff: fixture.ids.handoff,
            snapshot: fixture.ids.snapshot,
            claim: fixture.ids.key_value_resource,
            authority: authority.authority,
            exposed_rights: key_value_rights(),
            expected_owner: fixture.ids.source_node,
            expected_epoch: fixture.activation.initial_lease_epoch,
            candidate_owner: fixture.ids.destination_node,
            candidate_epoch: fixture.activation.initial_lease_epoch.next().unwrap(),
            kind: BindingKind::KeyValueNamespace { namespace: requested_namespace },
        })
    }
}
