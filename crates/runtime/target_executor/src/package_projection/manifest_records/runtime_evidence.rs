use visa_runtime::VisaRuntimeEvidenceSnapshot;

use super::{super::super::*, *};

#[derive(Clone, Debug, Default)]
pub struct RuntimeEvidenceTargetRuntimeManifests {
    pub target_artifacts: Vec<TargetArtifactImageManifest>,
    pub code_objects: Vec<CodeObjectManifest>,
    pub store_records: Vec<StoreRecordManifest>,
    pub capability_records: Vec<CapabilityRecordManifest>,
    pub wait_records: Vec<WaitRecordManifest>,
    pub activation_records: Vec<ActivationRecordManifest>,
    pub trap_records: Vec<TrapRecordManifest>,
    pub hostcall_trace: Vec<HostcallTraceManifest>,
    pub cleanup_transactions: Vec<CleanupTransactionManifest>,
    pub tombstones: Vec<TombstoneManifest>,
    pub substrate_events: Vec<SubstrateEventManifest>,
}

pub fn runtime_evidence_target_runtime_manifests(
    evidence: &VisaRuntimeEvidenceSnapshot,
) -> RuntimeEvidenceTargetRuntimeManifests {
    let graph = &evidence.contract_graph;
    RuntimeEvidenceTargetRuntimeManifests {
        target_artifacts: runtime_evidence_target_artifact_manifests(evidence),
        code_objects: graph.code_objects.iter().map(code_object_manifest).collect(),
        store_records: graph.stores.iter().map(store_record_manifest).collect(),
        capability_records: graph.capabilities.iter().map(capability_record_manifest).collect(),
        wait_records: graph.waits.iter().map(wait_record_manifest).collect(),
        activation_records: graph.activations.iter().map(activation_record_manifest).collect(),
        trap_records: graph.traps.iter().map(trap_record_manifest).collect(),
        hostcall_trace: graph.hostcalls.iter().map(hostcall_trace_manifest).collect(),
        cleanup_transactions: graph
            .cleanup_transactions
            .iter()
            .map(cleanup_transaction_manifest)
            .collect(),
        tombstones: graph.tombstones.iter().map(tombstone_manifest).collect(),
        substrate_events: runtime_evidence_substrate_event_manifests(evidence),
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use substrate_api::{
        ArtifactAuthority, ArtifactImageRef, CodeObjectRef, CodePublisherAuthority,
        ConsoleAuthority, DmaAuthority, DmwAuthority, EventQueueAuthority, GuestMemoryAuthority,
        IrqAuthority, MmioAuthority, PublishedCodeRef, SnapshotAuthority, SubstrateResult,
        TimerAuthority,
    };
    use target_abi::{
        SectionKindV1, TargetArtifactHeaderV1, TargetSectionHeaderV1,
        canonical_zero_field_image_hash,
    };
    use visa_profile::SubstrateProfile;
    use visa_runtime::{
        VisaArtifactInput, VisaExecutionStep, VisaRuntime, VisaRuntimeConfig,
        VisaRuntimeEvidenceSnapshot, VisaSubstrateAuthorityExtractionEvidence,
        VisaSubstrateUnsupportedEvidence, personality,
    };
    use visa_wasmtime::WasmVisaExecutor;

    use super::*;

    const REQUIRED_SECTIONS: [SectionKindV1; 7] = [
        SectionKindV1::Manifest,
        SectionKindV1::CodeObject,
        SectionKindV1::HostcallImportTable,
        SectionKindV1::TrapMap,
        SectionKindV1::PcRangeTable,
        SectionKindV1::ProfileRequirements,
        SectionKindV1::Signature,
    ];

    #[derive(Default)]
    struct ProjectionSubstrate {
        loaded: Vec<ArtifactImageRef>,
        published: Vec<(ArtifactImageRef, CodeObjectRef)>,
        console: Vec<u8>,
    }

    impl ArtifactAuthority for ProjectionSubstrate {
        fn load_artifact_image(&mut self, artifact: ArtifactImageRef) -> SubstrateResult<()> {
            self.loaded.push(artifact);
            Ok(())
        }
    }

    impl CodePublisherAuthority for ProjectionSubstrate {
        fn publish_code(
            &mut self,
            artifact: ArtifactImageRef,
            code: CodeObjectRef,
        ) -> SubstrateResult<PublishedCodeRef> {
            self.published.push((artifact, code));
            Ok(PublishedCodeRef::new(code.id, code.generation))
        }
    }

    impl ConsoleAuthority for ProjectionSubstrate {
        fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
            self.console.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    impl TimerAuthority for ProjectionSubstrate {}
    impl EventQueueAuthority for ProjectionSubstrate {}
    impl GuestMemoryAuthority for ProjectionSubstrate {}
    impl DmwAuthority for ProjectionSubstrate {}
    impl MmioAuthority for ProjectionSubstrate {}
    impl DmaAuthority for ProjectionSubstrate {}
    impl IrqAuthority for ProjectionSubstrate {}
    impl SnapshotAuthority for ProjectionSubstrate {}

    #[test]
    fn runtime_evidence_target_runtime_manifest_bundle_projects_package_ready_records() {
        let mut image = TargetArtifactImage::new(
            29,
            "native-visa",
            "native-visa-artifact",
            "visa-native-workload",
            "snapshot-replay",
            "artifact-hash",
            "abi-fingerprint",
            "manifest-binding",
            "code-hash",
            TargetMemoryPlan::new(4, 2, 16),
        );
        image.imports.push("visa.hostcall_1".to_owned());
        image.exports.push("visa_start".to_owned());

        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image).expect("verify artifact");
        let store = StoreRecord {
            id: 7,
            package: "native-visa".to_owned(),
            artifact: "native-visa-artifact".to_owned(),
            role: "visa-native-workload".to_owned(),
            fault_policy: "restartable".to_owned(),
            fault_domain: 3,
            resource: None,
            state: StoreState::Running,
            generation: 5,
            restart_count: 2,
        };
        let evidence = VisaRuntimeEvidenceSnapshot {
            contract_graph: semantic_core::ContractGraphSnapshot {
                artifacts: vec![verified],
                stores: vec![store],
                ..Default::default()
            },
            event_log_cursor: 11,
            runtime_events: Vec::new(),
            authority_extractions: vec![VisaSubstrateAuthorityExtractionEvidence {
                event_id: 9,
                event_epoch: 4,
                authority: "DmaAuthority".to_owned(),
                operation: "dma_alloc".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(7),
                capability_id: Some(13),
                capability_generation: Some(2),
            }],
            unsupported_substrate_events: vec![VisaSubstrateUnsupportedEvidence {
                event_id: 8,
                event_epoch: 3,
                authority: "ConsoleAuthority".to_owned(),
                operation: "console_write".to_owned(),
                requester: Some("native-visa".to_owned()),
                artifact_id: Some(29),
                store_id: Some(7),
            }],
        };

        let bundle = runtime_evidence_target_runtime_manifests(&evidence);

        assert_eq!(bundle.target_artifacts.len(), 1);
        assert_eq!(bundle.target_artifacts[0].id, 29);
        assert_eq!(bundle.target_artifacts[0].imports, vec![String::from("visa.hostcall_1")]);
        assert_eq!(bundle.target_artifacts[0].exports, vec![String::from("visa_start")]);
        assert_eq!(bundle.store_records.len(), 1);
        assert_eq!(bundle.store_records[0].id, 7);
        assert_eq!(bundle.store_records[0].state, "running");
        assert_eq!(bundle.store_records[0].generation, 5);
        assert_eq!(bundle.substrate_events.len(), 2);
        assert_eq!(bundle.substrate_events[0].event_kind, "unsupported");
        assert_eq!(bundle.substrate_events[0].id, 8);
        assert_eq!(bundle.substrate_events[1].event_kind, "authority-extracted");
        assert_eq!(bundle.substrate_events[1].capability.as_ref().map(|cap| cap.id), Some(13));
    }

    #[test]
    fn runtime_evidence_bundle_consumes_real_runtime_snapshot() {
        let personality = personality::native::VisaNativePersonality::new(
            "native-visa",
            SubstrateProfile::MinimalBareMetal,
        );
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let mut substrate = ProjectionSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(41) },
                ActivationEntry::Symbol("visa_start".into()),
                [VisaExecutionStep::new(
                    personality::native::VISA_CONSOLE_WRITE,
                    personality.console_write(b"bundle"),
                )],
                &mut substrate,
            )
            .expect("run native vISA runtime path");

        let evidence = runtime.evidence_snapshot();
        let bundle = runtime_evidence_target_runtime_manifests(&evidence);

        assert_eq!(substrate.console, b"bundle");
        assert_eq!(bundle.target_artifacts.len(), 1);
        assert_eq!(bundle.code_objects.len(), 1);
        assert_eq!(bundle.store_records.len(), 1);
        assert!(!bundle.capability_records.is_empty());
        assert_eq!(bundle.activation_records.len(), 1);
        assert_eq!(bundle.hostcall_trace.len(), 1);
        assert_eq!(bundle.substrate_events.len(), 1);
        assert_eq!(bundle.target_artifacts[0].id, report.loaded.artifact_id);
        assert_eq!(bundle.code_objects[0].id, report.loaded.code_object_id);
        assert_eq!(bundle.code_objects[0].artifact_id, report.loaded.artifact_id);
        assert_eq!(bundle.code_objects[0].bound_store, Some(report.loaded.store_id));
        assert_eq!(bundle.store_records[0].id, report.loaded.store_id);
        assert_eq!(bundle.activation_records[0].id, report.activation.activation_id);
        assert_eq!(bundle.activation_records[0].store, report.loaded.store_id);
        assert_eq!(bundle.hostcall_trace[0].activation, report.activation.activation_id);
        assert_eq!(bundle.hostcall_trace[0].artifact, report.loaded.artifact_id);
        assert_eq!(bundle.hostcall_trace[0].name, "visa.console.write");
        assert_eq!(bundle.hostcall_trace[0].result, "complete");
        assert_eq!(bundle.hostcall_trace[0].subject, "native-visa");
        assert_eq!(bundle.substrate_events[0].event_kind, "authority-extracted");
        assert_eq!(bundle.substrate_events[0].authority, "ConsoleAuthority");
        assert_eq!(bundle.substrate_events[0].operation, "console_write");
        assert_eq!(
            bundle.substrate_events[0].requester.as_deref(),
            Some(bundle.hostcall_trace[0].subject.as_str())
        );
        assert_eq!(bundle.substrate_events[0].artifact, Some(report.loaded.artifact_id));
        assert_eq!(bundle.substrate_events[0].store, Some(report.loaded.store_id));

        let target_v1 = TargetExecutorV1Report {
            target_artifacts: bundle.target_artifacts.clone(),
            code_objects: bundle.code_objects.clone(),
            store_records: bundle.store_records.clone(),
            capability_records: bundle.capability_records.clone(),
            wait_records: bundle.wait_records.clone(),
            activation_records: bundle.activation_records.clone(),
            trap_records: bundle.trap_records.clone(),
            hostcall_trace: bundle.hostcall_trace.clone(),
            cleanup_transactions: bundle.cleanup_transactions.clone(),
            tombstones: bundle.tombstones.clone(),
            substrate_events: bundle.substrate_events.clone(),
            snapshot_validation: runtime_evidence_validation_report("snapshot-barrier"),
            replay_validation: runtime_evidence_validation_report("package-replay"),
            ..Default::default()
        };
        let manifest = runtime_evidence_test_manifest();
        let mut package = demo_migration_package(&manifest, runtime.semantic(), &target_v1);
        package.target.arch_requirement = "riscv64".to_owned();
        package.required_artifact_profile.target_arch = "riscv64".to_owned();
        package.substrate_boundary.native_state_policy =
            contract_validate::REAL_TARGET_SUBSTRATE_POLICY.to_owned();

        let audit = contract_validate::audit_migration_package(&package);

        assert!(audit.ok(), "{:#?}", audit.findings);
        assert!(audit.portable_artifact_execution_claim);
        assert!(audit.visa_native_portable_artifact_execution_claim);
        assert!(audit.real_target_substrate_claim);
        assert_eq!(audit.linked_authority_extraction_event_count, 1);
        validate_external_audit(&package).expect("runtime evidence package should pass audit gate");
    }

    #[test]
    fn wasmtime_runtime_evidence_package_passes_external_audit() {
        let personality = personality::native::VisaNativePersonality::new(
            "native-visa",
            SubstrateProfile::MinimalBareMetal,
        );
        let runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let substrate = ProjectionSubstrate::default();
        let wasm = visa_native_console_wasm();
        let artifact = fake_wasm_image(&REQUIRED_SECTIONS, &wasm);
        let mut executor = WasmVisaExecutor::new(runtime, Box::new(substrate));

        let report = executor
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(51) },
                "visa_start",
            )
            .expect("run wasmtime vISA artifact");

        let evidence = executor.runtime().evidence_snapshot();
        let bundle = runtime_evidence_target_runtime_manifests(&evidence);

        assert_eq!(report.hostcalls.len(), 1);
        assert_eq!(bundle.target_artifacts.len(), 1);
        assert_eq!(bundle.target_artifacts[0].id, report.activation.artifact_id);
        assert_eq!(bundle.target_artifacts[0].payload_len, wasm.len());
        assert_eq!(bundle.activation_records.len(), 1);
        assert_eq!(bundle.hostcall_trace.len(), 1);
        assert_eq!(bundle.hostcall_trace[0].subject, "native-visa");
        assert_eq!(bundle.substrate_events.len(), 1);
        assert_eq!(bundle.substrate_events[0].event_kind, "authority-extracted");
        assert_eq!(
            bundle.substrate_events[0].requester.as_deref(),
            Some(bundle.hostcall_trace[0].subject.as_str())
        );

        let target_v1 = TargetExecutorV1Report {
            target_artifacts: bundle.target_artifacts.clone(),
            code_objects: bundle.code_objects.clone(),
            store_records: bundle.store_records.clone(),
            capability_records: bundle.capability_records.clone(),
            wait_records: bundle.wait_records.clone(),
            activation_records: bundle.activation_records.clone(),
            trap_records: bundle.trap_records.clone(),
            hostcall_trace: bundle.hostcall_trace.clone(),
            cleanup_transactions: bundle.cleanup_transactions.clone(),
            tombstones: bundle.tombstones.clone(),
            substrate_events: bundle.substrate_events.clone(),
            snapshot_validation: runtime_evidence_validation_report("snapshot-barrier"),
            replay_validation: runtime_evidence_validation_report("package-replay"),
            ..Default::default()
        };
        let manifest = runtime_evidence_test_manifest();
        let mut package =
            demo_migration_package(&manifest, executor.runtime().semantic(), &target_v1);
        package.target.arch_requirement = "riscv64".to_owned();
        package.required_artifact_profile.target_arch = "riscv64".to_owned();
        package.substrate_boundary.native_state_policy =
            contract_validate::REAL_TARGET_SUBSTRATE_POLICY.to_owned();

        let audit = contract_validate::audit_migration_package(&package);

        assert!(audit.ok(), "{:#?}", audit.findings);
        assert!(audit.portable_artifact_execution_claim);
        assert!(audit.visa_native_portable_artifact_execution_claim);
        assert!(audit.real_target_substrate_claim);
        assert_eq!(audit.linked_authority_extraction_event_count, 1);
        validate_external_audit(&package)
            .expect("wasmtime runtime evidence package should pass audit gate");
    }

    fn visa_native_console_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (import "visa" "hostcall_1" (func $console_write (param i64 i64 i64 i64 i64 i64) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 16) "native-vISA")
  (func (export "visa_start") (result i64)
    i64.const 16
    i64.const 11
    i64.const 0
    i64.const 0
    i64.const 0
    i64.const 0
    call $console_write
  )
)"#,
        )
        .expect("parse wat")
    }

    fn runtime_evidence_validation_report(
        validator: &str,
    ) -> artifact_manifest::BoundaryValidationReportManifest {
        artifact_manifest::BoundaryValidationReportManifest {
            validator: validator.to_owned(),
            evidence_boundary: "real-target-substrate".to_owned(),
            ok: true,
            violation_count: 0,
            violations: Vec::new(),
        }
    }

    fn runtime_evidence_test_manifest() -> artifact_manifest::ArtifactBundleManifest {
        artifact_manifest::ArtifactBundleManifest {
            schema_version: 1,
            artifact_profile: "minimal-bare-metal".to_owned(),
            runtime_mode: "research".to_owned(),
            contract: artifact_manifest::SupervisorContractManifest::default(),
            target: artifact_manifest::TargetManifest {
                arch: "riscv64".to_owned(),
                machine_abi_version: "test-machine-abi".to_owned(),
                supervisor_abi_version: "test-supervisor-abi".to_owned(),
                wasm_feature_profile: "test-wasm-profile".to_owned(),
                memory64: false,
                multi_memory: false,
                dmw_layout: "test-dmw-layout".to_owned(),
                linux_abi_profile: "none".to_owned(),
                artifact_signature_profile: "test-signature-profile".to_owned(),
                network_contract_version: "test-network-contract".to_owned(),
            },
            compiler: artifact_manifest::CompilerManifest {
                engine: "test-engine".to_owned(),
                engine_version: "test-version".to_owned(),
                execution_mode: "test-execution".to_owned(),
                artifact_format: "target-artifact-image-v1".to_owned(),
                target_artifact_format: "target-artifact-image-v1".to_owned(),
                runtime_executor_abi: "test-runtime-executor-abi".to_owned(),
            },
            modules: Vec::new(),
        }
    }

    fn fake_image(kinds: &[SectionKindV1]) -> Vec<u8> {
        let header_len = core::mem::size_of::<TargetArtifactHeaderV1>();
        let section_len = core::mem::size_of::<TargetSectionHeaderV1>();
        let payload_len = 16;
        let section_table_len = kinds.len() * section_len;
        let payload_base = header_len + section_table_len;
        let image_len = payload_base + kinds.len() * payload_len;
        let mut image = vec![0; image_len];

        let header = TargetArtifactHeaderV1::fake_riscv64(kinds.len() as u32, image_len as u64);
        header.write_to(&mut image).expect("header");

        for (index, kind) in kinds.iter().copied().enumerate() {
            let offset = payload_base + index * payload_len;
            image[offset..offset + payload_len].fill(kind as u32 as u8);
            let mut section =
                TargetSectionHeaderV1::new(kind, offset as u64, payload_len as u64, 1);
            section.hash = Sha256::digest(&image[offset..offset + payload_len]).into();
            let section_off = header_len + index * section_len;
            section.write_to(&mut image[section_off..section_off + section_len]).expect("section");
        }

        let mut header = TargetArtifactHeaderV1::parse(&image).expect("parse header");
        let (manifest_start, manifest_end) = section_payload_range(&image, SectionKindV1::Manifest);
        header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
        header.write_to(&mut image).expect("manifest hash");
        refresh_image_hash(&mut image);
        image
    }

    fn fake_wasm_image(kinds: &[SectionKindV1], code_payload: &[u8]) -> Vec<u8> {
        let header_len = core::mem::size_of::<TargetArtifactHeaderV1>();
        let section_len = core::mem::size_of::<TargetSectionHeaderV1>();
        let section_table_len = kinds.len() * section_len;
        let payload_base = header_len + section_table_len;
        let payload_lens = kinds
            .iter()
            .map(|kind| if *kind == SectionKindV1::CodeObject { code_payload.len() } else { 16 })
            .collect::<Vec<_>>();
        let image_len = payload_base + payload_lens.iter().sum::<usize>();
        let mut image = vec![0; image_len];

        let header = TargetArtifactHeaderV1::fake_riscv64(kinds.len() as u32, image_len as u64);
        header.write_to(&mut image).expect("header");

        let mut payload_offset = payload_base;
        for (index, kind) in kinds.iter().copied().enumerate() {
            let payload_len = payload_lens[index];
            let payload_range = payload_offset..payload_offset + payload_len;
            if kind == SectionKindV1::CodeObject {
                image[payload_range.clone()].copy_from_slice(code_payload);
            } else {
                image[payload_range.clone()].fill(kind as u32 as u8);
            }
            let mut section =
                TargetSectionHeaderV1::new(kind, payload_offset as u64, payload_len as u64, 1);
            section.hash = Sha256::digest(&image[payload_range]).into();
            let section_off = header_len + index * section_len;
            section.write_to(&mut image[section_off..section_off + section_len]).expect("section");
            payload_offset += payload_len;
        }

        let mut header = TargetArtifactHeaderV1::parse(&image).expect("parse header");
        let (manifest_start, manifest_end) = section_payload_range(&image, SectionKindV1::Manifest);
        header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
        header.write_to(&mut image).expect("manifest hash");
        refresh_image_hash(&mut image);
        image
    }

    fn section_payload_range(image: &[u8], kind: SectionKindV1) -> (usize, usize) {
        let header = TargetArtifactHeaderV1::parse(image).expect("header");
        let section_len = core::mem::size_of::<TargetSectionHeaderV1>();
        for index in 0..header.section_count as usize {
            let section_off = core::mem::size_of::<TargetArtifactHeaderV1>() + index * section_len;
            let section =
                TargetSectionHeaderV1::parse(&image[section_off..section_off + section_len])
                    .expect("section");
            if section.kind == kind {
                let start = section.offset as usize;
                return (start, start + section.len as usize);
            }
        }
        panic!("missing section")
    }

    fn refresh_image_hash(image: &mut [u8]) {
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = [0; 32];
        header.write_to(image).expect("zero image hash");
        let hash = canonical_zero_field_image_hash(image).expect("canonical hash");
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = hash;
        header.write_to(image).expect("image hash");
    }
}
