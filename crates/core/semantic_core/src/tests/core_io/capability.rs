use super::*;

pub(in crate::tests) fn handle_for(record: &CapabilityRecord, rights: &[&str]) -> CapabilityHandle {
    record
        .store_local_handle(rights.iter().map(|right| (*right).to_string()).collect())
        .expect("capability record has store-local handle")
}

#[test]
pub(super) fn capability_attenuation_cannot_expand_rights() {
    let mut ledger = CapabilityLedger::new();
    let parent = ledger.grant("driver", "mmio-bar0", &["read"], "store").expect("test grant");

    assert!(ledger.attenuate(parent, "helper", &["read"], "activation").is_some());
    let helper = ledger.check("helper", "mmio-bar0", "read").expect("attenuated capability");
    assert_eq!(helper.source, "attenuated");
    assert!(ledger.attenuate(parent, "helper", &["write"], "activation").is_none());
}

#[test]
pub(super) fn capability_authority_uses_object_ref_not_debug_label() {
    let mut ledger = CapabilityLedger::new();
    let cap = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");
    let record =
        ledger.records().iter().find(|record| record.id == cap).expect("capability record");
    let object_ref = record.object_ref.expect("authority object ref");
    let handle = handle_for(record, &["map"]);
    assert!(ledger.check_authority("driver", object_ref, "map", Some(&handle)).is_ok());

    let mut debug_only = CapabilityLedger::new();
    debug_only.grant_debug_label_only_for_test("driver", "mmio.virtio-net", &["map"], "store");
    assert_eq!(
        debug_only.check("driver", "mmio.virtio-net", "map"),
        Err(CapabilityDenyReason::Missing)
    );

    let mut wrong_object = CapabilityLedger::new();
    let different_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let wrong_cap = wrong_object
        .grant_with_authority_ref(
            "driver",
            "mmio.virtio-net",
            different_ref,
            &["map"],
            "store",
            Some(1),
            Some(1),
            None,
            "manifest",
            true,
        )
        .expect("test grant");
    let wrong_record = wrong_object
        .records()
        .iter()
        .find(|record| record.id == wrong_cap)
        .expect("wrong capability record");
    let wrong_handle = handle_for(wrong_record, &["map"]);
    assert_eq!(
        wrong_object.check_authority("driver", object_ref, "map", Some(&wrong_handle)),
        Err(CapabilityDenyReason::ObjectMismatch)
    );
    assert_eq!(
        wrong_object.check_authority("driver", object_ref, "map", None),
        Err(CapabilityDenyReason::Missing)
    );
}

#[test]
pub(super) fn manifest_binding_does_not_overwrite_explicit_authority_ref_by_label() {
    let mut ledger = CapabilityLedger::new();
    let explicit_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let explicit_cap = ledger
        .grant_with_authority_ref(
            "driver",
            "mmio.virtio-net",
            explicit_ref,
            &["map"],
            "store",
            Some(1),
            Some(1),
            None,
            "explicit",
            true,
        )
        .expect("test grant");
    let manifest_cap = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");

    assert_ne!(explicit_cap, manifest_cap);
    let explicit_record = ledger
        .records()
        .iter()
        .find(|record| record.id == explicit_cap)
        .expect("explicit capability");
    assert_eq!(explicit_record.object_ref, Some(explicit_ref));
    assert_eq!(explicit_record.source, "explicit");
}

#[test]
pub(super) fn authority_binding_release_revokes_exact_granted_capability_not_same_label() {
    let mut graph = SemanticGraph::new();
    let manifest_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let manifest_cap = graph.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "mmio.virtio-net0",
        manifest_ref,
        &["read"],
        "store",
        "manifest-test",
        true,
    );
    let mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    let authority = graph
        .bind_authority_resource(mmio, "driver_virtio_net", "mmio.virtio-net0", &["read"], "store")
        .expect("authority binding");
    let binding_cap = graph.authority_bindings()[0].capability;
    assert_ne!(manifest_cap, binding_cap);

    assert!(graph.release_authority_binding(authority, "test release"));

    let manifest_record = graph.capabilities().record(manifest_cap).expect("manifest cap");
    let binding_record = graph.capabilities().record(binding_cap).expect("binding cap");
    assert!(!manifest_record.revoked);
    assert!(binding_record.revoked);
}

#[test]
pub(super) fn capability_grant_rejects_owner_store_without_generation() {
    let mut ledger = CapabilityLedger::new();
    assert_eq!(
        ledger.grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            None,
            None,
            "bad-test",
        ),
        Err(CapabilityGrantError::OwnerStoreGenerationRequired { owner_store: 1 })
    );
}

#[test]
pub(super) fn revoke_owner_store_matches_exact_generation_only() {
    let mut ledger = CapabilityLedger::new();
    let cap_gen_1 = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.gen1",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "test",
        )
        .expect("test grant");
    let cap_gen_2 = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.gen2",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(2),
            None,
            "test",
        )
        .expect("test grant");

    assert_eq!(ledger.revoke_owner_store(1, 1), {
        let mut revoked = Vec::new();
        revoked.push(cap_gen_1);
        revoked
    });
    assert!(ledger.record(cap_gen_1).expect("gen1").revoked);
    assert!(!ledger.record(cap_gen_2).expect("gen2").revoked);
}

#[test]
pub(super) fn capability_authority_rejects_stale_revoked_wrong_subject_and_undeclared_external() {
    let mut ledger = CapabilityLedger::new();
    let cap = ledger
        .grant_manifest_binding(
            "driver",
            "packet-device.net0",
            &["rx", "tx"],
            "store",
            CapabilityClass::PacketDevice,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");
    let record =
        ledger.records().iter().find(|record| record.id == cap).expect("capability record").clone();
    let object_ref = record.object_ref.expect("authority object ref");
    let mut stale_handle = handle_for(&record, &["rx"]);
    stale_handle.generation += 1;
    assert_eq!(
        ledger.check_authority("driver", object_ref, "rx", Some(&stale_handle)),
        Err(CapabilityDenyReason::GenerationMismatch)
    );
    let wrong_subject_handle = handle_for(&record, &["rx"]);
    assert_eq!(
        ledger.check_authority("other-driver", object_ref, "rx", Some(&wrong_subject_handle)),
        Err(CapabilityDenyReason::SubjectMismatch)
    );
    assert!(ledger.revoke(cap));
    assert_eq!(
        ledger.check_authority("driver", object_ref, "rx", None),
        Err(CapabilityDenyReason::Revoked)
    );

    let mut external = CapabilityLedger::new();
    let external_ref = AuthorityObjectRef::external(
        CapabilityClass::Device,
        ContractObjectRef::new(ContractObjectKind::ExternalObject, 7, 0),
    );
    external
        .grant_with_authority_ref(
            "driver",
            "device.pci0",
            external_ref,
            &["probe"],
            "store",
            Some(1),
            Some(1),
            None,
            "test",
            false,
        )
        .expect("test grant");
    assert_eq!(
        external.check_authority("driver", external_ref, "probe", None),
        Err(CapabilityDenyReason::ManifestDeclarationMissing)
    );
}
