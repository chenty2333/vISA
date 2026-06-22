use super::*;

#[test]
fn semantic_roots_reject_guest_address_space_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.guest_address_space_count = 1;
    package.semantic.guest_address_spaces.push(artifact_manifest::GuestAddressSpaceManifest {
        id: 70,
        owner: artifact_manifest::ContractObjectRefManifest {
            kind: "store".to_owned(),
            id: 1,
            generation: 1,
        },
        generation: 1,
        state: "live".to_owned(),
        root_region: None,
        vma_generation: 1,
        page_map_generation: 1,
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "guest address space root/count mismatch");
}

#[test]
fn semantic_roots_reject_vma_region_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.vma_region_count = 1;
    package.semantic.vma_regions.push(artifact_manifest::VmaRegionManifest {
        id: 71,
        aspace: artifact_manifest::ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 70,
            generation: 1,
        },
        range: artifact_manifest::GuestVaRangeManifest { start: 0x4000, len: 0x1000 },
        perms: artifact_manifest::GuestPermsManifest {
            readable: true,
            writable: true,
            executable: false,
        },
        flags: artifact_manifest::VmaFlagsManifest { cow: false, shared: false, device: false },
        backing: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        generation: 1,
        state: "mapped".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "vma region root/count mismatch");
}

#[test]
fn semantic_roots_reject_page_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.page_object_count = 1;
    package.semantic.page_objects.push(artifact_manifest::PageObjectManifest {
        id: 72,
        backing: "anonymous".to_owned(),
        cow: "none".to_owned(),
        dirty_generation: 1,
        generation: 1,
        state: "live".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "page object root/count mismatch");
}

#[test]
fn semantic_roots_reject_guest_memory_fault_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.guest_memory_fault_count = 1;
    package.semantic.guest_memory_faults.push(artifact_manifest::GuestMemoryFaultManifest {
        id: 73,
        generation: 1,
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        reason: "copyin-efault".to_owned(),
        historical: true,
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "guest memory fault root/count mismatch");
}
