use super::*;

pub(in crate::tests) fn setup_b11_block_page_object_graph() -> SemanticGraph {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
        "b11 existing dma buffer",
    ));
    graph
}

pub(in crate::tests) fn b11_aspace() -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, 1901, 1)
}

pub(in crate::tests) fn b11_vma_region() -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::VmaRegion, 1902, 1)
}

pub(in crate::tests) fn b11_page(id: u64) -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::PageObject, id, 1)
}

#[test]
pub(super) fn block_runtime_b11_page_object_integration_records_exact_refs() {
    let mut graph = setup_b11_block_page_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1835,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1903),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11 integrate block dma buffer with page object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_page_object_count(), 1);
    let page = &graph.block_page_objects()[0];
    assert_eq!(
        page.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockPageObject, 1835, 1)
    );
    assert_eq!(page.block_dma_buffer, 1834);
    assert_eq!(page.block_request, 1828);
    assert_eq!(page.block_completion, 1830);
    assert_eq!(page.dma_buffer, 1833);
    assert_eq!(page.aspace, b11_aspace());
    assert_eq!(page.vma_region, b11_vma_region());
    assert_eq!(page.page, b11_page(1903));
    assert_eq!(page.page_dirty_generation, 1);
    assert_eq!(page.page_backing, PageBacking::FileBacked);
    assert_eq!(page.cow_state, CowState::None);
    assert_eq!(page.page_state, PageObjectState::Live);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockPageObjectIntegrated block_page_object=1835 block_dma_buffer=1834@1 block_request=1828@1 block_completion=1830@1 dma_buffer=1833@1 block_device=1824@1 block_range=1825@1 aspace=guest-address-space:1901@1 vma_region=vma-region:1902@1 page=page-object:1903@1 page_dirty_generation=1 page_offset=0 byte_len=4096 operation=write generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b11_rejects_stale_dead_oversized_and_broken_page() {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b11 existing page integration",
    ));

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1836,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 2,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "stale dma buffer".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block page object dma buffer generation is missing or inactive".to_string()]
    );

    let dead_page = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1837,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Dead,
            page_offset: 0,
            byte_len: 4096,
            note: "dead page".to_string(),
        },
    ));
    assert_eq!(dead_page.status, CommandStatus::Rejected);
    assert_eq!(dead_page.violations, vec!["block page object page must be live".to_string()]);

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1838,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 1,
            byte_len: 4096,
            note: "oversized page range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(oversized.violations, vec!["block page object byte range exceeds page".to_string()]);

    let broken_cow = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1839,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::Broken,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "broken cow".to_string(),
        },
    ));
    assert_eq!(broken_cow.status, CommandStatus::Rejected);
    assert_eq!(
        broken_cow.violations,
        vec!["block page object COW break must be revalidated before IO".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b11_invariants_reject_page_generation_leak() {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b11 invariant page integration",
    ));
    graph.corrupt_block_page_object_page_generation_for_test(1835, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockPageObjectInvalid { block_page_object: 1835 })
    );
}

pub(in crate::tests) fn setup_b12_buffer_cache_graph() -> SemanticGraph {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b12 existing page integration",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b12_buffer_cache_records_page_and_block_range_contract() {
    let mut graph = setup_b12_buffer_cache_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1840,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 1,
            note: "b12 record dirty buffer cache entry".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.buffer_cache_object_count(), 1);
    let cache = &graph.buffer_cache_objects()[0];
    assert_eq!(
        cache.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BufferCacheObject, 1840, 1)
    );
    assert_eq!(cache.block_page_object, 1835);
    assert_eq!(cache.block_dma_buffer, 1834);
    assert_eq!(cache.block_device, 1824);
    assert_eq!(cache.block_range, 1825);
    assert_eq!(cache.page, b11_page(1903));
    assert_eq!(cache.page_dirty_generation, 1);
    assert_eq!(cache.cache_state, BufferCacheObjectState::Dirty);
    assert_eq!(cache.state, BufferCacheObjectState::Dirty);
    assert_eq!(cache.coherency_epoch, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BufferCacheObjectRecorded buffer_cache_object=1840 block_page_object=1835@1 block_dma_buffer=1834@1 block_device=1824@1 block_range=1825@1 aspace=guest-address-space:1901@1 vma_region=vma-region:1902@1 page=page-object:1903@1 page_dirty_generation=1 page_offset=0 block_offset=0 byte_len=4096 operation=write cache_state=dirty coherency_epoch=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b12_rejects_stale_wrong_duplicate_and_oversized_cache() {
    let mut graph = setup_b12_buffer_cache_graph();

    let stale_page = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1841,
            block_page_object: 1835,
            block_page_object_generation: 2,
            page: b11_page(1904),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 2,
            note: "stale page integration".to_string(),
        },
    ));
    assert_eq!(stale_page.status, CommandStatus::Rejected);
    assert_eq!(
        stale_page.violations,
        vec!["buffer cache object page integration generation is missing".to_string()]
    );

    let wrong_page = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1842,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1904),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 3,
            note: "wrong page".to_string(),
        },
    ));
    assert_eq!(wrong_page.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_page.violations,
        vec!["buffer cache object page ref does not match integration".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1843,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4097,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 4,
            note: "oversized cache range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["buffer cache object byte range exceeds integrated page".to_string()]
    );

    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b12 existing cache entry",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1844,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::WritebackPending,
            coherency_epoch: 5,
            note: "duplicate cache key".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["buffer cache object block range already cached".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b12_invariants_reject_cache_page_generation_leak() {
    let mut graph = setup_b12_buffer_cache_graph();
    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b12 invariant cache entry",
    ));
    graph.corrupt_buffer_cache_object_page_generation_for_test(1840, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BufferCacheObjectInvalid { buffer_cache_object: 1840 })
    );
}
