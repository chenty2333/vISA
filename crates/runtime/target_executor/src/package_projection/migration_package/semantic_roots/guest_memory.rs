use super::*;

pub(super) fn push_guest_memory_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.guest_address_space_roots = semantic
        .guest_address_spaces()
        .iter()
        .map(|aspace| {
            let root_region = aspace
                .root_region
                .map(|region| region.object_ref().summary())
                .unwrap_or_else(|| "none".to_owned());
            format!(
                "guest-address-space id={} owner={} state={} root_region={} vma_generation={} page_map_generation={} generation={}",
                aspace.aspace.id(),
                aspace.owner.summary(),
                aspace.state.as_str(),
                root_region,
                aspace.vma_generation,
                aspace.page_map_generation,
                aspace.generation
            )
        })
        .collect();
    roots.vma_region_roots = semantic
        .vma_regions()
        .iter()
        .map(|region| {
            format!(
                "vma-region id={} aspace={} start={} len={} perms={}{}{} flags=cow:{};shared:{};device:{} backing={} state={} generation={}",
                region.region.id(),
                region.aspace.object_ref().summary(),
                region.range.start,
                region.range.len,
                if region.perms.contains(semantic_core::GuestPerms::READ) { "r" } else { "-" },
                if region.perms.contains(semantic_core::GuestPerms::WRITE) { "w" } else { "-" },
                if region.perms.contains(semantic_core::GuestPerms::EXEC) { "x" } else { "-" },
                region.flags.cow,
                region.flags.shared,
                region.flags.device,
                region.backing.object_ref().summary(),
                region.state.as_str(),
                region.generation
            )
        })
        .collect();
    roots.page_object_roots = semantic
        .page_objects()
        .iter()
        .map(|page| {
            format!(
                "page-object id={} backing={} cow={} dirty_generation={} state={} generation={}",
                page.page.id(),
                page.backing.as_str(),
                page.cow.as_str(),
                page.dirty_generation,
                page.state.as_str(),
                page.generation
            )
        })
        .collect();
    roots.guest_memory_fault_roots = semantic
        .guest_memory_faults()
        .iter()
        .map(|fault| {
            format!(
                "page-fault-event id={} page={} reason={} historical={} generation={}",
                fault.id,
                fault.page.object_ref().summary(),
                fault.reason,
                fault.historical,
                fault.generation
            )
        })
        .collect();
}
