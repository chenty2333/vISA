use super::*;

mod block_fs;
mod device_io;
mod guest_memory;
mod integrated;
mod lifecycle_core;
mod network;
mod scheduler;
mod simd_display;
mod target_runtime;

pub(crate) fn semantic_roots(
    capabilities: &[MigrationCapabilityManifest],
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> SemanticRootSetManifest {
    let mut roots = SemanticRootSetManifest::default();
    scheduler::push_scheduler_roots(&mut roots, semantic, capabilities, target_v1);
    integrated::push_integrated_roots(&mut roots, semantic, capabilities, target_v1);
    device_io::push_device_io_roots(&mut roots, semantic, capabilities, target_v1);
    network::push_network_roots(&mut roots, semantic, capabilities, target_v1);
    guest_memory::push_guest_memory_roots(&mut roots, semantic, capabilities, target_v1);
    block_fs::push_block_fs_roots(&mut roots, semantic, capabilities, target_v1);
    simd_display::push_simd_display_roots(&mut roots, semantic, capabilities, target_v1);
    lifecycle_core::push_lifecycle_core_roots(&mut roots, semantic, capabilities, target_v1);
    target_runtime::push_target_runtime_roots(&mut roots, semantic, capabilities, target_v1);
    roots
}
