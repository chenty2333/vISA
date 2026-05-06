use super::*;

mod block_fs;
mod device_runtime;
mod integrated;
mod network;
mod scheduler;
mod simd_display;

pub(crate) fn history_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
    integrated::push_integrated_history_edges(package, &mut edges);
    block_fs::push_block_fs_history_edges(package, &mut edges);
    simd_display::push_simd_display_history_edges(package, &mut edges);
    network::push_network_history_edges(package, &mut edges);
    scheduler::push_scheduler_history_edges(package, &mut edges);
    device_runtime::push_device_runtime_history_edges(package, &mut edges);
    edges
}
