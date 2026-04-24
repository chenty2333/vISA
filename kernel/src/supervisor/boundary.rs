use semantic_core::{BoundaryKind, BoundaryStatus, SemanticGraph};

use super::artifacts::ArtifactLoadPlan;
use super::engine::{ExecutorLoadPlan, ExecutorTableState};

pub(super) fn publish_boot_boundaries(
    graph: &mut SemanticGraph,
    load_plan: &ArtifactLoadPlan,
    executor_plan: &ExecutorLoadPlan,
) {
    graph.publish_boundary(
        "artifact-loader",
        BoundaryKind::ArtifactLoader,
        BoundaryStatus::ManifestBacked,
        load_plan.artifact_profile,
        Some("target-cwasm-loader"),
    );
    graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::RuntimeContract,
        executor_plan.profile.runtime_executor_abi,
        Some("code-publish-not-linked"),
    );
    graph.publish_boundary(
        "hostcall-table",
        BoundaryKind::HostcallTable,
        hostcall_table_status(executor_plan),
        executor_plan.profile.runtime_executor_abi,
        Some("hostcall-trampoline-not-linked"),
    );
    graph.publish_boundary(
        "dmw",
        BoundaryKind::Dmw,
        BoundaryStatus::Logical,
        "logical-activation-lease",
        Some("real-mmu-window"),
    );
    graph.publish_boundary(
        "dma",
        BoundaryKind::Dma,
        BoundaryStatus::SemanticResource,
        "fake-substrate-dma",
        Some("dma-iommu"),
    );
    graph.publish_boundary(
        "mmio",
        BoundaryKind::Mmio,
        BoundaryStatus::SemanticResource,
        "fake-substrate-mmio",
        Some("device-mmio-map"),
    );
    graph.publish_boundary(
        "irq",
        BoundaryKind::Irq,
        BoundaryStatus::SemanticResource,
        "fake-substrate-irq",
        Some("real-irq-top-half"),
    );
    graph.publish_boundary(
        "packet-device",
        BoundaryKind::PacketDevice,
        BoundaryStatus::Toy,
        "toy-packet-queue",
        Some("virtio-net-mmio-dma-irq"),
    );
    graph.publish_boundary(
        "network-stack",
        BoundaryKind::NetworkStack,
        BoundaryStatus::Toy,
        "toy-net-core",
        Some("smoltcp-contract"),
    );
    graph.publish_boundary(
        "target-executor",
        BoundaryKind::TargetExecutor,
        BoundaryStatus::HostSide,
        "wasmtime-host-validator",
        Some("bare-metal-cwasm-loader"),
    );
    graph.publish_boundary(
        "fastpath",
        BoundaryKind::FastPath,
        BoundaryStatus::EventOnly,
        "semantic-event",
        Some("substrate-fastpath-codegen"),
    );
    graph.publish_boundary(
        "snapshot-replay",
        BoundaryKind::SnapshotReplay,
        BoundaryStatus::PackageOnly,
        "semantic-package-v1",
        Some("cow-nondeterminism-replay-runner"),
    );
    graph.publish_boundary(
        "store-lifecycle",
        BoundaryKind::StoreLifecycle,
        BoundaryStatus::ManagerOwned,
        "StoreManager-v2",
        None,
    );
    graph.publish_boundary(
        "authority-plane",
        BoundaryKind::AuthorityPlane,
        BoundaryStatus::LifecycleObject,
        "AuthorityPlane-v1",
        Some("real-mmio-dma-irq-substrate"),
    );
}

pub(super) fn publish_code_published_boundary(
    graph: &mut SemanticGraph,
    runtime_executor_abi: &'static str,
) {
    graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::CodePublished,
        runtime_executor_abi,
        Some("target-code-publish-stub"),
    );
}

pub(super) fn publish_hostcalls_linked_boundary(
    graph: &mut SemanticGraph,
    runtime_executor_abi: &'static str,
) {
    graph.publish_boundary(
        "hostcall-table",
        BoundaryKind::HostcallTable,
        BoundaryStatus::HostcallsLinked,
        runtime_executor_abi,
        Some("hostcall-trampoline-stub"),
    );
}

pub(super) fn publish_runnable_blocked_boundary(
    graph: &mut SemanticGraph,
    runtime_executor_abi: &'static str,
) {
    graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::Runnable,
        runtime_executor_abi,
        Some("target-entry-trampoline-not-linked"),
    );
}

fn hostcall_table_status(executor_plan: &ExecutorLoadPlan) -> BoundaryStatus {
    if executor_plan
        .stores()
        .iter()
        .any(|store| store.hostcall_table.state == ExecutorTableState::Bound)
    {
        BoundaryStatus::RuntimeContract
    } else {
        BoundaryStatus::NotLinked
    }
}
