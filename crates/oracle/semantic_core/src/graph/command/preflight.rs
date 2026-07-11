use super::*;

mod block;
mod integrated;
mod io;
mod lifecycle;
mod network;
mod scheduler;
mod simd_display;
mod storage;

impl SemanticGraph {
    pub(super) fn preflight_command(&self, command: &SemanticCommand) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RegisterHart { .. }
            | SemanticCommand::SetHartState { .. }
            | SemanticCommand::BindHartCurrentActivation { .. }
            | SemanticCommand::ClearHartCurrentActivation { .. }
            | SemanticCommand::CreateRuntimeActivation { .. }
            | SemanticCommand::CreateRunnableQueue { .. }
            | SemanticCommand::BindRunnableQueueOwner { .. }
            | SemanticCommand::EnqueueRunnable { .. }
            | SemanticCommand::DequeueRunnable { .. }
            | SemanticCommand::CreateActivationContext { .. }
            | SemanticCommand::UpdateActivationContextVectorState { .. }
            | SemanticCommand::EnableLazyVectorState { .. }
            | SemanticCommand::CaptureSavedContext { .. }
            | SemanticCommand::SavePreemptedContext { .. }
            | SemanticCommand::SaveDirtyVectorStateOnPreempt { .. }
            | SemanticCommand::RecordTimerInterrupt { .. }
            | SemanticCommand::RecordIpiEvent { .. }
            | SemanticCommand::RemotePreemptActivation { .. }
            | SemanticCommand::RemoteParkHart { .. }
            | SemanticCommand::PreemptActivation { .. }
            | SemanticCommand::RecordSchedulerDecision { .. }
            | SemanticCommand::RecordCrossHartSchedulerDecision { .. }
            | SemanticCommand::MigrateRunnableActivation { .. }
            | SemanticCommand::RecordSmpSafePoint { .. }
            | SemanticCommand::CompleteStopTheWorldRendezvous { .. }
            | SemanticCommand::ValidateSmpCodePublishBarrier { .. }
            | SemanticCommand::ValidateSmpCleanupQuiescence { .. }
            | SemanticCommand::ValidateSmpSnapshotBarrier { .. }
            | SemanticCommand::RecordSmpStressRun { .. }
            | SemanticCommand::RecordSmpScalingBenchmark { .. } => {
                self.preflight_scheduler_command(command)
            }
            SemanticCommand::RecordIntegratedSmpPreemptionCleanup { .. }
            | SemanticCommand::RecordIntegratedSmpNetworkFault { .. }
            | SemanticCommand::RecordIntegratedDiskPreemptFault { .. }
            | SemanticCommand::RecordIntegratedSimdMigration { .. }
            | SemanticCommand::RecordIntegratedNetworkDiskIo { .. }
            | SemanticCommand::RecordIntegratedDisplaySchedulerLoad { .. }
            | SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier { .. }
            | SemanticCommand::RecordIntegratedCodePublishSmpWorkload { .. }
            | SemanticCommand::RecordIntegratedDisplayPanic { .. }
            | SemanticCommand::RecordIntegratedOsctlTraceReplay { .. } => {
                self.preflight_integrated_command(command)
            }
            SemanticCommand::RecordDeviceObject { .. }
            | SemanticCommand::RecordPacketDeviceObject { .. }
            | SemanticCommand::RecordPacketBufferObject { .. }
            | SemanticCommand::RecordPacketQueueObject { .. }
            | SemanticCommand::RecordPacketDescriptorObject { .. }
            | SemanticCommand::RecordFakeNetBackendObject { .. }
            | SemanticCommand::RecordFakeBlockBackendObject { .. }
            | SemanticCommand::RecordVirtioBlkBackendObject { .. }
            | SemanticCommand::RecordBlockReadPath { .. }
            | SemanticCommand::RecordBlockWritePath { .. }
            | SemanticCommand::RecordBlockRequestQueue { .. }
            | SemanticCommand::RecordBlockDmaBuffer { .. }
            | SemanticCommand::RecordBlockPageObject { .. }
            | SemanticCommand::RecordBufferCacheObject { .. }
            | SemanticCommand::RecordFileObject { .. }
            | SemanticCommand::RecordDirectoryObject { .. }
            | SemanticCommand::RecordFatAdapterObject { .. }
            | SemanticCommand::RecordExt4AdapterObject { .. }
            | SemanticCommand::RecordFileHandleCapability { .. }
            | SemanticCommand::RecordFsWait { .. }
            | SemanticCommand::ResolveFsWait { .. }
            | SemanticCommand::CancelFsWait { .. }
            | SemanticCommand::CleanupBlockDriver { .. } => self.preflight_storage_command(command),
            SemanticCommand::RecordVirtioNetBackendObject { .. }
            | SemanticCommand::RecordNetworkRxInterrupt { .. }
            | SemanticCommand::ResolveNetworkRxWait { .. }
            | SemanticCommand::RecordNetworkTxCapabilityGate { .. }
            | SemanticCommand::RecordNetworkTxCompletion { .. }
            | SemanticCommand::RecordNetworkStackAdapter { .. }
            | SemanticCommand::RecordSocketObject { .. }
            | SemanticCommand::RecordEndpointObject { .. }
            | SemanticCommand::BindSocketEndpoint { .. }
            | SemanticCommand::ListenSocketEndpoint { .. }
            | SemanticCommand::ConnectSocketEndpoint { .. }
            | SemanticCommand::SendSocket { .. }
            | SemanticCommand::RecvSocket { .. }
            | SemanticCommand::RecordSocketWait { .. }
            | SemanticCommand::ResolveSocketWait { .. }
            | SemanticCommand::CancelSocketWait { .. }
            | SemanticCommand::RecordNetworkBackpressure { .. }
            | SemanticCommand::CleanupNetworkDriver { .. }
            | SemanticCommand::RecordNetworkGenerationAudit { .. }
            | SemanticCommand::RecordNetworkFaultInjection { .. }
            | SemanticCommand::RecordNetworkBenchmark { .. }
            | SemanticCommand::RecordNetworkRecoveryBenchmark { .. } => {
                self.preflight_network_command(command)
            }
            SemanticCommand::RecordBlockDeviceObject { .. }
            | SemanticCommand::RecordBlockRangeObject { .. }
            | SemanticCommand::RecordBlockRequestObject { .. }
            | SemanticCommand::RecordBlockCompletionObject { .. }
            | SemanticCommand::RecordBlockWait { .. }
            | SemanticCommand::ResolveBlockWait { .. }
            | SemanticCommand::CancelBlockWait { .. }
            | SemanticCommand::ApplyBlockPendingIoPolicy { .. }
            | SemanticCommand::RecordBlockRequestGenerationAudit { .. }
            | SemanticCommand::RecordBlockBenchmark { .. }
            | SemanticCommand::RecordBlockRecoveryBenchmark { .. } => {
                self.preflight_block_command(command)
            }
            SemanticCommand::RecordTargetFeatureSet { .. }
            | SemanticCommand::RecordVectorState { .. }
            | SemanticCommand::RecordSimdFaultInjection { .. }
            | SemanticCommand::RecordSimdBenchmark { .. }
            | SemanticCommand::RecordSimdContextSwitchBenchmark { .. }
            | SemanticCommand::RecordFramebufferObject { .. }
            | SemanticCommand::RecordDisplayObject { .. }
            | SemanticCommand::RecordDisplayCapability { .. }
            | SemanticCommand::RecordFramebufferWindowLease { .. }
            | SemanticCommand::RecordFramebufferMapping { .. }
            | SemanticCommand::RecordFramebufferWrite { .. }
            | SemanticCommand::RecordFramebufferFlushRegion { .. }
            | SemanticCommand::RecordFramebufferDirtyRegion { .. }
            | SemanticCommand::RecordDisplayEventLog { .. }
            | SemanticCommand::CleanupDisplay { .. }
            | SemanticCommand::ValidateDisplaySnapshotBarrier { .. }
            | SemanticCommand::RecordDisplayPanicLastFrame { .. }
            | SemanticCommand::RecordFramebufferBenchmark { .. } => {
                self.preflight_simd_display_command(command)
            }
            SemanticCommand::RecordQueueObject { .. }
            | SemanticCommand::RecordDescriptorObject { .. }
            | SemanticCommand::RecordDmaBufferObject { .. }
            | SemanticCommand::RecordMmioRegionObject { .. }
            | SemanticCommand::RecordIrqLineObject { .. }
            | SemanticCommand::RecordIrqEvent { .. }
            | SemanticCommand::RecordDeviceCapability { .. }
            | SemanticCommand::BindDriverStore { .. }
            | SemanticCommand::RecordIoWait { .. }
            | SemanticCommand::ResolveIoWait { .. }
            | SemanticCommand::CancelIoWait { .. }
            | SemanticCommand::CleanupIoDriver { .. }
            | SemanticCommand::InjectIoFault { .. }
            | SemanticCommand::ValidateIoRuntime { .. } => self.preflight_io_command(command),
            SemanticCommand::ResumeActivation { .. }
            | SemanticCommand::RecordPreemptionLatencySample { .. }
            | SemanticCommand::BlockActivationOnWait { .. }
            | SemanticCommand::CancelActivationWait { .. }
            | SemanticCommand::CleanupActivationForStoreFault { .. }
            | SemanticCommand::GrantCapability { .. }
            | SemanticCommand::RevokeCapability { .. }
            | SemanticCommand::CreateWait { .. }
            | SemanticCommand::ResolveWait { .. }
            | SemanticCommand::CancelWait { .. }
            | SemanticCommand::BeginCleanup { .. }
            | SemanticCommand::ApplyCleanupStep { .. }
            | SemanticCommand::CommitCleanup { .. }
            | SemanticCommand::RecordTrap { .. } => self.preflight_lifecycle_command(command),
        }
    }
}
