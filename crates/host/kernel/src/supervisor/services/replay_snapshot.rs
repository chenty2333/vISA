use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_ok},
    types::ServiceCallError,
};

const REPLAY_SNAPSHOT_WASM: &[u8] = include_bytes!(env!("VMOS_REPLAY_SNAPSHOT_WASM"));

pub(crate) struct ReplaySnapshotService {
    io: BufferedModule,
    validate_barrier: WasmFn<(u32, u32, u32, u32), i32>,
    replay_until: WasmFn<u64, u64>,
    last_replay_cursor: WasmFn<(), u64>,
}

impl ReplaySnapshotService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            REPLAY_SNAPSHOT_WASM,
            "failed to instantiate replay_snapshot",
        )?;
        let validate_barrier =
            io.bind("validate_barrier", "missing replay_snapshot validate_barrier export")?;
        let replay_until =
            io.bind("replay_until", "missing replay_snapshot replay_until export")?;
        let last_replay_cursor =
            io.bind("last_replay_cursor", "missing replay_snapshot last_replay_cursor export")?;
        Ok(Self { io, validate_barrier, replay_until, last_replay_cursor })
    }

    pub(crate) fn validate_barrier(
        &mut self,
        pending_waits: u32,
        active_transactions: u32,
        active_dmw_leases: u32,
        pending_dma: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(
                    &self.validate_barrier,
                    (pending_waits, active_transactions, active_dmw_leases, pending_dma),
                    "replay_snapshot trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn replay_until(&mut self, cursor: u64) -> Result<u64, ServiceCallError> {
        self.io
            .call(&self.replay_until, cursor, "replay_snapshot trapped")
            .map_err(ServiceCallError::Trap)
    }

    pub(crate) fn last_replay_cursor(&mut self) -> Result<u64, ServiceCallError> {
        self.io
            .call(&self.last_replay_cursor, (), "replay_snapshot trapped")
            .map_err(ServiceCallError::Trap)
    }
}
