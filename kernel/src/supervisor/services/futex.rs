use alloc::vec::Vec;

use super::super::engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok};
use super::super::types::ServiceCallError;

const FUTEX_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_FUTEX_SERVICE_WASM"));

pub(crate) struct FutexService {
    io: BufferedModule,
    register_wait: WasmFn<(u64, u64), i32>,
    wake: WasmFn<(u64, u32), i32>,
    cancel_wait: WasmFn<u64, i32>,
}

impl FutexService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            FUTEX_SERVICE_WASM,
            "failed to instantiate futex_service",
        )?;
        let register_wait = io.bind("register_wait", "missing futex register_wait export")?;
        let wake = io.bind("wake", "missing futex wake export")?;
        let cancel_wait = io.bind("cancel_wait", "missing futex cancel_wait export")?;

        Ok(Self {
            io,
            register_wait,
            wake,
            cancel_wait,
        })
    }

    pub(crate) fn register_wait(&mut self, key: u64, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.register_wait, (key, wait_id), "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn wake(&mut self, key: u64, max_count: u32) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.wake, (key, max_count), "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        let bytes = self
            .io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)?;

        if bytes.len() % 8 != 0 {
            return Err(ServiceCallError::Invalid(
                "futex_service returned a malformed wake response",
            ));
        }

        let mut ids = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(chunk);
            ids.push(u64::from_le_bytes(raw));
        }
        Ok(ids)
    }

    pub(crate) fn cancel_wait(&mut self, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.cancel_wait, wait_id, "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }
}
