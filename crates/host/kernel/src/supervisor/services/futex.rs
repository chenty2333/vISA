use alloc::vec::Vec;

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::ServiceCallError,
};

const FUTEX_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_FUTEX_SERVICE_WASM"));

pub(crate) struct FutexService {
    io: BufferedModule,
    register_wait_with_priority_export: WasmFn<(u64, u64, u32), i32>,
    register_wait_bitset_with_priority_export: WasmFn<(u64, u64, u32, u32), i32>,
    wake_export: WasmFn<(u64, u32), i32>,
    wake_bitset_export: WasmFn<(u64, u32, u32), i32>,
    requeue_export: WasmFn<(u64, u32, u64, u32), i32>,
    cancel_wait_export: WasmFn<u64, i32>,
    max_priority_export: WasmFn<u64, i32>,
}

impl FutexService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            FUTEX_SERVICE_WASM,
            "failed to instantiate futex_service",
        )?;
        let register_wait_with_priority_export = io.bind(
            "register_wait_with_priority",
            "missing futex register_wait_with_priority export",
        )?;
        let register_wait_bitset_with_priority_export = io.bind(
            "register_wait_bitset_with_priority",
            "missing futex register_wait_bitset_with_priority export",
        )?;
        let wake_export = io.bind("wake", "missing futex wake export")?;
        let wake_bitset_export = io.bind("wake_bitset", "missing futex wake_bitset export")?;
        let requeue_export = io.bind("requeue", "missing futex requeue export")?;
        let cancel_wait_export = io.bind("cancel_wait", "missing futex cancel_wait export")?;
        let max_priority_export = io.bind("max_priority", "missing futex max_priority export")?;

        Ok(Self {
            io,
            register_wait_with_priority_export,
            register_wait_bitset_with_priority_export,
            wake_export,
            wake_bitset_export,
            requeue_export,
            cancel_wait_export,
            max_priority_export,
        })
    }

    pub(crate) fn register_wait(&mut self, key: u64, wait_id: u64) -> Result<(), ServiceCallError> {
        self.register_wait_with_priority(key, wait_id, 0)
    }

    pub(crate) fn register_wait_with_priority(
        &mut self,
        key: u64,
        wait_id: u64,
        priority: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(
                    &self.register_wait_with_priority_export,
                    (key, wait_id, priority),
                    "futex_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn register_wait_bitset(
        &mut self,
        key: u64,
        wait_id: u64,
        bitset: u32,
    ) -> Result<(), ServiceCallError> {
        self.register_wait_bitset_with_priority(key, wait_id, bitset, 0)
    }

    pub(crate) fn register_wait_bitset_with_priority(
        &mut self,
        key: u64,
        wait_id: u64,
        bitset: u32,
        priority: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(
                    &self.register_wait_bitset_with_priority_export,
                    (key, wait_id, bitset, priority),
                    "futex_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn wake(&mut self, key: u64, max_count: u32) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.wake_export, (key, max_count), "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.read_wake_response(len)
    }

    pub(crate) fn wake_bitset(
        &mut self,
        key: u64,
        max_count: u32,
        bitset: u32,
    ) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.wake_bitset_export, (key, max_count, bitset), "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.read_wake_response(len)
    }

    pub(crate) fn requeue(
        &mut self,
        src_key: u64,
        requeue_count: u32,
        dst_key: u64,
        wake_count: u32,
    ) -> Result<(u32, Vec<u64>), ServiceCallError> {
        let len = expect_len(
            self.io
                .call(
                    &self.requeue_export,
                    (src_key, requeue_count, dst_key, wake_count),
                    "futex_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )?;
        let bytes = self.io.read_response(len).map_err(ServiceCallError::Invalid)?;
        decode_requeue_response(&bytes)
    }

    fn read_wake_response(&self, len: usize) -> Result<Vec<u64>, ServiceCallError> {
        let bytes = self.io.read_response(len).map_err(ServiceCallError::Invalid)?;

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
                .call(&self.cancel_wait_export, wait_id, "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn max_priority(&mut self, key: u64) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.max_priority_export, key, "futex_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }
}

fn decode_requeue_response(bytes: &[u8]) -> Result<(u32, Vec<u64>), ServiceCallError> {
    if bytes.len() < 8 || bytes.len() % 8 != 0 {
        return Err(ServiceCallError::Invalid(
            "futex_service returned a malformed requeue response",
        ));
    }
    let mut total = [0u8; 8];
    total.copy_from_slice(&bytes[..8]);
    let total = u64::from_le_bytes(total);
    let total = u32::try_from(total)
        .map_err(|_| ServiceCallError::Invalid("futex_service requeue total overflowed"))?;
    let mut ids = Vec::with_capacity((bytes.len() - 8) / 8);
    for chunk in bytes[8..].chunks_exact(8) {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(chunk);
        ids.push(u64::from_le_bytes(raw));
    }
    Ok((total, ids))
}
