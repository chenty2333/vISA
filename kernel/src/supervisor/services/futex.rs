use alloc::vec::Vec;

use wasmi::{Engine, TypedFunc};

use super::super::types::ServiceCallError;
use super::super::wasm::{BufferedStore, expect_len, expect_ok};

const FUTEX_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_FUTEX_SERVICE_WASM"));

pub(crate) struct FutexService {
    io: BufferedStore,
    register_wait: TypedFunc<(u64, u64), i32>,
    wake: TypedFunc<(u64, u32), i32>,
    cancel_wait: TypedFunc<u64, i32>,
}

impl FutexService {
    pub(crate) fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            FUTEX_SERVICE_WASM,
            "failed to instantiate futex_service",
        )?;
        let register_wait = instance
            .get_typed_func::<(u64, u64), i32>(&io.store, "register_wait")
            .map_err(|_| "missing futex register_wait export")?;
        let wake = instance
            .get_typed_func::<(u64, u32), i32>(&io.store, "wake")
            .map_err(|_| "missing futex wake export")?;
        let cancel_wait = instance
            .get_typed_func::<u64, i32>(&io.store, "cancel_wait")
            .map_err(|_| "missing futex cancel_wait export")?;

        Ok(Self {
            io,
            register_wait,
            wake,
            cancel_wait,
        })
    }

    pub(crate) fn register_wait(&mut self, key: u64, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.register_wait
                .call(&mut self.io.store, (key, wait_id))
                .map_err(|_| ServiceCallError::Trap("futex_service trapped"))?,
        )
    }

    pub(crate) fn wake(&mut self, key: u64, max_count: u32) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(
            self.wake
                .call(&mut self.io.store, (key, max_count))
                .map_err(|_| ServiceCallError::Trap("futex_service trapped"))?,
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
            self.cancel_wait
                .call(&mut self.io.store, wait_id)
                .map_err(|_| ServiceCallError::Trap("futex_service trapped"))?,
        )
    }
}
