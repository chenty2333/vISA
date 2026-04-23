use alloc::vec::Vec;

use wasmi::{Engine, TypedFunc};

use super::super::types::ServiceCallError;
use super::super::wasm::{BufferedStore, expect_len, expect_ok};

const EPOLL_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_EPOLL_SERVICE_WASM"));

pub(crate) struct EpollService {
    io: BufferedStore,
    create: TypedFunc<u32, i32>,
    ctl: TypedFunc<(u32, u32, u64, u32, u64), i32>,
    collect_ready: TypedFunc<(u32, u32), i32>,
    arm_wait: TypedFunc<(u32, u64), i32>,
    notify_ready: TypedFunc<u64, i32>,
    restart_key: TypedFunc<u64, i32>,
    cancel_wait: TypedFunc<u64, i32>,
}

impl EpollService {
    pub(crate) fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            EPOLL_SERVICE_WASM,
            "failed to instantiate epoll_service",
        )?;
        let create = instance
            .get_typed_func::<u32, i32>(&io.store, "create")
            .map_err(|_| "missing epoll create export")?;
        let ctl = instance
            .get_typed_func::<(u32, u32, u64, u32, u64), i32>(&io.store, "ctl")
            .map_err(|_| "missing epoll ctl export")?;
        let collect_ready = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "collect_ready")
            .map_err(|_| "missing epoll collect_ready export")?;
        let arm_wait = instance
            .get_typed_func::<(u32, u64), i32>(&io.store, "arm_wait")
            .map_err(|_| "missing epoll arm_wait export")?;
        let notify_ready = instance
            .get_typed_func::<u64, i32>(&io.store, "notify_ready")
            .map_err(|_| "missing epoll notify_ready export")?;
        let restart_key = instance
            .get_typed_func::<u64, i32>(&io.store, "restart_key")
            .map_err(|_| "missing epoll restart_key export")?;
        let cancel_wait = instance
            .get_typed_func::<u64, i32>(&io.store, "cancel_wait")
            .map_err(|_| "missing epoll cancel_wait export")?;

        Ok(Self {
            io,
            create,
            ctl,
            collect_ready,
            arm_wait,
            notify_ready,
            restart_key,
            cancel_wait,
        })
    }

    pub(crate) fn create(&mut self, flags: u32) -> Result<u32, ServiceCallError> {
        let raw = self
            .create
            .call(&mut self.io.store, flags)
            .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?;
        if raw < 0 {
            return Err(ServiceCallError::Errno((-raw) as i32));
        }
        Ok(raw as u32)
    }

    pub(crate) fn ctl(
        &mut self,
        epoll_id: u32,
        op: u32,
        ready_key: u64,
        events: u32,
        data: u64,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.ctl
                .call(&mut self.io.store, (epoll_id, op, ready_key, events, data))
                .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?,
        )
    }

    pub(crate) fn collect_ready(
        &mut self,
        epoll_id: u32,
        max_events: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let len = expect_len(
            self.collect_ready
                .call(&mut self.io.store, (epoll_id, max_events))
                .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn arm_wait(&mut self, epoll_id: u32, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.arm_wait
                .call(&mut self.io.store, (epoll_id, wait_id))
                .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?,
        )
    }

    pub(crate) fn notify_ready(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        let len = self
            .notify_ready
            .call(&mut self.io.store, ready_key)
            .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?;
        self.read_wait_ids(len)
    }

    pub(crate) fn restart_key(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        let len = self
            .restart_key
            .call(&mut self.io.store, ready_key)
            .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?;
        self.read_wait_ids(len)
    }

    pub(crate) fn cancel_wait(&mut self, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.cancel_wait
                .call(&mut self.io.store, wait_id)
                .map_err(|_| ServiceCallError::Trap("epoll_service trapped"))?,
        )
    }

    fn read_wait_ids(&mut self, raw_len: i32) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(raw_len)?;
        let bytes = self
            .io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)?;
        if bytes.len() % 8 != 0 {
            return Err(ServiceCallError::Invalid(
                "epoll_service returned a malformed wait list",
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
}
