use alloc::vec::Vec;

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::ServiceCallError,
};

const EPOLL_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_EPOLL_SERVICE_WASM"));

pub(crate) struct EpollService {
    io: BufferedModule,
    create: WasmFn<u32, i32>,
    ctl: WasmFn<(u32, u32, u64, u32, u64), i32>,
    collect_ready: WasmFn<(u32, u32), i32>,
    arm_wait: WasmFn<(u32, u64), i32>,
    notify_ready: WasmFn<u64, i32>,
    restart_key: WasmFn<u64, i32>,
    cancel_wait: WasmFn<u64, i32>,
}

impl EpollService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            EPOLL_SERVICE_WASM,
            "failed to instantiate epoll_service",
        )?;
        let create = io.bind("create", "missing epoll create export")?;
        let ctl = io.bind("ctl", "missing epoll ctl export")?;
        let collect_ready = io.bind("collect_ready", "missing epoll collect_ready export")?;
        let arm_wait = io.bind("arm_wait", "missing epoll arm_wait export")?;
        let notify_ready = io.bind("notify_ready", "missing epoll notify_ready export")?;
        let restart_key = io.bind("restart_key", "missing epoll restart_key export")?;
        let cancel_wait = io.bind("cancel_wait", "missing epoll cancel_wait export")?;

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
            .io
            .call(&self.create, flags, "epoll_service trapped")
            .map_err(ServiceCallError::Trap)?;
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
            self.io
                .call(&self.ctl, (epoll_id, op, ready_key, events, data), "epoll_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn collect_ready(
        &mut self,
        epoll_id: u32,
        max_events: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.collect_ready, (epoll_id, max_events), "epoll_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn arm_wait(&mut self, epoll_id: u32, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.arm_wait, (epoll_id, wait_id), "epoll_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn notify_ready(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        let len = self
            .io
            .call(&self.notify_ready, ready_key, "epoll_service trapped")
            .map_err(ServiceCallError::Trap)?;
        self.read_wait_ids(len)
    }

    pub(crate) fn restart_key(&mut self, ready_key: u64) -> Result<Vec<u64>, ServiceCallError> {
        let len = self
            .io
            .call(&self.restart_key, ready_key, "epoll_service trapped")
            .map_err(ServiceCallError::Trap)?;
        self.read_wait_ids(len)
    }

    pub(crate) fn cancel_wait(&mut self, wait_id: u64) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.cancel_wait, wait_id, "epoll_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    fn read_wait_ids(&mut self, raw_len: i32) -> Result<Vec<u64>, ServiceCallError> {
        let len = expect_len(raw_len)?;
        let bytes = self.io.read_response(len).map_err(ServiceCallError::Invalid)?;
        if bytes.len() % 8 != 0 {
            return Err(ServiceCallError::Invalid("epoll_service returned a malformed wait list"));
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
