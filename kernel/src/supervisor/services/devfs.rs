use alloc::vec::Vec;

use vmos_abi::NodeKind;

use super::super::engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok};
use super::super::types::ServiceCallError;

const DEVFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_DEVFS_SERVICE_WASM"));

pub(crate) struct DevfsService {
    io: BufferedModule,
    lookup: WasmFn<(u32, u32), i32>,
    node_kind: WasmFn<(), u32>,
    list_dir: WasmFn<(u32, u32), i32>,
    read_device: WasmFn<(u32, u32, u32), i32>,
    write_device: WasmFn<(u32, u32, u32), i32>,
}

impl DevfsService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            DEVFS_SERVICE_WASM,
            "failed to instantiate devfs_service",
        )?;
        let lookup = io.bind("lookup", "missing devfs lookup export")?;
        let node_kind = io.bind("node_kind", "missing devfs node_kind export")?;
        let list_dir = io.bind("list_dir", "missing devfs list_dir export")?;
        let read_device = io.bind("read_device", "missing devfs read_device export")?;
        let write_device = io.bind("write_device", "missing devfs write_device export")?;

        Ok(Self {
            io,
            lookup,
            node_kind,
            list_dir,
            read_device,
            write_device,
        })
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<NodeKind, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.io
                .call(
                    &self.lookup,
                    (path_len, inject_fault as u32),
                    "devfs_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )?;
        NodeKind::from_raw(
            self.io
                .call(&self.node_kind, (), "devfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
        .ok_or(ServiceCallError::Invalid(
            "devfs_service returned an invalid node kind",
        ))
    }

    pub(crate) fn list_dir(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(
                    &self.list_dir,
                    (path_len, inject_fault as u32),
                    "devfs_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn read_device(
        &mut self,
        path: &[u8],
        count: u32,
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(
                    &self.read_device,
                    (path_len, count, inject_fault as u32),
                    "devfs_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn write_device(
        &mut self,
        path: &[u8],
        data_len: u32,
        inject_fault: bool,
    ) -> Result<u32, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_len(
            self.io
                .call(
                    &self.write_device,
                    (path_len, data_len, inject_fault as u32),
                    "devfs_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }
}
