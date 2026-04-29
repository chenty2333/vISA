use alloc::vec::Vec;

use vmos_abi::NodeKind;

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::ServiceCallError,
};

const PROCFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_PROCFS_SERVICE_WASM"));

pub(crate) struct ProcfsService {
    io: BufferedModule,
    lookup: WasmFn<(u32, u32), i32>,
    node_kind: WasmFn<(), u32>,
    read_file: WasmFn<(u32, u32), i32>,
    list_dir: WasmFn<(u32, u32), i32>,
    read_link: WasmFn<(u32, u32), i32>,
}

impl ProcfsService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            PROCFS_SERVICE_WASM,
            "failed to instantiate procfs_service",
        )?;
        let lookup = io.bind("lookup", "missing procfs lookup export")?;
        let node_kind = io.bind("node_kind", "missing procfs node_kind export")?;
        let read_file = io.bind("read_file", "missing procfs read_file export")?;
        let list_dir = io.bind("list_dir", "missing procfs list_dir export")?;
        let read_link = io.bind("read_link", "missing procfs read_link export")?;

        Ok(Self { io, lookup, node_kind, read_file, list_dir, read_link })
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<NodeKind, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.io
                .call(&self.lookup, (path_len, inject_fault as u32), "procfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        NodeKind::from_raw(
            self.io
                .call(&self.node_kind, (), "procfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
        .ok_or(ServiceCallError::Invalid("procfs_service returned an invalid node kind"))
    }

    pub(crate) fn read_file(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(&self.read_file, (path_len, inject_fault as u32), "procfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn list_dir(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(&self.list_dir, (path_len, inject_fault as u32), "procfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn read_link(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(&self.read_link, (path_len, inject_fault as u32), "procfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }
}
