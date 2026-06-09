use alloc::vec::Vec;

use visa_abi::{NodeKind, ServiceRoute};

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::{LookupInfo, ServiceCallError, VfsTimestamps},
};

const VFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VISA_VFS_SERVICE_WASM"));

pub(crate) struct VfsService {
    io: BufferedModule,
    lookup: WasmFn<(u32, u32), i32>,
    route_kind: WasmFn<(), u32>,
    node_kind: WasmFn<(), u32>,
    read_file: WasmFn<(u32, u32), i32>,
    list_dir: WasmFn<(u32, u32), i32>,
    read_link: WasmFn<(u32, u32), i32>,
}

impl VfsService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            VFS_SERVICE_WASM,
            "failed to instantiate vfs_service",
        )?;
        let lookup = io.bind("lookup", "missing vfs lookup export")?;
        let route_kind = io.bind("route_kind", "missing vfs route_kind export")?;
        let node_kind = io.bind("node_kind", "missing vfs node_kind export")?;
        let read_file = io.bind("read_file", "missing vfs read_file export")?;
        let list_dir = io.bind("list_dir", "missing vfs list_dir export")?;
        let read_link = io.bind("read_link", "missing vfs read_link export")?;

        Ok(Self { io, lookup, route_kind, node_kind, read_file, list_dir, read_link })
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<LookupInfo, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.io
                .call(&self.lookup, (path_len, inject_fault as u32), "vfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        let route = ServiceRoute::from_raw(
            self.io
                .call(&self.route_kind, (), "vfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
        .ok_or(ServiceCallError::Invalid("vfs_service returned an invalid route"))?;
        let node = NodeKind::from_raw(
            self.io
                .call(&self.node_kind, (), "vfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
        .ok_or(ServiceCallError::Invalid("vfs_service returned an invalid node kind"))?;

        Ok(LookupInfo { route, node })
    }

    pub(crate) fn read_file(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self.io.write_request(path).map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.io
                .call(&self.read_file, (path_len, inject_fault as u32), "vfs_service trapped")
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
                .call(&self.list_dir, (path_len, inject_fault as u32), "vfs_service trapped")
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
                .call(&self.read_link, (path_len, inject_fault as u32), "vfs_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn timestamps_for_path(&self, _path: &[u8]) -> VfsTimestamps {
        VfsTimestamps::default()
    }

    pub(crate) fn timestamps_for_node(&self, _node_id: Option<u64>, _path: &[u8]) -> VfsTimestamps {
        VfsTimestamps::default()
    }

    pub(crate) fn set_timestamps_by_id(
        &mut self,
        _node_id: Option<u64>,
        _path: &[u8],
        _atime_ns: Option<u64>,
        _mtime_ns: Option<u64>,
        _ctime_ns: u64,
    ) -> Result<(), ServiceCallError> {
        Err(ServiceCallError::Errno(visa_abi::ERR_EOPNOTSUPP))
    }
}
