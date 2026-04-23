use alloc::vec::Vec;

use wasmi::{Engine, TypedFunc};

use vmos_abi::{NodeKind, ServiceRoute};

use super::super::types::{LookupInfo, ServiceCallError};
use super::super::wasm::{BufferedStore, expect_len, expect_ok};

const VFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_VFS_SERVICE_WASM"));

pub(crate) struct VfsService {
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    route_kind: TypedFunc<(), u32>,
    node_kind: TypedFunc<(), u32>,
    read_file: TypedFunc<(u32, u32), i32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_link: TypedFunc<(u32, u32), i32>,
}

impl VfsService {
    pub(crate) fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            VFS_SERVICE_WASM,
            "failed to instantiate vfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing vfs lookup export")?;
        let route_kind = instance
            .get_typed_func::<(), u32>(&io.store, "route_kind")
            .map_err(|_| "missing vfs route_kind export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing vfs node_kind export")?;
        let read_file = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_file")
            .map_err(|_| "missing vfs read_file export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing vfs list_dir export")?;
        let read_link = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_link")
            .map_err(|_| "missing vfs read_link export")?;

        Ok(Self {
            io,
            lookup,
            route_kind,
            node_kind,
            read_file,
            list_dir,
            read_link,
        })
    }

    pub(crate) fn lookup(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<LookupInfo, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        let route = ServiceRoute::from_raw(
            self.route_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "vfs_service returned an invalid route",
        ))?;
        let node = NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "vfs_service returned an invalid node kind",
        ))?;

        Ok(LookupInfo { route, node })
    }

    pub(crate) fn read_file(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_file
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
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
            self.list_dir
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn read_link(
        &mut self,
        path: &[u8],
        inject_fault: bool,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        let len = expect_len(
            self.read_link
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("vfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }
}
