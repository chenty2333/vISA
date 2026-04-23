use alloc::vec::Vec;

use wasmi::{Engine, TypedFunc};

use vmos_abi::NodeKind;

use super::super::types::ServiceCallError;
use super::super::wasm::{BufferedStore, expect_len, expect_ok};

const PROCFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_PROCFS_SERVICE_WASM"));

pub(crate) struct ProcfsService<'engine> {
    pub(crate) engine: &'engine Engine,
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    node_kind: TypedFunc<(), u32>,
    read_file: TypedFunc<(u32, u32), i32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_link: TypedFunc<(u32, u32), i32>,
}

impl<'engine> ProcfsService<'engine> {
    pub(crate) fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            PROCFS_SERVICE_WASM,
            "failed to instantiate procfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing procfs lookup export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing procfs node_kind export")?;
        let read_file = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_file")
            .map_err(|_| "missing procfs read_file export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing procfs list_dir export")?;
        let read_link = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "read_link")
            .map_err(|_| "missing procfs read_link export")?;

        Ok(Self {
            engine,
            io,
            lookup,
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
    ) -> Result<NodeKind, ServiceCallError> {
        let path_len = self
            .io
            .write_request(path)
            .map_err(ServiceCallError::Invalid)?;
        expect_ok(
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )
        .ok_or(ServiceCallError::Invalid(
            "procfs_service returned an invalid node kind",
        ))
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
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
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
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
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
                .map_err(|_| ServiceCallError::Trap("procfs_service trapped"))?,
        )?;
        self.io
            .read_response(len)
            .map_err(ServiceCallError::Invalid)
    }
}
