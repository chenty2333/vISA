use alloc::vec::Vec;

use wasmi::{Engine, TypedFunc};

use vmos_abi::NodeKind;

use super::super::types::ServiceCallError;
use super::super::wasm::{BufferedStore, expect_len, expect_ok};

const DEVFS_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_DEVFS_SERVICE_WASM"));

pub(crate) struct DevfsService {
    io: BufferedStore,
    lookup: TypedFunc<(u32, u32), i32>,
    node_kind: TypedFunc<(), u32>,
    list_dir: TypedFunc<(u32, u32), i32>,
    read_device: TypedFunc<(u32, u32, u32), i32>,
    write_device: TypedFunc<(u32, u32, u32), i32>,
}

impl DevfsService {
    pub(crate) fn new(engine: &Engine) -> Result<Self, &'static str> {
        let (io, instance) = BufferedStore::new(
            engine,
            DEVFS_SERVICE_WASM,
            "failed to instantiate devfs_service",
        )?;
        let lookup = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "lookup")
            .map_err(|_| "missing devfs lookup export")?;
        let node_kind = instance
            .get_typed_func::<(), u32>(&io.store, "node_kind")
            .map_err(|_| "missing devfs node_kind export")?;
        let list_dir = instance
            .get_typed_func::<(u32, u32), i32>(&io.store, "list_dir")
            .map_err(|_| "missing devfs list_dir export")?;
        let read_device = instance
            .get_typed_func::<(u32, u32, u32), i32>(&io.store, "read_device")
            .map_err(|_| "missing devfs read_device export")?;
        let write_device = instance
            .get_typed_func::<(u32, u32, u32), i32>(&io.store, "write_device")
            .map_err(|_| "missing devfs write_device export")?;

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
            self.lookup
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )?;
        NodeKind::from_raw(
            self.node_kind
                .call(&mut self.io.store, ())
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
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
            self.list_dir
                .call(&mut self.io.store, (path_len, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
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
            self.read_device
                .call(&mut self.io.store, (path_len, count, inject_fault as u32))
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
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
            self.write_device
                .call(
                    &mut self.io.store,
                    (path_len, data_len, inject_fault as u32),
                )
                .map_err(|_| ServiceCallError::Trap("devfs_service trapped"))?,
        )
    }
}
