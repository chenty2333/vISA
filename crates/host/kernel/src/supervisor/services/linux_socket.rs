use service_core::net_contract::NETWORK_CONTRACT_ABI_VERSION;

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::ServiceCallError,
};

const LINUX_SOCKET_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_LINUX_SOCKET_SERVICE_WASM"));

pub(crate) struct LinuxSocketService {
    io: BufferedModule,
    register_socket: WasmFn<(u32, u32, u32, u32, u64), i32>,
    close_socket: WasmFn<u32, i32>,
    bind_socket: WasmFn<(u32, u32), i32>,
    connect_socket: WasmFn<(u32, u32), i32>,
    listen_socket: WasmFn<(u32, u32), i32>,
    accept_socket: WasmFn<(u32, u32, u64), i32>,
    pending_accept_count: WasmFn<u32, i32>,
    accept_ready_key_for_client: WasmFn<u32, u64>,
    send_socket: WasmFn<(u32, u32), i32>,
    recv_socket: WasmFn<(u32, u32), i32>,
    setsockopt: WasmFn<(u32, u32, u32, u32), i32>,
    getsockopt: WasmFn<(u32, u32, u32), i32>,
    fcntl: WasmFn<(u32, u32, u64), i32>,
    socket_count: WasmFn<(), u32>,
}

impl LinuxSocketService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            LINUX_SOCKET_SERVICE_WASM,
            "failed to instantiate linux_socket_service",
        )?;
        let register_socket =
            io.bind("register_socket", "missing linux_socket register_socket export")?;
        let close_socket = io.bind("close_socket", "missing linux_socket close_socket export")?;
        let bind_socket = io.bind("bind_socket", "missing linux_socket bind_socket export")?;
        let connect_socket =
            io.bind("connect_socket", "missing linux_socket connect_socket export")?;
        let listen_socket =
            io.bind("listen_socket", "missing linux_socket listen_socket export")?;
        let accept_socket =
            io.bind("accept_socket", "missing linux_socket accept_socket export")?;
        let pending_accept_count =
            io.bind("pending_accept_count", "missing linux_socket pending_accept_count export")?;
        let accept_ready_key_for_client = io.bind(
            "accept_ready_key_for_client",
            "missing linux_socket accept_ready_key_for_client export",
        )?;
        let send_socket = io.bind("send_socket", "missing linux_socket send_socket export")?;
        let recv_socket = io.bind("recv_socket", "missing linux_socket recv_socket export")?;
        let setsockopt = io.bind("setsockopt", "missing linux_socket setsockopt export")?;
        let getsockopt = io.bind("getsockopt", "missing linux_socket getsockopt export")?;
        let fcntl = io.bind("fcntl", "missing linux_socket fcntl export")?;
        let socket_count = io.bind("socket_count", "missing linux_socket socket_count export")?;
        let network_contract_version: WasmFn<(), u32> = io.bind(
            "network_contract_version",
            "missing linux_socket network_contract_version export",
        )?;

        let mut service = Self {
            io,
            register_socket,
            close_socket,
            bind_socket,
            connect_socket,
            listen_socket,
            accept_socket,
            pending_accept_count,
            accept_ready_key_for_client,
            send_socket,
            recv_socket,
            setsockopt,
            getsockopt,
            fcntl,
            socket_count,
        };
        let version = service.io.call(
            &network_contract_version,
            (),
            "linux_socket network contract version trapped",
        )?;
        if version != NETWORK_CONTRACT_ABI_VERSION {
            return Err("linux_socket network contract mismatch");
        }
        Ok(service)
    }

    pub(crate) fn register_socket(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
        ready_key: u64,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(
                    &self.register_socket,
                    (socket_id, domain, ty, protocol, ready_key),
                    "linux_socket_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.close_socket, socket_id, "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn bind_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.bind_socket, (socket_id, addr_len), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn connect_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.connect_socket, (socket_id, addr_len), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn listen_socket(
        &mut self,
        socket_id: u32,
        backlog: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.listen_socket, (socket_id, backlog), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn accept_socket(
        &mut self,
        socket_id: u32,
        accepted_socket_id: u32,
        ready_key: u64,
    ) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(
                    &self.accept_socket,
                    (socket_id, accepted_socket_id, ready_key),
                    "linux_socket_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn pending_accept_count(&mut self, socket_id: u32) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.pending_accept_count, socket_id, "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn accept_ready_key_for_client(
        &mut self,
        socket_id: u32,
    ) -> Result<Option<u64>, ServiceCallError> {
        let key = self
            .io
            .call(&self.accept_ready_key_for_client, socket_id, "linux_socket_service trapped")
            .map_err(ServiceCallError::Trap)?;
        if key == 0 { Ok(None) } else { Ok(Some(key)) }
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.send_socket, (socket_id, len), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.recv_socket, (socket_id, len), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn setsockopt(
        &mut self,
        socket_id: u32,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(
                    &self.setsockopt,
                    (socket_id, level, optname, optlen),
                    "linux_socket_service trapped",
                )
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn getsockopt(
        &mut self,
        socket_id: u32,
        level: u32,
        optname: u32,
    ) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.getsockopt, (socket_id, level, optname), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn fcntl(&mut self, fd: u32, cmd: u32, arg: u64) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.fcntl, (fd, cmd, arg), "linux_socket_service trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        self.io
            .call(&self.socket_count, (), "linux_socket_service trapped")
            .map_err(ServiceCallError::Trap)
    }
}
