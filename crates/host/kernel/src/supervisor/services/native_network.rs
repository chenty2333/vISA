use alloc::vec::Vec;
use core::ptr::addr_of_mut;

pub(crate) use service_core::driver::DriverNetEventKind;
use service_core::{
    driver::{DriverVirtioNetState, RESPONSE_CAPACITY},
    linux_socket::LinuxSocketState,
    net::{NetCoreState, QUEUE_CAPACITY},
    packet::decode_frame,
    replay::ReplaySnapshotState,
};

use crate::supervisor::{engine::SupervisorEngine, types::ServiceCallError};

pub(crate) struct NetCoreService {
    state: &'static mut NetCoreState,
}

impl NetCoreService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: unsafe { net_core_state() } })
    }

    pub(crate) fn create_socket(
        &mut self,
        domain: u32,
        ty: u32,
        protocol: u32,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.create_socket(domain, ty, protocol))
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        map_errno(self.state.close_socket(socket_id))
    }

    pub(crate) fn ready_key(&mut self, socket_id: u32) -> Result<u64, ServiceCallError> {
        map_errno(self.state.ready_key(socket_id))
    }

    pub(crate) fn poll_socket(&mut self, socket_id: u32) -> Result<u32, ServiceCallError> {
        map_errno(self.state.poll_socket(socket_id))
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        bytes: &[u8],
    ) -> Result<u32, ServiceCallError> {
        if bytes.len() > QUEUE_CAPACITY {
            return errno(vmos_abi::ERR_EIO);
        }
        map_errno(self.state.send_socket(socket_id, bytes))
    }

    pub(crate) fn take_tx_frame(&mut self, socket_id: u32) -> Result<Vec<u8>, ServiceCallError> {
        let mut out = alloc::vec![0; service_core::packet::PACKET_FRAME_CAPACITY];
        let len = map_errno(self.state.take_tx_frame(socket_id, &mut out))?;
        out.truncate(len as usize);
        Ok(out)
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let mut out = alloc::vec![0; count as usize];
        let len = map_errno(self.state.recv_socket(socket_id, count, &mut out))?;
        out.truncate(len as usize);
        Ok(out)
    }

    pub(crate) fn deliver_packet_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<u64>, ServiceCallError> {
        map_errno(self.state.deliver_packet_frame(frame))
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.state.socket_count())
    }

    pub(crate) fn queued_rx_bytes(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.state.queued_rx_bytes())
    }
}

pub(crate) struct LinuxSocketService {
    state: &'static mut LinuxSocketState,
}

impl LinuxSocketService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: unsafe { linux_socket_state() } })
    }

    pub(crate) fn register_socket(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
        ready_key: u64,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.register_socket(socket_id, domain, ty, protocol, ready_key))
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        map_errno(self.state.close_socket(socket_id))
    }

    pub(crate) fn bind_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.bind_socket(socket_id, addr_len))
    }

    pub(crate) fn connect_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.connect_socket(socket_id, addr_len))
    }

    pub(crate) fn listen_socket(
        &mut self,
        socket_id: u32,
        backlog: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.listen_socket(socket_id, backlog))
    }

    pub(crate) fn accept_socket(
        &mut self,
        socket_id: u32,
        accepted_socket_id: u32,
        ready_key: u64,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.accept_socket(socket_id, accepted_socket_id, ready_key))
    }

    pub(crate) fn pending_accept_count(&mut self, socket_id: u32) -> Result<u32, ServiceCallError> {
        map_errno(self.state.pending_accept_count(socket_id))
    }

    pub(crate) fn accept_ready_key_for_client(
        &mut self,
        socket_id: u32,
    ) -> Result<Option<u64>, ServiceCallError> {
        map_errno(self.state.accept_ready_key_for_client(socket_id))
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.send_socket(socket_id, len))
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        len: u32,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.recv_socket(socket_id, len))
    }

    pub(crate) fn setsockopt(
        &mut self,
        socket_id: u32,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.setsockopt(socket_id, level, optname, optlen))
    }

    pub(crate) fn getsockopt(
        &mut self,
        socket_id: u32,
        level: u32,
        optname: u32,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.getsockopt(socket_id, level, optname))
    }

    pub(crate) fn fcntl(
        &mut self,
        socket_id: u32,
        cmd: u32,
        arg: u64,
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.fcntl(socket_id, cmd, arg))
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.state.socket_count())
    }
}

pub(crate) struct DriverNetEvent {
    pub(crate) kind: DriverNetEventKind,
    pub(crate) len: u32,
    pub(crate) frame: Vec<u8>,
}

pub(crate) struct DriverVirtioNetService {
    state: &'static mut DriverVirtioNetState,
}

impl DriverVirtioNetService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: unsafe { driver_state() } })
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) -> Result<(), ServiceCallError> {
        self.state.reset_sequence(now_ticks);
        Ok(())
    }

    pub(crate) fn submit_tx_frame(
        &mut self,
        now_ticks: u64,
        frame: &[u8],
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.submit_tx_frame(now_ticks, frame))
    }

    pub(crate) fn poll_device(
        &mut self,
        now_ticks: u64,
    ) -> Result<DriverNetEvent, ServiceCallError> {
        let event = self.state.poll_device(now_ticks);
        let mut frame = alloc::vec![0; RESPONSE_CAPACITY];
        let mut payload_len = event.len;
        if event.kind == DriverNetEventKind::PacketRx {
            let frame_len = map_errno(self.state.dequeue_rx_frame(&mut frame))?;
            frame.truncate(frame_len as usize);
            payload_len =
                decode_frame(&frame).map(|(meta, _)| meta.payload_len).unwrap_or(frame_len);
        } else {
            frame.clear();
        }
        Ok(DriverNetEvent { kind: event.kind, len: payload_len, frame })
    }
}

pub(crate) struct ReplaySnapshotService {
    state: &'static mut ReplaySnapshotState,
}

impl ReplaySnapshotService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: unsafe { replay_snapshot_state() } })
    }

    pub(crate) fn validate_barrier(
        &mut self,
        pending_waits: u32,
        active_transactions: u32,
        active_dmw_leases: u32,
        pending_dma: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.validate_barrier(
            pending_waits,
            active_transactions,
            active_dmw_leases,
            pending_dma,
        ))
    }

    pub(crate) fn replay_until(&mut self, cursor: u64) -> Result<u64, ServiceCallError> {
        Ok(self.state.replay_until(cursor))
    }

    pub(crate) fn last_replay_cursor(&mut self) -> Result<u64, ServiceCallError> {
        Ok(self.state.last_replay_cursor())
    }
}

fn map_errno<T>(result: Result<T, i32>) -> Result<T, ServiceCallError> {
    result.map_err(ServiceCallError::Errno)
}

fn errno<T>(errno: i32) -> Result<T, ServiceCallError> {
    Err(ServiceCallError::Errno(errno))
}

static mut NET_CORE_STATE: NetCoreState = NetCoreState::new();
static mut LINUX_SOCKET_STATE: LinuxSocketState = LinuxSocketState::new();
static mut DRIVER_STATE: DriverVirtioNetState = DriverVirtioNetState::new();
static mut REPLAY_SNAPSHOT_STATE: ReplaySnapshotState = ReplaySnapshotState::new();

unsafe fn net_core_state() -> &'static mut NetCoreState {
    unsafe { &mut *addr_of_mut!(NET_CORE_STATE) }
}

unsafe fn linux_socket_state() -> &'static mut LinuxSocketState {
    unsafe { &mut *addr_of_mut!(LINUX_SOCKET_STATE) }
}

unsafe fn driver_state() -> &'static mut DriverVirtioNetState {
    unsafe { &mut *addr_of_mut!(DRIVER_STATE) }
}

unsafe fn replay_snapshot_state() -> &'static mut ReplaySnapshotState {
    unsafe { &mut *addr_of_mut!(REPLAY_SNAPSHOT_STATE) }
}
