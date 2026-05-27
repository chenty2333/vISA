use alloc::vec::Vec;

pub(crate) use service_core::driver::DriverNetEventKind;
use service_core::{
    driver::{DriverVirtioNetState, RESPONSE_CAPACITY},
    linux_socket::LinuxSocketState,
    net::{NetCoreState, QUEUE_CAPACITY},
    packet::decode_frame,
    replay::ReplaySnapshotState,
};

use crate::supervisor::{engine::SupervisorEngine, types::ServiceCallError};

const ETHERNET_HEADER_LEN: usize = 14;

pub(crate) struct NetCoreService {
    state: NetCoreState,
}

impl NetCoreService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: NetCoreState::new() })
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

    pub(crate) fn peek_socket(
        &mut self,
        socket_id: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let mut out = alloc::vec![0; count as usize];
        let len = map_errno(self.state.peek_socket(socket_id, count, &mut out))?;
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
    state: LinuxSocketState,
}

impl LinuxSocketService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: LinuxSocketState::new() })
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

    pub(crate) fn register_connected_socket(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
        ready_key: u64,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.register_connected_socket(socket_id, domain, ty, protocol, ready_key))
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        map_errno(self.state.close_socket(socket_id))
    }

    pub(crate) fn bind_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
        family: u32,
        ipv4: u32,
        port: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.bind_socket(socket_id, addr_len, family, ipv4, port))
    }

    pub(crate) fn connect_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
        family: u32,
        ipv4: u32,
        port: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.connect_socket(socket_id, addr_len, family, ipv4, port))
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

    pub(crate) fn ipv4_endpoint(
        &mut self,
        socket_id: u32,
        peer: bool,
    ) -> Result<Option<(u32, u16)>, ServiceCallError> {
        map_errno(self.state.ipv4_endpoint(socket_id, peer))
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

    pub(crate) fn shutdown_socket(
        &mut self,
        socket_id: u32,
        how: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.shutdown_socket(socket_id, how))
    }

    pub(crate) fn setsockopt(
        &mut self,
        socket_id: u32,
        level: u32,
        optname: u32,
        optlen: u32,
        value: u32,
    ) -> Result<(), ServiceCallError> {
        map_errno(self.state.setsockopt(socket_id, level, optname, optlen, value))
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
    state: DriverVirtioNetState,
}

impl DriverVirtioNetService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: DriverVirtioNetState::new() })
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

    #[allow(dead_code)]
    pub(crate) fn deliver_rx_frame(
        &mut self,
        now_ticks: u64,
        frame: &[u8],
    ) -> Result<u32, ServiceCallError> {
        map_errno(self.state.deliver_rx_frame(now_ticks, frame))
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
            payload_len = driver_rx_len(&frame)?;
        } else {
            frame.clear();
        }
        Ok(DriverNetEvent { kind: event.kind, len: payload_len, frame })
    }

    #[allow(dead_code)]
    pub(crate) fn take_tx_frame(&mut self) -> Result<Option<Vec<u8>>, ServiceCallError> {
        let mut frame = alloc::vec![0; RESPONSE_CAPACITY];
        let len = map_errno(self.state.take_tx_frame(&mut frame))?;
        if len == 0 {
            return Ok(None);
        }
        frame.truncate(len as usize);
        Ok(Some(frame))
    }

    #[allow(dead_code)]
    pub(crate) fn pending_rx_frames(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.state.pending_rx_frames())
    }

    #[allow(dead_code)]
    pub(crate) fn pending_tx_frames(&mut self) -> Result<u32, ServiceCallError> {
        Ok(self.state.pending_tx_frames())
    }
}

fn driver_rx_len(frame: &[u8]) -> Result<u32, ServiceCallError> {
    if let Ok((meta, _)) = decode_frame(frame) {
        return Ok(meta.payload_len);
    }
    if frame.len() >= ETHERNET_HEADER_LEN {
        return u32::try_from(frame.len())
            .map_err(|_| ServiceCallError::Invalid("driver returned an oversized raw frame"));
    }
    Err(ServiceCallError::Invalid("driver returned an invalid frame"))
}

pub(crate) struct ReplaySnapshotService {
    state: ReplaySnapshotState,
}

impl ReplaySnapshotService {
    pub(crate) fn new(_engine: &SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self { state: ReplaySnapshotState::new() })
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
