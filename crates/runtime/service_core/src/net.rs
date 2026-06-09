use visa_abi::{EPOLLIN, EPOLLOUT, ERR_EAGAIN, ERR_EBADF, ERR_EIO, ERR_EOPNOTSUPP};

use crate::{
    net_contract::{canonical_socket_protocol, validate_linux_socket_contract},
    packet::{
        DEMO_CLIENT_PORT, DEMO_SERVER_PORT, PROTO_DEMO_TCP, PacketFrameMeta, decode_frame,
        encode_frame,
    },
};

pub const MAX_SOCKETS: usize = 16;
pub const QUEUE_CAPACITY: usize = 512;
pub const RX_QUEUE_CAPACITY: usize = 4096;
pub const READY_KEY_BASE: u64 = 0x6e65_7473_6f63_0000;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Socket {
    id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    local_port: u16,
    remote_port: u16,
    state: u32,
    rx_len: usize,
    rx_capacity: usize,
    tx_len: usize,
    active: bool,
}

impl Socket {
    const EMPTY: Self = Self {
        id: 0,
        domain: 0,
        ty: 0,
        protocol: 0,
        ready_key: 0,
        local_port: 0,
        remote_port: 0,
        state: 0,
        rx_len: 0,
        rx_capacity: RX_QUEUE_CAPACITY,
        tx_len: 0,
        active: false,
    };
}

pub struct NetCoreState {
    sockets: [Socket; MAX_SOCKETS],
    rx_queues: [[u8; RX_QUEUE_CAPACITY]; MAX_SOCKETS],
    tx_queues: [[u8; QUEUE_CAPACITY]; MAX_SOCKETS],
    next_socket_id: u32,
    next_sequence: u64,
}

impl NetCoreState {
    pub const fn new() -> Self {
        Self {
            sockets: [Socket::EMPTY; MAX_SOCKETS],
            rx_queues: [[0; RX_QUEUE_CAPACITY]; MAX_SOCKETS],
            tx_queues: [[0; QUEUE_CAPACITY]; MAX_SOCKETS],
            next_socket_id: 1,
            next_sequence: 1,
        }
    }

    pub fn create_socket(&mut self, domain: u32, ty: u32, protocol: u32) -> Result<u32, i32> {
        if !validate_linux_socket_contract(domain, ty, protocol) {
            return Err(ERR_EOPNOTSUPP);
        }
        let socket_id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.saturating_add(1);
        let protocol = canonical_socket_protocol(protocol) as u32;
        for socket in &mut self.sockets {
            if !socket.active {
                *socket = Socket {
                    id: socket_id,
                    domain,
                    ty,
                    protocol,
                    ready_key: READY_KEY_BASE | socket_id as u64,
                    local_port: 0,
                    remote_port: 0,
                    state: 1,
                    rx_len: 0,
                    rx_capacity: RX_QUEUE_CAPACITY,
                    tx_len: 0,
                    active: true,
                };
                return Ok(socket_id);
            }
        }
        Err(ERR_EIO)
    }

    pub fn close_socket(&mut self, socket_id: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        self.sockets[index] = Socket::EMPTY;
        self.rx_queues[index] = [0; RX_QUEUE_CAPACITY];
        self.tx_queues[index] = [0; QUEUE_CAPACITY];
        Ok(())
    }

    pub fn ready_key(&self, socket_id: u32) -> Result<u64, i32> {
        Ok(self.sockets[self.socket_index(socket_id)?].ready_key)
    }

    pub fn poll_socket(&self, socket_id: u32) -> Result<u32, i32> {
        let socket = self.sockets[self.socket_index(socket_id)?];
        let mut events = EPOLLOUT;
        if socket.rx_len > 0 {
            events |= EPOLLIN;
        }
        Ok(events)
    }

    pub fn set_recv_capacity(&mut self, socket_id: u32, capacity: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        self.sockets[index].rx_capacity = (capacity as usize).clamp(1, RX_QUEUE_CAPACITY);
        Ok(())
    }

    pub fn send_socket(&mut self, socket_id: u32, bytes: &[u8]) -> Result<u32, i32> {
        if bytes.len() > QUEUE_CAPACITY {
            return Err(ERR_EIO);
        }
        let index = self.socket_index(socket_id)?;
        self.tx_queues[index][..bytes.len()].copy_from_slice(bytes);
        if self.sockets[index].local_port == 0 {
            self.sockets[index].local_port = DEMO_CLIENT_PORT;
        }
        if self.sockets[index].remote_port == 0 {
            self.sockets[index].remote_port = DEMO_SERVER_PORT;
        }
        self.sockets[index].tx_len = bytes.len();
        self.sockets[index].state = 2;
        Ok(bytes.len() as u32)
    }

    pub fn take_tx_frame(&mut self, socket_id: u32, out: &mut [u8]) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        let tx_len = self.sockets[index].tx_len;
        if tx_len == 0 {
            return Err(ERR_EAGAIN);
        }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let meta = PacketFrameMeta::demo_http_request(sequence, tx_len);
        let len = encode_frame(meta, &self.tx_queues[index][..tx_len], out)?;
        self.sockets[index].tx_len = 0;
        Ok(len as u32)
    }

    pub fn recv_socket(&mut self, socket_id: u32, count: u32, out: &mut [u8]) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        let rx_len = self.sockets[index].rx_len;
        if rx_len == 0 {
            return Err(ERR_EAGAIN);
        }
        let len = rx_len.min(count as usize).min(out.len());
        out[..len].copy_from_slice(&self.rx_queues[index][..len]);
        let remaining = rx_len - len;
        if remaining == 0 {
            self.sockets[index].rx_len = 0;
        } else {
            self.rx_queues[index].copy_within(len..rx_len, 0);
            self.sockets[index].rx_len = remaining;
        }
        Ok(len as u32)
    }

    pub fn peek_socket(&mut self, socket_id: u32, count: u32, out: &mut [u8]) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        let rx_len = self.sockets[index].rx_len;
        if rx_len == 0 {
            return Err(ERR_EAGAIN);
        }
        let len = rx_len.min(count as usize).min(out.len());
        out[..len].copy_from_slice(&self.rx_queues[index][..len]);
        Ok(len as u32)
    }

    pub fn deliver_packet_frame(&mut self, frame: &[u8]) -> Result<Option<u64>, i32> {
        let (meta, payload) = decode_frame(frame)?;
        if meta.protocol != PROTO_DEMO_TCP {
            return Ok(None);
        }

        let Some(index) = self.socket_index_for_packet(meta.dst_port, meta.src_port) else {
            return Ok(None);
        };
        let rx_len = self.sockets[index].rx_len;
        let next_rx_len = rx_len.checked_add(payload.len()).ok_or(ERR_EAGAIN)?;
        if next_rx_len > self.sockets[index].rx_capacity {
            return Err(ERR_EAGAIN);
        }
        self.rx_queues[index][rx_len..next_rx_len].copy_from_slice(payload);
        self.sockets[index].rx_len = next_rx_len;
        self.sockets[index].remote_port = meta.src_port;
        self.sockets[index].state = 3;
        Ok(Some(self.sockets[index].ready_key))
    }

    pub fn socket_count(&self) -> u32 {
        self.sockets.iter().filter(|socket| socket.active).count() as u32
    }

    pub fn queued_rx_bytes(&self) -> u32 {
        self.sockets.iter().fold(0u32, |acc, socket| {
            if socket.active { acc.saturating_add(socket.rx_len as u32) } else { acc }
        })
    }

    fn socket_index(&self, socket_id: u32) -> Result<usize, i32> {
        self.sockets
            .iter()
            .position(|socket| socket.active && socket.id == socket_id)
            .ok_or(ERR_EBADF)
    }

    fn socket_index_for_packet(&self, dst_port: u16, src_port: u16) -> Option<usize> {
        self.sockets.iter().position(|socket| {
            socket.active
                && socket.local_port == dst_port
                && (socket.remote_port == 0 || socket.remote_port == src_port)
        })
    }
}

impl Default for NetCoreState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        PACKET_FRAME_CAPACITY, PACKET_PAYLOAD_CAPACITY, PacketFrameMeta, encode_frame,
    };

    #[test]
    fn packet_frame_routes_to_matching_socket_endpoint() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET / HTTP/1.0\r\n\r\n").unwrap();

        let mut tx_frame = [0u8; PACKET_FRAME_CAPACITY];
        let tx_frame_len = state.take_tx_frame(socket, &mut tx_frame).unwrap();
        let (tx_meta, tx_payload) =
            crate::packet::decode_frame(&tx_frame[..tx_frame_len as usize]).unwrap();
        assert_eq!(tx_meta.src_port, DEMO_CLIENT_PORT);
        assert_eq!(tx_meta.dst_port, DEMO_SERVER_PORT);
        assert_eq!(tx_payload, b"GET / HTTP/1.0\r\n\r\n");

        let payload = b"HTTP/1.0 200 OK\r\n\r\n";
        let meta = PacketFrameMeta::demo_http_response(1, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).unwrap();
        let ready_key = state.deliver_packet_frame(&frame[..frame_len]).unwrap();

        assert_eq!(ready_key, Some(READY_KEY_BASE | socket as u64));
        let mut out = [0u8; 64];
        let len = state.recv_socket(socket, out.len() as u32, &mut out).unwrap();
        assert_eq!(&out[..len as usize], payload);
    }

    #[test]
    fn peek_socket_preserves_queued_payload_for_later_recv() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET / HTTP/1.0\r\n\r\n").unwrap();

        let payload = b"HTTP/1.0 200 OK\r\n\r\n";
        let meta = PacketFrameMeta::demo_http_response(1, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).unwrap();
        let ready_key = state.deliver_packet_frame(&frame[..frame_len]).unwrap();
        assert_eq!(ready_key, Some(READY_KEY_BASE | socket as u64));

        let mut peek = [0u8; 8];
        let peek_len = state.peek_socket(socket, peek.len() as u32, &mut peek).unwrap();
        assert_eq!(&peek[..peek_len as usize], &payload[..peek.len()]);
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, EPOLLIN);

        let mut out = [0u8; 64];
        let len = state.recv_socket(socket, out.len() as u32, &mut out).unwrap();
        assert_eq!(&out[..len as usize], payload);
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, 0);
    }

    #[test]
    fn recv_socket_partial_read_preserves_unread_tail() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET / HTTP/1.0\r\n\r\n").unwrap();

        let payload = b"HTTP/1.0 200 OK\r\n\r\n";
        let meta = PacketFrameMeta::demo_http_response(1, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).unwrap();
        state.deliver_packet_frame(&frame[..frame_len]).unwrap();

        let mut first = [0u8; 8];
        let first_len = state.recv_socket(socket, first.len() as u32, &mut first).unwrap();
        assert_eq!(&first[..first_len as usize], &payload[..first.len()]);
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, EPOLLIN);

        let mut second = [0u8; 64];
        let second_len = state.recv_socket(socket, second.len() as u32, &mut second).unwrap();
        assert_eq!(&second[..second_len as usize], &payload[first.len()..]);
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, 0);
    }

    #[test]
    fn delivered_frames_append_without_overwriting_queued_payload() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET /first HTTP/1.0\r\n\r\n").unwrap();

        let first = b"first ";
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let first_meta = PacketFrameMeta::demo_http_response(1, first.len());
        let first_frame_len = encode_frame(first_meta, first, &mut frame).unwrap();
        assert_eq!(
            state.deliver_packet_frame(&frame[..first_frame_len]).unwrap(),
            Some(READY_KEY_BASE | socket as u64)
        );

        let second = b"second";
        let second_meta = PacketFrameMeta::demo_http_response(2, second.len());
        let second_frame_len = encode_frame(second_meta, second, &mut frame).unwrap();
        assert_eq!(
            state.deliver_packet_frame(&frame[..second_frame_len]).unwrap(),
            Some(READY_KEY_BASE | socket as u64)
        );

        let mut out = [0u8; 16];
        let len = state.recv_socket(socket, out.len() as u32, &mut out).unwrap();
        assert_eq!(&out[..len as usize], b"first second");
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, 0);
    }

    #[test]
    fn delivered_frame_overflow_preserves_existing_receive_queue() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET /overflow HTTP/1.0\r\n\r\n").unwrap();
        state.set_recv_capacity(socket, (QUEUE_CAPACITY - 4) as u32).unwrap();

        let first = [b'a'; QUEUE_CAPACITY - 4];
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let first_meta = PacketFrameMeta::demo_http_response(1, first.len());
        let first_frame_len = encode_frame(first_meta, &first, &mut frame).unwrap();
        assert_eq!(
            state.deliver_packet_frame(&frame[..first_frame_len]).unwrap(),
            Some(READY_KEY_BASE | socket as u64)
        );

        let overflow = b"excess";
        let overflow_meta = PacketFrameMeta::demo_http_response(2, overflow.len());
        let overflow_frame_len = encode_frame(overflow_meta, overflow, &mut frame).unwrap();
        assert_eq!(state.deliver_packet_frame(&frame[..overflow_frame_len]), Err(ERR_EAGAIN));

        let mut out = [0u8; QUEUE_CAPACITY];
        let len = state.recv_socket(socket, out.len() as u32, &mut out).unwrap();
        assert_eq!(len as usize, first.len());
        assert!(out[..first.len()].iter().all(|byte| *byte == b'a'));
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, 0);
    }

    #[test]
    fn recv_capacity_limits_delivered_frame_queue_without_data_loss() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();
        state.send_socket(socket, b"GET /capacity HTTP/1.0\r\n\r\n").unwrap();
        state.set_recv_capacity(socket, 2048).unwrap();

        let payload = [b'q'; PACKET_PAYLOAD_CAPACITY];
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        for sequence in 1..=4 {
            let meta = PacketFrameMeta::demo_http_response(sequence, payload.len());
            let frame_len = encode_frame(meta, &payload, &mut frame).unwrap();
            assert_eq!(
                state.deliver_packet_frame(&frame[..frame_len]).unwrap(),
                Some(READY_KEY_BASE | socket as u64)
            );
        }

        let meta = PacketFrameMeta::demo_http_response(5, payload.len());
        let frame_len = encode_frame(meta, &payload, &mut frame).unwrap();
        assert_eq!(state.deliver_packet_frame(&frame[..frame_len]), Err(ERR_EAGAIN));

        let mut out = [0u8; 2048];
        let len = state.recv_socket(socket, out.len() as u32, &mut out).unwrap();
        assert_eq!(len as usize, out.len());
        assert!(out.iter().all(|byte| *byte == b'q'));
        assert_eq!(state.poll_socket(socket).unwrap() & EPOLLIN, 0);
    }

    #[test]
    fn poll_socket_reports_writable_and_readable_after_rx_delivery() {
        let mut state = NetCoreState::new();
        let socket = state.create_socket(2, 1, 0).unwrap();

        let initial = state.poll_socket(socket).unwrap();
        assert_eq!(initial & EPOLLOUT, EPOLLOUT);
        assert_eq!(initial & EPOLLIN, 0);

        state.send_socket(socket, b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let payload = b"HTTP/1.0 200 OK\r\n\r\n";
        let meta = PacketFrameMeta::demo_http_response(2, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).unwrap();
        let ready_key = state.deliver_packet_frame(&frame[..frame_len]).unwrap();

        assert_eq!(ready_key, Some(READY_KEY_BASE | socket as u64));
        let ready = state.poll_socket(socket).unwrap();
        assert_eq!(ready & EPOLLOUT, EPOLLOUT);
        assert_eq!(ready & EPOLLIN, EPOLLIN);
    }

    #[test]
    fn socket_creation_enforces_network_contract() {
        let mut state = NetCoreState::new();

        assert!(state.create_socket(2, 1, 0).is_ok());
        assert!(state.create_socket(2, 2, crate::net_contract::PROTO_UDP as u32).is_ok());
        assert_eq!(state.create_socket(99, 1, 0), Err(ERR_EOPNOTSUPP));
    }
}
