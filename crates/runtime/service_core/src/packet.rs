use visa_abi::{ERR_EAGAIN, ERR_EINVAL, ERR_EIO};

use crate::net_contract::PACKET_MAX_PAYLOAD_LEN;
pub use crate::net_contract::{DEMO_CLIENT_PORT, DEMO_SERVER_PORT, PROTO_DEMO_TCP};

pub const FRAME_HEADER_LEN: usize = 20;
pub const PACKET_PAYLOAD_CAPACITY: usize = PACKET_MAX_PAYLOAD_LEN as usize;
pub const PACKET_FRAME_CAPACITY: usize = FRAME_HEADER_LEN + PACKET_PAYLOAD_CAPACITY;
pub const PACKET_RX_QUEUE_DEPTH: usize = 4;

pub const PACKET_FLAG_ACK: u16 = 0x01;
pub const PACKET_FLAG_PAYLOAD: u16 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketFrameMeta {
    pub protocol: u16,
    pub flags: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u32,
    pub sequence: u64,
}

impl PacketFrameMeta {
    pub const EMPTY: Self =
        Self { protocol: 0, flags: 0, src_port: 0, dst_port: 0, payload_len: 0, sequence: 0 };

    pub const fn demo_http_response(sequence: u64, payload_len: usize) -> Self {
        Self {
            protocol: PROTO_DEMO_TCP,
            flags: PACKET_FLAG_ACK | PACKET_FLAG_PAYLOAD,
            src_port: DEMO_SERVER_PORT,
            dst_port: DEMO_CLIENT_PORT,
            payload_len: payload_len as u32,
            sequence,
        }
    }

    pub const fn demo_http_request(sequence: u64, payload_len: usize) -> Self {
        Self {
            protocol: PROTO_DEMO_TCP,
            flags: PACKET_FLAG_PAYLOAD,
            src_port: DEMO_CLIENT_PORT,
            dst_port: DEMO_SERVER_PORT,
            payload_len: payload_len as u32,
            sequence,
        }
    }
}

#[derive(Clone, Copy)]
struct PacketSlot {
    meta: PacketFrameMeta,
    payload: [u8; PACKET_PAYLOAD_CAPACITY],
    payload_len: usize,
    active: bool,
}

impl PacketSlot {
    const EMPTY: Self = Self {
        meta: PacketFrameMeta::EMPTY,
        payload: [0; PACKET_PAYLOAD_CAPACITY],
        payload_len: 0,
        active: false,
    };
}

pub struct PacketDeviceState {
    rx: [PacketSlot; PACKET_RX_QUEUE_DEPTH],
    rx_head: usize,
    rx_len: usize,
    sequence: u64,
}

impl PacketDeviceState {
    pub const fn new() -> Self {
        Self { rx: [PacketSlot::EMPTY; PACKET_RX_QUEUE_DEPTH], rx_head: 0, rx_len: 0, sequence: 1 }
    }

    pub fn reset(&mut self) {
        self.rx = [PacketSlot::EMPTY; PACKET_RX_QUEUE_DEPTH];
        self.rx_head = 0;
        self.rx_len = 0;
        self.sequence = 1;
    }

    pub fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        sequence
    }

    pub fn enqueue_rx(&mut self, meta: PacketFrameMeta, payload: &[u8]) -> Result<u32, i32> {
        if payload.len() > PACKET_PAYLOAD_CAPACITY {
            return Err(ERR_EIO);
        }
        if self.rx_len == PACKET_RX_QUEUE_DEPTH {
            return Err(ERR_EAGAIN);
        }

        let tail = (self.rx_head + self.rx_len) % PACKET_RX_QUEUE_DEPTH;
        self.rx[tail].meta = PacketFrameMeta { payload_len: payload.len() as u32, ..meta };
        self.rx[tail].payload[..payload.len()].copy_from_slice(payload);
        self.rx[tail].payload_len = payload.len();
        self.rx[tail].active = true;
        self.rx_len += 1;
        Ok((FRAME_HEADER_LEN + payload.len()) as u32)
    }

    pub fn dequeue_rx_frame(&mut self, out: &mut [u8]) -> Result<u32, i32> {
        if self.rx_len == 0 {
            return Ok(0);
        }

        let slot = self.rx[self.rx_head];
        if !slot.active {
            return Err(ERR_EIO);
        }
        let len = encode_frame(slot.meta, &slot.payload[..slot.payload_len], out)?;
        self.rx[self.rx_head] = PacketSlot::EMPTY;
        self.rx_head = (self.rx_head + 1) % PACKET_RX_QUEUE_DEPTH;
        self.rx_len -= 1;
        Ok(len as u32)
    }

    pub fn peek_rx_frame_len(&self) -> u32 {
        if self.rx_len == 0 {
            return 0;
        }
        let slot = self.rx[self.rx_head];
        if slot.active { (FRAME_HEADER_LEN + slot.payload_len) as u32 } else { 0 }
    }

    pub fn pending_rx_frames(&self) -> u32 {
        self.rx_len as u32
    }
}

impl Default for PacketDeviceState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode_frame(meta: PacketFrameMeta, payload: &[u8], out: &mut [u8]) -> Result<usize, i32> {
    if payload.len() > PACKET_PAYLOAD_CAPACITY {
        return Err(ERR_EIO);
    }
    let frame_len = FRAME_HEADER_LEN.checked_add(payload.len()).ok_or(ERR_EIO)?;
    if out.len() < frame_len {
        return Err(ERR_EIO);
    }

    out[0..2].copy_from_slice(&meta.protocol.to_le_bytes());
    out[2..4].copy_from_slice(&meta.flags.to_le_bytes());
    out[4..6].copy_from_slice(&meta.src_port.to_le_bytes());
    out[6..8].copy_from_slice(&meta.dst_port.to_le_bytes());
    out[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[12..20].copy_from_slice(&meta.sequence.to_le_bytes());
    out[FRAME_HEADER_LEN..frame_len].copy_from_slice(payload);
    Ok(frame_len)
}

pub fn decode_frame(frame: &[u8]) -> Result<(PacketFrameMeta, &[u8]), i32> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(ERR_EINVAL);
    }

    let payload_len = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    let frame_len = FRAME_HEADER_LEN.checked_add(payload_len).ok_or(ERR_EINVAL)?;
    if frame_len > frame.len() || payload_len > PACKET_PAYLOAD_CAPACITY {
        return Err(ERR_EINVAL);
    }

    let meta = PacketFrameMeta {
        protocol: u16::from_le_bytes([frame[0], frame[1]]),
        flags: u16::from_le_bytes([frame[2], frame[3]]),
        src_port: u16::from_le_bytes([frame[4], frame[5]]),
        dst_port: u16::from_le_bytes([frame[6], frame[7]]),
        payload_len: payload_len as u32,
        sequence: u64::from_le_bytes([
            frame[12], frame[13], frame[14], frame[15], frame[16], frame[17], frame[18], frame[19],
        ]),
    };
    Ok((meta, &frame[FRAME_HEADER_LEN..frame_len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_metadata_and_payload() {
        let payload = b"hello";
        let meta = PacketFrameMeta::demo_http_response(7, payload.len());
        let mut buffer = [0u8; PACKET_FRAME_CAPACITY];

        let len = encode_frame(meta, payload, &mut buffer).unwrap();
        let (decoded, decoded_payload) = decode_frame(&buffer[..len]).unwrap();

        assert_eq!(decoded.protocol, PROTO_DEMO_TCP);
        assert_eq!(decoded.src_port, DEMO_SERVER_PORT);
        assert_eq!(decoded.dst_port, DEMO_CLIENT_PORT);
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn packet_device_dequeues_in_fifo_order() {
        let mut device = PacketDeviceState::new();
        let mut buffer = [0u8; PACKET_FRAME_CAPACITY];
        device.enqueue_rx(PacketFrameMeta::demo_http_response(1, 1), b"a").unwrap();
        device.enqueue_rx(PacketFrameMeta::demo_http_response(2, 1), b"b").unwrap();

        let len = device.dequeue_rx_frame(&mut buffer).unwrap();
        let (meta, payload) = decode_frame(&buffer[..len as usize]).unwrap();
        assert_eq!(meta.sequence, 1);
        assert_eq!(payload, b"a");

        let len = device.dequeue_rx_frame(&mut buffer).unwrap();
        let (meta, payload) = decode_frame(&buffer[..len as usize]).unwrap();
        assert_eq!(meta.sequence, 2);
        assert_eq!(payload, b"b");
    }
}
