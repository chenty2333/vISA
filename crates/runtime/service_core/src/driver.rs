use vmos_abi::{ERR_EAGAIN, ERR_EINVAL, ERR_EIO};

use crate::{
    net_contract::VIRTIO_NET0_MTU,
    packet::{PROTO_DEMO_TCP, PacketDeviceState, PacketFrameMeta, decode_frame},
};

pub const FIRST_RX_DELAY_TICKS: u64 = 7;
pub const NEXT_RX_DELAY_TICKS: u64 = 20;
pub const ETHERNET_HEADER_LEN: usize = 14;
pub const RAW_ETHERNET_FRAME_CAPACITY: usize = VIRTIO_NET0_MTU as usize + ETHERNET_HEADER_LEN;
pub const REQUEST_CAPACITY: usize = RAW_ETHERNET_FRAME_CAPACITY;
pub const RESPONSE_CAPACITY: usize = RAW_ETHERNET_FRAME_CAPACITY;
pub const RAW_RX_QUEUE_DEPTH: usize = 4;
pub const RAW_TX_QUEUE_DEPTH: usize = 4;
pub const DEMO_HTTP_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello vmos\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverNetEventKind {
    None = 0,
    Irq = 1,
    DmaSubmitted = 2,
    DmaCompleted = 3,
    DriverCompletion = 4,
    PacketRx = 5,
}

impl DriverNetEventKind {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Irq),
            2 => Some(Self::DmaSubmitted),
            3 => Some(Self::DmaCompleted),
            4 => Some(Self::DriverCompletion),
            5 => Some(Self::PacketRx),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DriverNetEvent {
    pub kind: DriverNetEventKind,
    pub len: u32,
}

pub struct DriverVirtioNetState {
    next_tick: u64,
    phase: DriverNetEventKind,
    ready: bool,
    last_len: u32,
    device: PacketDeviceState,
    raw_rx: [RawRxSlot; RAW_RX_QUEUE_DEPTH],
    raw_rx_head: usize,
    raw_rx_len: usize,
    raw_tx: [RawFrameSlot; RAW_TX_QUEUE_DEPTH],
    raw_tx_head: usize,
    raw_tx_len: usize,
    tx_pending: bool,
}

#[derive(Clone, Copy)]
struct RawRxSlot {
    data: [u8; REQUEST_CAPACITY],
    len: usize,
    active: bool,
}

impl RawRxSlot {
    const EMPTY: Self = Self { data: [0; REQUEST_CAPACITY], len: 0, active: false };
}

#[derive(Clone, Copy)]
struct RawFrameSlot {
    data: [u8; RAW_ETHERNET_FRAME_CAPACITY],
    len: usize,
    active: bool,
}

impl RawFrameSlot {
    const EMPTY: Self = Self { data: [0; RAW_ETHERNET_FRAME_CAPACITY], len: 0, active: false };
}

impl DriverVirtioNetState {
    pub const fn new() -> Self {
        Self {
            next_tick: FIRST_RX_DELAY_TICKS,
            phase: DriverNetEventKind::None,
            ready: false,
            last_len: 0,
            device: PacketDeviceState::new(),
            raw_rx: [RawRxSlot::EMPTY; RAW_RX_QUEUE_DEPTH],
            raw_rx_head: 0,
            raw_rx_len: 0,
            raw_tx: [RawFrameSlot::EMPTY; RAW_TX_QUEUE_DEPTH],
            raw_tx_head: 0,
            raw_tx_len: 0,
            tx_pending: false,
        }
    }

    pub fn reset_sequence(&mut self, now_ticks: u64) {
        self.next_tick = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
        self.phase = DriverNetEventKind::None;
        self.ready = false;
        self.last_len = 0;
        self.device.reset();
        self.raw_rx = [RawRxSlot::EMPTY; RAW_RX_QUEUE_DEPTH];
        self.raw_rx_head = 0;
        self.raw_rx_len = 0;
        self.raw_tx = [RawFrameSlot::EMPTY; RAW_TX_QUEUE_DEPTH];
        self.raw_tx_head = 0;
        self.raw_tx_len = 0;
        self.tx_pending = false;
    }

    pub fn submit_tx_frame(&mut self, now_ticks: u64, frame: &[u8]) -> Result<u32, i32> {
        match decode_frame(frame) {
            Ok((meta, payload)) if meta.protocol == PROTO_DEMO_TCP && !payload.is_empty() => {
                self.tx_pending = true;
                self.ready = false;
                self.phase = DriverNetEventKind::None;
                self.next_tick = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
                Ok(payload.len() as u32)
            }
            _ if frame.len() >= ETHERNET_HEADER_LEN => self.enqueue_raw_tx_frame(frame),
            Ok(_) => Ok(0),
            Err(errno) => Err(errno),
        }
    }

    pub fn deliver_rx_frame(&mut self, now_ticks: u64, frame: &[u8]) -> Result<u32, i32> {
        if frame.len() < ETHERNET_HEADER_LEN {
            return Err(ERR_EINVAL);
        }
        if frame.len() > REQUEST_CAPACITY {
            return Err(ERR_EIO);
        }
        if self.raw_rx_len == RAW_RX_QUEUE_DEPTH {
            return Err(ERR_EAGAIN);
        }

        let tail = (self.raw_rx_head + self.raw_rx_len) % RAW_RX_QUEUE_DEPTH;
        self.raw_rx[tail].data[..frame.len()].copy_from_slice(frame);
        self.raw_rx[tail].len = frame.len();
        self.raw_rx[tail].active = true;
        self.raw_rx_len += 1;
        self.ready = false;
        self.phase = DriverNetEventKind::None;
        self.next_tick = now_ticks;
        Ok(frame.len() as u32)
    }

    pub fn poll_device(&mut self, now_ticks: u64) -> DriverNetEvent {
        if !self.tx_pending && self.pending_rx_frames() == 0 {
            self.last_len = 0;
            return DriverNetEvent { kind: DriverNetEventKind::None, len: 0 };
        }
        if self.ready || now_ticks < self.next_tick {
            self.last_len = 0;
            return DriverNetEvent { kind: DriverNetEventKind::None, len: 0 };
        }

        self.phase = match self.phase {
            DriverNetEventKind::None => DriverNetEventKind::Irq,
            DriverNetEventKind::Irq => DriverNetEventKind::DmaSubmitted,
            DriverNetEventKind::DmaSubmitted => DriverNetEventKind::DmaCompleted,
            DriverNetEventKind::DmaCompleted => DriverNetEventKind::DriverCompletion,
            DriverNetEventKind::DriverCompletion | DriverNetEventKind::PacketRx => {
                DriverNetEventKind::PacketRx
            }
        };

        if self.phase == DriverNetEventKind::PacketRx {
            if self.raw_rx_len != 0 {
                self.last_len = self.peek_raw_rx_frame_len();
            } else if self.device.pending_rx_frames() == 0 {
                let sequence = self.device.next_sequence();
                let meta = PacketFrameMeta::demo_http_response(sequence, DEMO_HTTP_RESPONSE.len());
                self.last_len = self.device.enqueue_rx(meta, DEMO_HTTP_RESPONSE).unwrap_or(0);
                self.tx_pending = false;
            } else {
                self.last_len = self.device.peek_rx_frame_len();
                self.tx_pending = false;
            }
            self.ready = true;
            self.next_tick = now_ticks.saturating_add(NEXT_RX_DELAY_TICKS);
        } else {
            self.last_len = 64;
        }

        DriverNetEvent { kind: self.phase, len: self.last_len }
    }

    pub fn event_len(&self) -> u32 {
        self.last_len
    }

    pub fn dequeue_rx_frame(&mut self, out: &mut [u8]) -> Result<u32, i32> {
        let dequeued_raw = self.raw_rx_len != 0;
        let len = if dequeued_raw {
            self.dequeue_raw_rx_frame(out)?
        } else {
            self.device.dequeue_rx_frame(out)?
        };
        if len != 0 {
            self.ready = false;
            self.phase = DriverNetEventKind::None;
            if dequeued_raw && self.raw_rx_len != 0 {
                self.next_tick = 0;
            }
        }
        Ok(len)
    }

    pub fn pending_rx_frames(&self) -> u32 {
        self.device.pending_rx_frames().saturating_add(self.raw_rx_len as u32)
    }

    pub fn pending_tx_frames(&self) -> u32 {
        self.raw_tx_len as u32
    }

    pub fn take_tx_frame(&mut self, out: &mut [u8]) -> Result<u32, i32> {
        if self.raw_tx_len == 0 {
            return Ok(0);
        }
        let index = self.raw_tx_head;
        if !self.raw_tx[index].active {
            return Err(ERR_EIO);
        }
        let len = self.raw_tx[index].len;
        if out.len() < len {
            return Err(ERR_EIO);
        }
        out[..len].copy_from_slice(&self.raw_tx[index].data[..len]);
        self.raw_tx[index] = RawFrameSlot::EMPTY;
        self.raw_tx_head = (self.raw_tx_head + 1) % RAW_TX_QUEUE_DEPTH;
        self.raw_tx_len -= 1;
        Ok(len as u32)
    }

    fn enqueue_raw_tx_frame(&mut self, frame: &[u8]) -> Result<u32, i32> {
        if frame.len() > RAW_ETHERNET_FRAME_CAPACITY {
            return Err(ERR_EIO);
        }
        if self.raw_tx_len == RAW_TX_QUEUE_DEPTH {
            return Err(ERR_EAGAIN);
        }

        let tail = (self.raw_tx_head + self.raw_tx_len) % RAW_TX_QUEUE_DEPTH;
        self.raw_tx[tail].data[..frame.len()].copy_from_slice(frame);
        self.raw_tx[tail].len = frame.len();
        self.raw_tx[tail].active = true;
        self.raw_tx_len += 1;
        Ok(frame.len() as u32)
    }

    fn peek_raw_rx_frame_len(&self) -> u32 {
        if self.raw_rx_len == 0 {
            return 0;
        }
        let slot = &self.raw_rx[self.raw_rx_head];
        if slot.active { slot.len as u32 } else { 0 }
    }

    fn dequeue_raw_rx_frame(&mut self, out: &mut [u8]) -> Result<u32, i32> {
        if self.raw_rx_len == 0 {
            return Ok(0);
        }
        let index = self.raw_rx_head;
        if !self.raw_rx[index].active {
            return Err(ERR_EIO);
        }
        let len = self.raw_rx[index].len;
        if out.len() < len {
            return Err(ERR_EIO);
        }
        out[..len].copy_from_slice(&self.raw_rx[index].data[..len]);
        self.raw_rx[index] = RawRxSlot::EMPTY;
        self.raw_rx_head = (self.raw_rx_head + 1) % RAW_RX_QUEUE_DEPTH;
        self.raw_rx_len -= 1;
        Ok(len as u32)
    }
}

impl Default for DriverVirtioNetState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PACKET_FRAME_CAPACITY, PacketFrameMeta, encode_frame};

    #[test]
    fn tx_submission_drives_rx_event_sequence() {
        let mut driver = DriverVirtioNetState::new();
        let mut request = [0u8; PACKET_FRAME_CAPACITY];
        let request_len =
            encode_frame(PacketFrameMeta::demo_http_request(1, 3), b"GET", &mut request).unwrap();

        assert_eq!(driver.poll_device(FIRST_RX_DELAY_TICKS).kind, DriverNetEventKind::None);
        assert_eq!(driver.submit_tx_frame(10, &request[..request_len]).unwrap(), 3);
        assert_eq!(driver.poll_device(10).kind, DriverNetEventKind::None);
        assert_eq!(driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind, DriverNetEventKind::Irq);
        assert_eq!(
            driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind,
            DriverNetEventKind::DmaSubmitted
        );
        assert_eq!(
            driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind,
            DriverNetEventKind::DmaCompleted
        );
        assert_eq!(
            driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind,
            DriverNetEventKind::DriverCompletion
        );
        assert_eq!(
            driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind,
            DriverNetEventKind::PacketRx
        );

        let mut response = [0u8; PACKET_FRAME_CAPACITY];
        let response_len = driver.dequeue_rx_frame(&mut response).unwrap();
        let (_meta, payload) =
            crate::packet::decode_frame(&response[..response_len as usize]).unwrap();
        assert_eq!(payload, DEMO_HTTP_RESPONSE);
        assert_eq!(driver.poll_device(10 + FIRST_RX_DELAY_TICKS).kind, DriverNetEventKind::None);
    }

    #[test]
    fn raw_ethernet_tx_is_queued_without_synthetic_rx() {
        let mut driver = DriverVirtioNetState::new();
        let mut frame = [0u8; 42];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01]);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        assert_eq!(driver.submit_tx_frame(5, &frame).unwrap(), frame.len() as u32);
        assert_eq!(driver.pending_tx_frames(), 1);
        assert_eq!(driver.poll_device(5 + FIRST_RX_DELAY_TICKS).kind, DriverNetEventKind::None);
        assert_eq!(driver.pending_rx_frames(), 0);

        let mut out = [0u8; RESPONSE_CAPACITY];
        let len = driver.take_tx_frame(&mut out).unwrap();
        assert_eq!(len, frame.len() as u32);
        assert_eq!(&out[..frame.len()], &frame);
        assert_eq!(driver.pending_tx_frames(), 0);
    }

    #[test]
    fn raw_ethernet_tx_rejects_full_queue() {
        let mut driver = DriverVirtioNetState::new();
        let mut frame = [0u8; 42];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01]);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        for _ in 0..RAW_TX_QUEUE_DEPTH {
            assert_eq!(driver.submit_tx_frame(5, &frame).unwrap(), frame.len() as u32);
        }
        assert_eq!(driver.submit_tx_frame(5, &frame), Err(vmos_abi::ERR_EAGAIN));
    }

    #[test]
    fn delivered_raw_ethernet_rx_drives_rx_event_sequence() {
        let mut driver = DriverVirtioNetState::new();
        let mut frame = [0u8; 42];
        frame[..6].copy_from_slice(&[0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01]);
        frame[6..12].copy_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        assert_eq!(driver.deliver_rx_frame(12, &frame).unwrap(), frame.len() as u32);
        assert_eq!(driver.pending_rx_frames(), 1);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::Irq);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DmaSubmitted);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DmaCompleted);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DriverCompletion);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::PacketRx);
        assert_eq!(driver.event_len(), frame.len() as u32);

        let mut out = [0u8; PACKET_FRAME_CAPACITY];
        let len = driver.dequeue_rx_frame(&mut out).unwrap();
        assert_eq!(len, frame.len() as u32);
        assert_eq!(&out[..frame.len()], &frame);
        assert_eq!(driver.pending_rx_frames(), 0);
    }

    #[test]
    fn delivered_raw_ethernet_rx_batch_rearms_after_dequeue() {
        let mut driver = DriverVirtioNetState::new();
        let mut frame = [0u8; 42];
        frame[..6].copy_from_slice(&[0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01]);
        frame[6..12].copy_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        assert_eq!(driver.deliver_rx_frame(12, &frame).unwrap(), frame.len() as u32);
        assert_eq!(driver.deliver_rx_frame(12, &frame).unwrap(), frame.len() as u32);
        for _ in 0..5 {
            driver.poll_device(12);
        }

        let mut out = [0u8; PACKET_FRAME_CAPACITY];
        assert_eq!(driver.dequeue_rx_frame(&mut out).unwrap(), frame.len() as u32);
        assert_eq!(driver.pending_rx_frames(), 1);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::Irq);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DmaSubmitted);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DmaCompleted);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::DriverCompletion);
        assert_eq!(driver.poll_device(12).kind, DriverNetEventKind::PacketRx);
    }

    #[test]
    fn delivered_raw_ethernet_rx_accepts_full_mtu_frame() {
        let mut driver = DriverVirtioNetState::new();
        let mut frame = [0u8; RAW_ETHERNET_FRAME_CAPACITY];
        frame[..6].copy_from_slice(&[0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01]);
        frame[6..12].copy_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        assert_eq!(driver.deliver_rx_frame(12, &frame).unwrap(), frame.len() as u32);
        for _ in 0..5 {
            driver.poll_device(12);
        }

        let mut out = [0u8; RESPONSE_CAPACITY];
        let len = driver.dequeue_rx_frame(&mut out).unwrap();
        assert_eq!(len, frame.len() as u32);
        assert_eq!(&out[..frame.len()], &frame);
    }

    #[test]
    fn delivered_raw_ethernet_rx_rejects_short_or_full_queue() {
        let mut driver = DriverVirtioNetState::new();
        let frame = [0xff; 42];

        assert_eq!(driver.deliver_rx_frame(0, &[0u8; 4]), Err(vmos_abi::ERR_EINVAL));
        assert_eq!(
            driver.deliver_rx_frame(0, &[0u8; REQUEST_CAPACITY + 1]),
            Err(vmos_abi::ERR_EIO)
        );
        for _ in 0..RAW_RX_QUEUE_DEPTH {
            assert_eq!(driver.deliver_rx_frame(0, &frame).unwrap(), frame.len() as u32);
        }
        assert_eq!(driver.deliver_rx_frame(0, &frame), Err(vmos_abi::ERR_EAGAIN));
    }

    #[test]
    fn short_tx_frame_is_rejected() {
        let mut driver = DriverVirtioNetState::new();

        assert_eq!(driver.submit_tx_frame(0, &[0u8; 4]), Err(vmos_abi::ERR_EINVAL));
    }
}
