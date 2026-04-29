use crate::packet::{
    PACKET_FRAME_CAPACITY, PROTO_DEMO_TCP, PacketDeviceState, PacketFrameMeta, decode_frame,
};

pub const REQUEST_CAPACITY: usize = PACKET_FRAME_CAPACITY;
pub const RESPONSE_CAPACITY: usize = PACKET_FRAME_CAPACITY;
pub const FIRST_RX_DELAY_TICKS: u64 = 7;
pub const NEXT_RX_DELAY_TICKS: u64 = 20;
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
    tx_pending: bool,
}

impl DriverVirtioNetState {
    pub const fn new() -> Self {
        Self {
            next_tick: FIRST_RX_DELAY_TICKS,
            phase: DriverNetEventKind::None,
            ready: false,
            last_len: 0,
            device: PacketDeviceState::new(),
            tx_pending: false,
        }
    }

    pub fn reset_sequence(&mut self, now_ticks: u64) {
        self.next_tick = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
        self.phase = DriverNetEventKind::None;
        self.ready = false;
        self.last_len = 0;
        self.device.reset();
        self.tx_pending = false;
    }

    pub fn submit_tx_frame(&mut self, now_ticks: u64, frame: &[u8]) -> Result<u32, i32> {
        let (meta, payload) = decode_frame(frame)?;
        if meta.protocol != PROTO_DEMO_TCP || payload.is_empty() {
            return Ok(0);
        }
        self.tx_pending = true;
        self.ready = false;
        self.phase = DriverNetEventKind::None;
        self.next_tick = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
        Ok(payload.len() as u32)
    }

    pub fn poll_device(&mut self, now_ticks: u64) -> DriverNetEvent {
        if !self.tx_pending && self.device.pending_rx_frames() == 0 {
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
            if self.device.pending_rx_frames() == 0 {
                let sequence = self.device.next_sequence();
                let meta = PacketFrameMeta::demo_http_response(sequence, DEMO_HTTP_RESPONSE.len());
                self.last_len = self.device.enqueue_rx(meta, DEMO_HTTP_RESPONSE).unwrap_or(0);
            } else {
                self.last_len = self.device.peek_rx_frame_len();
            }
            self.tx_pending = false;
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
        let len = self.device.dequeue_rx_frame(out)?;
        if len != 0 {
            self.ready = false;
            self.phase = DriverNetEventKind::None;
        }
        Ok(len)
    }

    pub fn pending_rx_frames(&self) -> u32 {
        self.device.pending_rx_frames()
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
    use crate::packet::{PacketFrameMeta, encode_frame};

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
}
