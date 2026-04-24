pub const REQUEST_CAPACITY: usize = 128;
pub const RESPONSE_CAPACITY: usize = 512;
pub const FIRST_RX_DELAY_TICKS: u64 = 7;
pub const NEXT_RX_DELAY_TICKS: u64 = 20;
pub const PACKET: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello vmos\n";

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
}

impl DriverVirtioNetState {
    pub const fn new() -> Self {
        Self {
            next_tick: FIRST_RX_DELAY_TICKS,
            phase: DriverNetEventKind::None,
            ready: false,
            last_len: 0,
        }
    }

    pub fn reset_sequence(&mut self, now_ticks: u64) {
        self.next_tick = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
        self.phase = DriverNetEventKind::None;
        self.ready = false;
        self.last_len = 0;
    }

    pub fn poll_device(&mut self, now_ticks: u64, packet_out: &mut [u8]) -> DriverNetEvent {
        if self.ready || now_ticks < self.next_tick {
            self.last_len = 0;
            return DriverNetEvent {
                kind: DriverNetEventKind::None,
                len: 0,
            };
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
            let len = PACKET.len().min(packet_out.len());
            packet_out[..len].copy_from_slice(&PACKET[..len]);
            self.last_len = len as u32;
            self.ready = true;
            self.next_tick = now_ticks.saturating_add(NEXT_RX_DELAY_TICKS);
        } else {
            self.last_len = 64;
        }

        DriverNetEvent {
            kind: self.phase,
            len: self.last_len,
        }
    }

    pub fn event_len(&self) -> u32 {
        self.last_len
    }

    pub fn consume_packet(&mut self) {
        self.ready = false;
        self.phase = DriverNetEventKind::None;
    }
}

impl Default for DriverVirtioNetState {
    fn default() -> Self {
        Self::new()
    }
}
