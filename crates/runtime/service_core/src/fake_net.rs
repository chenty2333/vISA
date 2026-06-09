use visa_abi::{ERR_EINVAL, ERR_EIO};

use crate::{
    net_contract::{PACKET_FRAME_FORMAT_VERSION, PACKET_MAX_PAYLOAD_LEN, VIRTIO_NET0_CONTRACT},
    packet::{FRAME_HEADER_LEN, PROTO_DEMO_TCP, PacketFrameMeta, decode_frame, encode_frame},
};

pub const FAKE_NET_BACKEND_PROFILE: &str = "fake-net-v1";
pub const FAKE_NET_BACKEND_PROVIDER: &str = "service_core";
pub const FAKE_NET_BACKEND_SEED: u64 = 0x766d_6f73_6e65_7431;
pub const FAKE_NET_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello visa\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeNetBackendConfig {
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub deterministic_seed: u64,
}

impl FakeNetBackendConfig {
    pub const fn net0() -> Self {
        Self {
            mtu: VIRTIO_NET0_CONTRACT.mtu,
            rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
            tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
            mac: VIRTIO_NET0_CONTRACT.mac,
            frame_format_version: PACKET_FRAME_FORMAT_VERSION,
            max_payload_len: PACKET_MAX_PAYLOAD_LEN,
            deterministic_seed: FAKE_NET_BACKEND_SEED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeNetBackendAction {
    TxAccepted,
    RxSynthesized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeNetBackendEvent {
    pub action: FakeNetBackendAction,
    pub sequence: u64,
    pub frame_len: u32,
}

pub struct FakeNetBackend {
    config: FakeNetBackendConfig,
    next_sequence: u64,
}

impl FakeNetBackend {
    pub const fn new(config: FakeNetBackendConfig) -> Self {
        Self { config, next_sequence: 1 }
    }

    pub const fn config(&self) -> FakeNetBackendConfig {
        self.config
    }

    pub fn submit_tx_frame(&mut self, frame: &[u8]) -> Result<FakeNetBackendEvent, i32> {
        let (meta, payload) = decode_frame(frame)?;
        if meta.protocol != PROTO_DEMO_TCP || payload.is_empty() {
            return Err(ERR_EINVAL);
        }
        if payload.len() > self.config.max_payload_len as usize {
            return Err(ERR_EIO);
        }
        Ok(FakeNetBackendEvent {
            action: FakeNetBackendAction::TxAccepted,
            sequence: meta.sequence,
            frame_len: frame.len() as u32,
        })
    }

    pub fn synthesize_rx_frame(&mut self, out: &mut [u8]) -> Result<FakeNetBackendEvent, i32> {
        if FAKE_NET_RESPONSE.len() > self.config.max_payload_len as usize {
            return Err(ERR_EIO);
        }
        if out.len() < FRAME_HEADER_LEN + FAKE_NET_RESPONSE.len() {
            return Err(ERR_EIO);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let meta = PacketFrameMeta::demo_http_response(sequence, FAKE_NET_RESPONSE.len());
        let frame_len = encode_frame(meta, FAKE_NET_RESPONSE, out)?;
        Ok(FakeNetBackendEvent {
            action: FakeNetBackendAction::RxSynthesized,
            sequence,
            frame_len: frame_len as u32,
        })
    }
}

impl Default for FakeNetBackend {
    fn default() -> Self {
        Self::new(FakeNetBackendConfig::net0())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PACKET_FRAME_CAPACITY, PacketFrameMeta, decode_frame, encode_frame};

    #[test]
    fn fake_net_backend_accepts_demo_tx_and_synthesizes_rx() {
        let mut backend = FakeNetBackend::default();
        let mut tx = [0u8; PACKET_FRAME_CAPACITY];
        let tx_len =
            encode_frame(PacketFrameMeta::demo_http_request(7, 3), b"GET", &mut tx).unwrap();

        let tx_event = backend.submit_tx_frame(&tx[..tx_len]).unwrap();
        assert_eq!(tx_event.action, FakeNetBackendAction::TxAccepted);
        assert_eq!(tx_event.sequence, 7);

        let mut rx = [0u8; PACKET_FRAME_CAPACITY];
        let rx_event = backend.synthesize_rx_frame(&mut rx).unwrap();
        assert_eq!(rx_event.action, FakeNetBackendAction::RxSynthesized);
        assert_eq!(rx_event.sequence, 1);
        let (rx_meta, payload) = decode_frame(&rx[..rx_event.frame_len as usize]).unwrap();
        assert_eq!(rx_meta.protocol, PROTO_DEMO_TCP);
        assert_eq!(payload, FAKE_NET_RESPONSE);
    }

    #[test]
    fn fake_net_backend_rejects_bad_or_oversized_frames() {
        let mut backend = FakeNetBackend::default();
        assert_eq!(backend.submit_tx_frame(&[0u8; 4]), Err(ERR_EINVAL));

        let config = FakeNetBackendConfig { max_payload_len: 1, ..FakeNetBackendConfig::net0() };
        let mut small = FakeNetBackend::new(config);
        let mut rx = [0u8; PACKET_FRAME_CAPACITY];
        assert_eq!(small.synthesize_rx_frame(&mut rx), Err(ERR_EIO));
    }
}
