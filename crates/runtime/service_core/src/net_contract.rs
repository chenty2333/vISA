use vmos_abi::{AF_INET, AF_UNIX, SOCK_DGRAM, SOCK_STREAM};

pub const NETWORK_CONTRACT_VERSION: &str = "vmos-network-contract-v2";
pub const NETWORK_CONTRACT_ABI_VERSION: u32 = 2;
pub const PACKET_FRAME_FORMAT_VERSION: u32 = 2;
pub const PACKET_EVENT_POLICY_DEVICE_NEEDS_POLL: u32 = 1;
pub const PACKET_MAX_PAYLOAD_LEN: u32 = 512;
pub const VIRTIO_NET0_MTU: u32 = 1500;
pub const VIRTIO_NET0_RX_QUEUE_DEPTH: u32 = 4;
pub const VIRTIO_NET0_TX_QUEUE_DEPTH: u32 = 4;
pub const VIRTIO_NET0_MAC: [u8; 6] = [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01];

pub const PROTO_DEMO_TCP: u16 = 1;
pub const PROTO_TCP: u16 = 6;
pub const PROTO_UDP: u16 = 17;
pub const DEMO_CLIENT_PORT: u16 = 40_000;
pub const DEMO_SERVER_PORT: u16 = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketDeviceContract {
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub checksum_offload: bool,
    pub frame_format_version: u32,
    pub event_policy: u32,
    pub max_payload_len: u32,
}

pub const VIRTIO_NET0_CONTRACT: PacketDeviceContract = PacketDeviceContract {
    mtu: VIRTIO_NET0_MTU,
    rx_queue_depth: VIRTIO_NET0_RX_QUEUE_DEPTH,
    tx_queue_depth: VIRTIO_NET0_TX_QUEUE_DEPTH,
    mac: VIRTIO_NET0_MAC,
    checksum_offload: false,
    frame_format_version: PACKET_FRAME_FORMAT_VERSION,
    event_policy: PACKET_EVENT_POLICY_DEVICE_NEEDS_POLL,
    max_payload_len: PACKET_MAX_PAYLOAD_LEN,
};

pub const fn validate_linux_socket_contract(domain: u32, ty: u32, protocol: u32) -> bool {
    const PROTO_DEMO_TCP_U32: u32 = PROTO_DEMO_TCP as u32;
    const PROTO_TCP_U32: u32 = PROTO_TCP as u32;
    const PROTO_UDP_U32: u32 = PROTO_UDP as u32;

    match (domain, ty, protocol) {
        (AF_UNIX, SOCK_DGRAM, 0) => true,
        (AF_INET, SOCK_DGRAM, 0 | PROTO_UDP_U32) => true,
        (AF_INET, SOCK_STREAM, 0 | PROTO_DEMO_TCP_U32 | PROTO_TCP_U32) => true,
        _ => false,
    }
}

pub const fn canonical_socket_protocol(protocol: u32) -> u16 {
    match protocol {
        0 => PROTO_DEMO_TCP,
        other => other as u16,
    }
}

pub const fn validate_packet_device_contract(contract: PacketDeviceContract) -> bool {
    contract.mtu == VIRTIO_NET0_MTU
        && contract.rx_queue_depth == VIRTIO_NET0_RX_QUEUE_DEPTH
        && contract.tx_queue_depth == VIRTIO_NET0_TX_QUEUE_DEPTH
        && contract.mac[0] == VIRTIO_NET0_MAC[0]
        && contract.mac[1] == VIRTIO_NET0_MAC[1]
        && contract.mac[2] == VIRTIO_NET0_MAC[2]
        && contract.mac[3] == VIRTIO_NET0_MAC[3]
        && contract.mac[4] == VIRTIO_NET0_MAC[4]
        && contract.mac[5] == VIRTIO_NET0_MAC[5]
        && contract.frame_format_version == PACKET_FRAME_FORMAT_VERSION
        && contract.event_policy == PACKET_EVENT_POLICY_DEVICE_NEEDS_POLL
        && contract.max_payload_len == PACKET_MAX_PAYLOAD_LEN
        && !contract.checksum_offload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_device_contract_matches_v2_constants() {
        assert_eq!(NETWORK_CONTRACT_VERSION, "vmos-network-contract-v2");
        assert_eq!(NETWORK_CONTRACT_ABI_VERSION, 2);
        assert!(validate_packet_device_contract(VIRTIO_NET0_CONTRACT));
    }

    #[test]
    fn linux_socket_contract_includes_basic_ltp_socket_matrix() {
        assert!(validate_linux_socket_contract(AF_UNIX, SOCK_DGRAM, 0));
        assert!(validate_linux_socket_contract(AF_INET, SOCK_DGRAM, PROTO_UDP as u32));
        assert!(validate_linux_socket_contract(AF_INET, SOCK_STREAM, PROTO_TCP as u32));
        assert!(!validate_linux_socket_contract(AF_INET, SOCK_STREAM, PROTO_UDP as u32));
    }

    #[test]
    fn linux_socket_contract_is_narrow_by_default() {
        assert!(validate_linux_socket_contract(AF_INET, SOCK_STREAM, 0));
        assert!(validate_linux_socket_contract(AF_INET, SOCK_STREAM, PROTO_TCP as u32));
        assert!(validate_linux_socket_contract(AF_INET, SOCK_DGRAM, 0));
        assert!(!validate_linux_socket_contract(AF_INET + 1, SOCK_STREAM, 0));
        assert_eq!(canonical_socket_protocol(0), PROTO_DEMO_TCP);
    }
}
