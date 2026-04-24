use vmos_abi::{AF_INET, SOCK_STREAM};

pub const NETWORK_CONTRACT_VERSION: &str = "vmos-network-contract-v1";
pub const NETWORK_CONTRACT_ABI_VERSION: u32 = 1;
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
}

pub const VIRTIO_NET0_CONTRACT: PacketDeviceContract = PacketDeviceContract {
    mtu: VIRTIO_NET0_MTU,
    rx_queue_depth: VIRTIO_NET0_RX_QUEUE_DEPTH,
    tx_queue_depth: VIRTIO_NET0_TX_QUEUE_DEPTH,
    mac: VIRTIO_NET0_MAC,
    checksum_offload: false,
};

pub const fn validate_linux_socket_contract(domain: u32, ty: u32, protocol: u32) -> bool {
    domain == AF_INET
        && ty == SOCK_STREAM
        && (protocol == 0 || protocol == PROTO_DEMO_TCP as u32 || protocol == PROTO_TCP as u32)
}

pub const fn canonical_socket_protocol(protocol: u32) -> u16 {
    if protocol == 0 {
        PROTO_DEMO_TCP
    } else {
        protocol as u16
    }
}
