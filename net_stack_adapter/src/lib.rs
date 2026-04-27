#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use service_core::net_contract::{
    PacketDeviceContract, VIRTIO_NET0_CONTRACT, validate_packet_device_contract,
};
use smoltcp::iface::{Config, Interface, PollResult, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

pub const SMOLTCP_ADAPTER_IMPLEMENTATION: &str = "smoltcp";
pub const SMOLTCP_ADAPTER_VERSION: &str = "0.13.0";
pub const SMOLTCP_ADAPTER_PROFILE: &str = "smoltcp-0.13.0-ethernet-ipv4-tcp-v1";
pub const SMOLTCP_ADAPTER_MEDIUM: &str = "ethernet";
pub const DEFAULT_IPV4_ADDR: [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_IPV4_PREFIX_LEN: u8 = 24;
pub const DEFAULT_SOCKET_CAPACITY: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmoltcpAdapterConfig {
    pub contract: PacketDeviceContract,
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub random_seed: u64,
    pub socket_capacity: u16,
}

impl SmoltcpAdapterConfig {
    pub const fn default_vmos() -> Self {
        Self {
            contract: VIRTIO_NET0_CONTRACT,
            ipv4_addr: DEFAULT_IPV4_ADDR,
            ipv4_prefix_len: DEFAULT_IPV4_PREFIX_LEN,
            random_seed: 0x766d_6f73_6e65_7430,
            socket_capacity: DEFAULT_SOCKET_CAPACITY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpAdapterEvidence {
    pub implementation: &'static str,
    pub version: &'static str,
    pub profile: &'static str,
    pub medium: &'static str,
    pub hardware_addr: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub poll_result: &'static str,
}

pub fn build_smoltcp_adapter_evidence(
    config: SmoltcpAdapterConfig,
) -> Result<SmoltcpAdapterEvidence, &'static str> {
    if !validate_packet_device_contract(config.contract) {
        return Err("smoltcp adapter packet device contract mismatch");
    }
    if config.ipv4_prefix_len == 0 || config.ipv4_prefix_len > 32 {
        return Err("smoltcp adapter ipv4 prefix is invalid");
    }

    let mut device = Loopback::new(Medium::Ethernet);
    let mut iface_config = Config::new(HardwareAddress::Ethernet(EthernetAddress(
        config.contract.mac,
    )));
    iface_config.random_seed = config.random_seed;
    let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
    let ipv4_addr = Ipv4Address::new(
        config.ipv4_addr[0],
        config.ipv4_addr[1],
        config.ipv4_addr[2],
        config.ipv4_addr[3],
    );
    let mut installed_addr = false;
    iface.update_ip_addrs(|addrs| {
        let cidr = IpCidr::Ipv4(Ipv4Cidr::new(ipv4_addr, config.ipv4_prefix_len));
        installed_addr = addrs.push(cidr).is_ok();
    });
    if !installed_addr {
        return Err("smoltcp adapter failed to install ipv4 cidr");
    }
    if !iface.has_ip_addr(IpAddress::Ipv4(ipv4_addr)) {
        return Err("smoltcp adapter failed to install ipv4 address");
    }

    let mut sockets = SocketSet::new(Vec::new());
    let poll_result = match iface.poll(Instant::from_millis(0), &mut device, &mut sockets) {
        PollResult::None => "none",
        PollResult::SocketStateChanged => "socket-state-changed",
    };

    Ok(SmoltcpAdapterEvidence {
        implementation: SMOLTCP_ADAPTER_IMPLEMENTATION,
        version: SMOLTCP_ADAPTER_VERSION,
        profile: SMOLTCP_ADAPTER_PROFILE,
        medium: SMOLTCP_ADAPTER_MEDIUM,
        hardware_addr: config.contract.mac,
        ipv4_addr: config.ipv4_addr,
        ipv4_prefix_len: config.ipv4_prefix_len,
        mtu: config.contract.mtu,
        rx_queue_depth: config.contract.rx_queue_depth,
        tx_queue_depth: config.contract.tx_queue_depth,
        max_payload_len: config.contract.max_payload_len,
        socket_capacity: config.socket_capacity,
        poll_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoltcp_adapter_builds_ethernet_ipv4_tcp_profile() {
        let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_vmos())
            .expect("smoltcp adapter evidence");

        assert_eq!(evidence.implementation, "smoltcp");
        assert_eq!(evidence.version, "0.13.0");
        assert_eq!(evidence.profile, SMOLTCP_ADAPTER_PROFILE);
        assert_eq!(evidence.medium, "ethernet");
        assert_eq!(evidence.hardware_addr, VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(evidence.ipv4_addr, DEFAULT_IPV4_ADDR);
        assert_eq!(evidence.ipv4_prefix_len, DEFAULT_IPV4_PREFIX_LEN);
        assert_eq!(evidence.mtu, VIRTIO_NET0_CONTRACT.mtu);
        assert_eq!(evidence.socket_capacity, 0);
        assert_eq!(evidence.poll_result, "none");
    }

    #[test]
    fn smoltcp_adapter_rejects_contract_and_prefix_mismatch() {
        let mut config = SmoltcpAdapterConfig::default_vmos();
        config.contract.mtu += 1;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter packet device contract mismatch")
        );

        let mut config = SmoltcpAdapterConfig::default_vmos();
        config.ipv4_prefix_len = 0;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter ipv4 prefix is invalid")
        );
    }
}
