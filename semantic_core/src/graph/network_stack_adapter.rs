use super::*;

pub const NETWORK_STACK_ADAPTER_IMPLEMENTATION_SMOLTCP: &str = "smoltcp";
pub const NETWORK_STACK_ADAPTER_VERSION_SMOLTCP_0_13: &str = "0.13.0";
pub const NETWORK_STACK_ADAPTER_PROFILE_SMOLTCP_V1: &str = "smoltcp-0.13.0-ethernet-ipv4-tcp-v1";
pub const NETWORK_STACK_ADAPTER_MEDIUM_ETHERNET: &str = "ethernet";

impl SemanticGraph {
    pub(crate) fn validate_network_stack_adapter(
        &self,
        adapter: NetworkStackAdapterId,
        backend: ContractObjectRef,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        implementation: &str,
        implementation_version: &str,
        profile: &str,
        medium: &str,
        mac: [u8; 6],
        ipv4_addr: [u8; 4],
        ipv4_prefix_len: u8,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        max_payload_len: u32,
        socket_capacity: u16,
    ) -> Result<(), &'static str> {
        if adapter == 0 {
            return Err("network stack adapter id=0 is invalid");
        }
        if self
            .network_stack_adapters
            .iter()
            .any(|record| record.id == adapter)
        {
            return Err("network stack adapter already exists");
        }
        if implementation != NETWORK_STACK_ADAPTER_IMPLEMENTATION_SMOLTCP
            || implementation_version != NETWORK_STACK_ADAPTER_VERSION_SMOLTCP_0_13
            || profile != NETWORK_STACK_ADAPTER_PROFILE_SMOLTCP_V1
            || medium != NETWORK_STACK_ADAPTER_MEDIUM_ETHERNET
        {
            return Err("network stack adapter profile is unsupported");
        }
        if ipv4_prefix_len == 0 || ipv4_prefix_len > 32 {
            return Err("network stack adapter ipv4 prefix is invalid");
        }
        if ipv4_addr == [0, 0, 0, 0] || ipv4_addr == [255, 255, 255, 255] {
            return Err("network stack adapter ipv4 address is invalid");
        }
        if socket_capacity != 0 {
            return Err("network stack adapter must not own sockets before N11");
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network stack adapter packet device generation is missing or inactive");
        };
        if packet_device_record.mac != mac
            || packet_device_record.mtu != mtu
            || packet_device_record.rx_queue_depth != rx_queue_depth
            || packet_device_record.tx_queue_depth != tx_queue_depth
            || packet_device_record.max_payload_len != max_payload_len
        {
            return Err("network stack adapter packet device contract mismatch");
        }
        let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == rx_queue
                && record.generation == rx_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network stack adapter rx queue generation is missing or inactive");
        };
        let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == tx_queue
                && record.generation == tx_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network stack adapter tx queue generation is missing or inactive");
        };
        if rx_queue_record.role != PacketQueueRole::Rx
            || tx_queue_record.role != PacketQueueRole::Tx
            || rx_queue_record.packet_device != packet_device_record.id
            || rx_queue_record.packet_device_generation != packet_device_record.generation
            || tx_queue_record.packet_device != packet_device_record.id
            || tx_queue_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network stack adapter queues do not match packet device contract");
        }
        let Some((backend_packet_device, backend_packet_device_generation)) =
            self.live_network_stack_backend_packet_device(backend)
        else {
            return Err("network stack adapter backend generation is missing or inactive");
        };
        if backend_packet_device != packet_device_record.id
            || backend_packet_device_generation != packet_device_record.generation
        {
            return Err("network stack adapter backend packet device mismatch");
        }
        if self.network_stack_adapters.iter().any(|record| {
            record.packet_device == packet_device_record.id
                && record.packet_device_generation == packet_device_record.generation
                && record.state == NetworkStackAdapterState::Bound
        }) {
            return Err("network stack adapter packet device already bound");
        }
        if self.check_invariants().is_err() {
            return Err("network stack adapter requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_network_stack_adapter_with_id(
        &mut self,
        adapter: NetworkStackAdapterId,
        backend: ContractObjectRef,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        implementation: &str,
        implementation_version: &str,
        profile: &str,
        medium: &str,
        mac: [u8; 6],
        ipv4_addr: [u8; 4],
        ipv4_prefix_len: u8,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        max_payload_len: u32,
        socket_capacity: u16,
        note: &str,
    ) -> bool {
        if self
            .validate_network_stack_adapter(
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                implementation,
                implementation_version,
                profile,
                medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_network_stack_adapter_id = self.next_network_stack_adapter_id.max(adapter + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkStackAdapterBound {
                adapter,
                implementation: implementation.to_string(),
                implementation_version: implementation_version.to_string(),
                profile: profile.to_string(),
                medium: medium.to_string(),
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                generation,
            },
        );
        self.network_stack_adapters.push(NetworkStackAdapterRecord {
            id: adapter,
            implementation: implementation.to_string(),
            implementation_version: implementation_version.to_string(),
            profile: profile.to_string(),
            medium: medium.to_string(),
            backend,
            packet_device,
            packet_device_generation,
            rx_queue,
            rx_queue_generation,
            tx_queue,
            tx_queue_generation,
            mac,
            ipv4_addr,
            ipv4_prefix_len,
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            max_payload_len,
            socket_capacity,
            generation,
            state: NetworkStackAdapterState::Bound,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_stack_adapters(&self) -> &[NetworkStackAdapterRecord] {
        &self.network_stack_adapters
    }

    pub fn network_stack_adapter_count(&self) -> usize {
        self.network_stack_adapters.len()
    }

    pub fn check_network_stack_adapter_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.network_stack_adapters {
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(
                    SemanticInvariantError::NetworkStackAdapterMissingPacketDevice {
                        adapter: record.id,
                        packet_device: record.packet_device,
                    },
                );
            };
            let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.rx_queue && queue.generation == record.rx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkStackAdapterMissingQueue {
                    adapter: record.id,
                    packet_queue: record.rx_queue,
                });
            };
            let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.tx_queue && queue.generation == record.tx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkStackAdapterMissingQueue {
                    adapter: record.id,
                    packet_queue: record.tx_queue,
                });
            };
            let Some((backend_packet_device, backend_packet_device_generation)) =
                self.live_network_stack_backend_packet_device(record.backend)
            else {
                return Err(SemanticInvariantError::NetworkStackAdapterMissingBackend {
                    adapter: record.id,
                    backend: record.backend,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.implementation != NETWORK_STACK_ADAPTER_IMPLEMENTATION_SMOLTCP
                || record.implementation_version != NETWORK_STACK_ADAPTER_VERSION_SMOLTCP_0_13
                || record.profile != NETWORK_STACK_ADAPTER_PROFILE_SMOLTCP_V1
                || record.medium != NETWORK_STACK_ADAPTER_MEDIUM_ETHERNET
                || record.ipv4_prefix_len == 0
                || record.ipv4_prefix_len > 32
                || record.socket_capacity != 0
                || record.state != NetworkStackAdapterState::Bound
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || packet_device_record.mac != record.mac
                || packet_device_record.mtu != record.mtu
                || packet_device_record.rx_queue_depth != record.rx_queue_depth
                || packet_device_record.tx_queue_depth != record.tx_queue_depth
                || packet_device_record.max_payload_len != record.max_payload_len
                || rx_queue_record.state != PacketQueueObjectState::Registered
                || rx_queue_record.role != PacketQueueRole::Rx
                || rx_queue_record.packet_device != record.packet_device
                || rx_queue_record.packet_device_generation != record.packet_device_generation
                || tx_queue_record.state != PacketQueueObjectState::Registered
                || tx_queue_record.role != PacketQueueRole::Tx
                || tx_queue_record.packet_device != record.packet_device
                || tx_queue_record.packet_device_generation != record.packet_device_generation
                || backend_packet_device != record.packet_device
                || backend_packet_device_generation != record.packet_device_generation
            {
                return Err(SemanticInvariantError::NetworkStackAdapterInvalid {
                    adapter: record.id,
                });
            }
            if let Some(duplicate) = self.network_stack_adapters.iter().find(|other| {
                other.id != record.id
                    && other.packet_device == record.packet_device
                    && other.packet_device_generation == record.packet_device_generation
                    && other.state == NetworkStackAdapterState::Bound
            }) {
                return Err(
                    SemanticInvariantError::NetworkStackAdapterDuplicatePacketDevice {
                        adapter: duplicate.id,
                        packet_device: record.packet_device,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkStackAdapterBound {
                            adapter,
                            implementation,
                            implementation_version,
                            profile,
                            medium,
                            backend,
                            packet_device,
                            packet_device_generation,
                            rx_queue,
                            rx_queue_generation,
                            tx_queue,
                            tx_queue_generation,
                            mac,
                            ipv4_addr,
                            ipv4_prefix_len,
                            mtu,
                            rx_queue_depth,
                            tx_queue_depth,
                            max_payload_len,
                            socket_capacity,
                            generation,
                        } if *adapter == record.id
                            && implementation == &record.implementation
                            && implementation_version == &record.implementation_version
                            && profile == &record.profile
                            && medium == &record.medium
                            && *backend == record.backend
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *rx_queue == record.rx_queue
                            && *rx_queue_generation == record.rx_queue_generation
                            && *tx_queue == record.tx_queue
                            && *tx_queue_generation == record.tx_queue_generation
                            && *mac == record.mac
                            && *ipv4_addr == record.ipv4_addr
                            && *ipv4_prefix_len == record.ipv4_prefix_len
                            && *mtu == record.mtu
                            && *rx_queue_depth == record.rx_queue_depth
                            && *tx_queue_depth == record.tx_queue_depth
                            && *max_payload_len == record.max_payload_len
                            && *socket_capacity == record.socket_capacity
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkStackAdapterMissingEvent {
                    adapter: record.id,
                });
            }
        }
        Ok(())
    }

    fn live_network_stack_backend_packet_device(
        &self,
        backend: ContractObjectRef,
    ) -> Option<(PacketDeviceObjectId, Generation)> {
        match backend.kind {
            ContractObjectKind::FakeNetBackendObject => self
                .fake_net_backends
                .iter()
                .find(|record| {
                    record.id == backend.id
                        && record.generation == backend.generation
                        && record.state == FakeNetBackendObjectState::Bound
                })
                .map(|record| (record.packet_device, record.packet_device_generation)),
            ContractObjectKind::VirtioNetBackendObject => self
                .virtio_net_backends
                .iter()
                .find(|record| {
                    record.id == backend.id
                        && record.generation == backend.generation
                        && record.state == VirtioNetBackendObjectState::SkeletonReady
                })
                .map(|record| (record.packet_device, record.packet_device_generation)),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_stack_adapter_profile_for_test(
        &mut self,
        adapter: NetworkStackAdapterId,
        profile: &str,
    ) {
        if let Some(record) = self
            .network_stack_adapters
            .iter_mut()
            .find(|record| record.id == adapter)
        {
            record.profile = profile.to_string();
        }
    }
}
