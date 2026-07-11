use super::*;

pub const FAKE_NET_BACKEND_PROFILE_V1: &str = "fake-net-v1";
pub const FAKE_NET_BACKEND_PROVIDER_V1: &str = "service_core";

impl SemanticGraph {
    pub(crate) fn validate_fake_net_backend_object(
        &self,
        fake_net_backend: FakeNetBackendObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        provider: &str,
        profile: &str,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        deterministic_seed: u64,
    ) -> Result<(), &'static str> {
        if fake_net_backend == 0 {
            return Err("fake net backend object id=0 is invalid");
        }
        if self.domains.network.fake_net_backends.iter().any(|record| record.id == fake_net_backend)
        {
            return Err("fake net backend object already exists");
        }
        if name.is_empty() || provider.is_empty() || profile.is_empty() {
            return Err("fake net backend object identity fields are empty");
        }
        if provider != FAKE_NET_BACKEND_PROVIDER_V1 {
            return Err("fake net backend object provider is unsupported");
        }
        if profile != FAKE_NET_BACKEND_PROFILE_V1 {
            return Err("fake net backend object profile is unsupported");
        }
        if mtu == 0
            || rx_queue_depth == 0
            || tx_queue_depth == 0
            || frame_format_version == 0
            || max_payload_len == 0
            || deterministic_seed == 0
        {
            return Err("fake net backend object contract values must be nonzero");
        }
        let Some(packet_device_record) =
            self.domains.network.packet_device_objects.iter().find(|record| {
                record.id == packet_device
                    && record.generation == packet_device_generation
                    && record.state == PacketDeviceObjectState::Registered
            })
        else {
            return Err("fake net backend object packet device generation is missing or inactive");
        };
        if mtu != packet_device_record.mtu
            || rx_queue_depth != packet_device_record.rx_queue_depth
            || tx_queue_depth != packet_device_record.tx_queue_depth
            || mac != packet_device_record.mac
            || frame_format_version != packet_device_record.frame_format_version
            || max_payload_len != packet_device_record.max_payload_len
        {
            return Err("fake net backend object contract does not match packet device");
        }
        if self.domains.network.fake_net_backends.iter().any(|record| {
            record.packet_device == packet_device_record.id
                && record.packet_device_generation == packet_device_generation
                && record.state == FakeNetBackendObjectState::Bound
        }) {
            return Err("fake net backend object already bound to packet device generation");
        }
        if self.check_invariants().is_err() {
            return Err("fake net backend object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_fake_net_backend_object_with_id(
        &mut self,
        fake_net_backend: FakeNetBackendObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        provider: &str,
        profile: &str,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        deterministic_seed: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_fake_net_backend_object(
                fake_net_backend,
                name,
                packet_device,
                packet_device_generation,
                provider,
                profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.network.next_fake_net_backend_object_id =
            self.domains.network.next_fake_net_backend_object_id.max(fake_net_backend + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::FakeNetBackendObjectBound {
                fake_net_backend,
                packet_device,
                packet_device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                generation,
            },
        );
        self.domains.network.fake_net_backends.push(FakeNetBackendObjectRecord {
            id: fake_net_backend,
            name: name.to_string(),
            packet_device,
            packet_device_generation,
            provider: provider.to_string(),
            profile: profile.to_string(),
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            mac,
            frame_format_version,
            max_payload_len,
            deterministic_seed,
            generation,
            state: FakeNetBackendObjectState::Bound,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn fake_net_backends(&self) -> &[FakeNetBackendObjectRecord] {
        &self.domains.network.fake_net_backends
    }

    pub fn fake_net_backend_object_count(&self) -> usize {
        self.domains.network.fake_net_backends.len()
    }

    pub fn check_fake_net_backend_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.fake_net_backends {
            let Some(packet_device_record) =
                self.domains.network.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(SemanticInvariantError::FakeNetBackendObjectMissingPacketDevice {
                    fake_net_backend: record.id,
                    packet_device: record.packet_device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.provider != FAKE_NET_BACKEND_PROVIDER_V1
                || record.profile != FAKE_NET_BACKEND_PROFILE_V1
                || record.packet_device_generation == 0
                || record.mtu == 0
                || record.rx_queue_depth == 0
                || record.tx_queue_depth == 0
                || record.frame_format_version == 0
                || record.max_payload_len == 0
                || record.deterministic_seed == 0
                || record.state != FakeNetBackendObjectState::Bound
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || record.mtu != packet_device_record.mtu
                || record.rx_queue_depth != packet_device_record.rx_queue_depth
                || record.tx_queue_depth != packet_device_record.tx_queue_depth
                || record.mac != packet_device_record.mac
                || record.frame_format_version != packet_device_record.frame_format_version
                || record.max_payload_len != packet_device_record.max_payload_len
            {
                return Err(SemanticInvariantError::FakeNetBackendObjectInvalid {
                    fake_net_backend: record.id,
                });
            }
            if let Some(duplicate) = self.domains.network.fake_net_backends.iter().find(|other| {
                other.id != record.id
                    && other.packet_device == record.packet_device
                    && other.packet_device_generation == record.packet_device_generation
                    && other.state == FakeNetBackendObjectState::Bound
            }) {
                return Err(SemanticInvariantError::FakeNetBackendObjectDuplicateBinding {
                    fake_net_backend: duplicate.id,
                    packet_device: record.packet_device,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FakeNetBackendObjectBound {
                            fake_net_backend,
                            packet_device,
                            packet_device_generation,
                            mtu,
                            rx_queue_depth,
                            tx_queue_depth,
                            frame_format_version,
                            max_payload_len,
                            deterministic_seed,
                            generation,
                        } if *fake_net_backend == record.id
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *mtu == record.mtu
                            && *rx_queue_depth == record.rx_queue_depth
                            && *tx_queue_depth == record.tx_queue_depth
                            && *frame_format_version == record.frame_format_version
                            && *max_payload_len == record.max_payload_len
                            && *deterministic_seed == record.deterministic_seed
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FakeNetBackendObjectMissingEvent {
                    fake_net_backend: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_fake_net_backend_packet_device_generation_for_test(
        &mut self,
        fake_net_backend: FakeNetBackendObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .fake_net_backends
            .iter_mut()
            .find(|record| record.id == fake_net_backend)
        {
            record.packet_device_generation = generation;
        }
    }
}
