use super::*;

pub const VIRTIO_NET_BACKEND_PROVIDER_V1: &str = "substrate_virtio";
pub const VIRTIO_NET_BACKEND_PROFILE_V1: &str = "virtio-net-backend-skeleton-v1";
pub const VIRTIO_NET_BACKEND_MODEL_V1: &str = "virtio-net";

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_virtio_net_backend_object(
        &self,
        virtio_net_backend: VirtioNetBackendObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: &str,
        profile: &str,
        model: &str,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        rx_queue_index: u16,
        tx_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
    ) -> Result<(), &'static str> {
        if virtio_net_backend == 0 {
            return Err("virtio net backend object id=0 is invalid");
        }
        if self.virtio_net_backends.iter().any(|record| record.id == virtio_net_backend) {
            return Err("virtio net backend object already exists");
        }
        if name.is_empty() || provider.is_empty() || profile.is_empty() || model.is_empty() {
            return Err("virtio net backend object identity fields are empty");
        }
        if provider != VIRTIO_NET_BACKEND_PROVIDER_V1 {
            return Err("virtio net backend object provider is unsupported");
        }
        if profile != VIRTIO_NET_BACKEND_PROFILE_V1 {
            return Err("virtio net backend object profile is unsupported");
        }
        if model != VIRTIO_NET_BACKEND_MODEL_V1 {
            return Err("virtio net backend object model is unsupported");
        }
        if mtu == 0
            || rx_queue_depth == 0
            || tx_queue_depth == 0
            || frame_format_version == 0
            || max_payload_len == 0
            || queue_size == 0
            || irq_vector == 0
            || rx_queue_index == tx_queue_index
        {
            return Err("virtio net backend object contract values are invalid");
        }
        if negotiated_features & !device_features != 0 {
            return Err("virtio net backend negotiated features exceed device features");
        }
        if negotiated_features & !driver_features != 0 {
            return Err("virtio net backend negotiated features exceed driver features");
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err(
                "virtio net backend object packet device generation is missing or inactive",
            );
        };
        if mtu != packet_device_record.mtu
            || rx_queue_depth != packet_device_record.rx_queue_depth
            || tx_queue_depth != packet_device_record.tx_queue_depth
            || mac != packet_device_record.mac
            || frame_format_version != packet_device_record.frame_format_version
            || max_payload_len != packet_device_record.max_payload_len
        {
            return Err("virtio net backend object contract does not match packet device");
        }
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == driver_binding
                && record.generation == driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err(
                "virtio net backend object driver binding generation is missing or inactive",
            );
        };
        if binding_record.device != packet_device_record.device
            || binding_record.device_generation != packet_device_record.device_generation
        {
            return Err("virtio net backend object driver binding does not target packet device");
        }
        if self.virtio_net_backends.iter().any(|record| {
            record.packet_device == packet_device_record.id
                && record.packet_device_generation == packet_device_generation
                && record.state == VirtioNetBackendObjectState::SkeletonReady
        }) {
            return Err("virtio net backend object already bound to packet device generation");
        }
        if self.virtio_net_backends.iter().any(|record| {
            record.driver_binding == binding_record.id
                && record.driver_binding_generation == driver_binding_generation
                && record.state == VirtioNetBackendObjectState::SkeletonReady
        }) {
            return Err("virtio net backend object already bound to driver binding generation");
        }
        if self.check_invariants().is_err() {
            return Err("virtio net backend object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_virtio_net_backend_object_with_id(
        &mut self,
        virtio_net_backend: VirtioNetBackendObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: &str,
        profile: &str,
        model: &str,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        rx_queue_index: u16,
        tx_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
        note: &str,
    ) -> bool {
        if self
            .validate_virtio_net_backend_object(
                virtio_net_backend,
                name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
            )
            .is_err()
        {
            return false;
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device && record.generation == packet_device_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_virtio_net_backend_object_id =
            self.next_virtio_net_backend_object_id.max(virtio_net_backend + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::VirtioNetBackendSkeletonBound {
                virtio_net_backend,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                device: packet_device_record.device,
                device_generation: packet_device_record.device_generation,
                queue_size,
                rx_queue_index,
                tx_queue_index,
                negotiated_features,
                generation,
            },
        );
        self.virtio_net_backends.push(VirtioNetBackendObjectRecord {
            id: virtio_net_backend,
            name: name.to_string(),
            packet_device,
            packet_device_generation,
            driver_binding,
            driver_binding_generation,
            device: packet_device_record.device,
            device_generation: packet_device_record.device_generation,
            provider: provider.to_string(),
            profile: profile.to_string(),
            model: model.to_string(),
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            mac,
            frame_format_version,
            max_payload_len,
            device_features,
            driver_features,
            negotiated_features,
            rx_queue_index,
            tx_queue_index,
            queue_size,
            irq_vector,
            generation,
            state: VirtioNetBackendObjectState::SkeletonReady,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn virtio_net_backends(&self) -> &[VirtioNetBackendObjectRecord] {
        &self.virtio_net_backends
    }

    pub fn virtio_net_backend_object_count(&self) -> usize {
        self.virtio_net_backends.len()
    }

    pub fn check_virtio_net_backend_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.virtio_net_backends {
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(SemanticInvariantError::VirtioNetBackendObjectMissingPacketDevice {
                    virtio_net_backend: record.id,
                    packet_device: record.packet_device,
                });
            };
            let Some(binding_record) = self.driver_store_bindings.iter().find(|driver_binding| {
                driver_binding.id == record.driver_binding
                    && driver_binding.generation == record.driver_binding_generation
            }) else {
                return Err(SemanticInvariantError::VirtioNetBackendObjectMissingDriverBinding {
                    virtio_net_backend: record.id,
                    driver_binding: record.driver_binding,
                });
            };
            let binding_available = binding_record.state == DriverStoreBindingState::Bound
                || (binding_record.state == DriverStoreBindingState::Released
                    && self.network_driver_cleanup_covers_binding(
                        record.driver_binding,
                        record.driver_binding_generation,
                    ));
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.provider != VIRTIO_NET_BACKEND_PROVIDER_V1
                || record.profile != VIRTIO_NET_BACKEND_PROFILE_V1
                || record.model != VIRTIO_NET_BACKEND_MODEL_V1
                || record.packet_device_generation == 0
                || record.driver_binding_generation == 0
                || record.device_generation == 0
                || record.mtu == 0
                || record.rx_queue_depth == 0
                || record.tx_queue_depth == 0
                || record.frame_format_version == 0
                || record.max_payload_len == 0
                || record.queue_size == 0
                || record.irq_vector == 0
                || record.rx_queue_index == record.tx_queue_index
                || (record.negotiated_features & !record.device_features) != 0
                || (record.negotiated_features & !record.driver_features) != 0
                || record.state != VirtioNetBackendObjectState::SkeletonReady
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || !binding_available
                || binding_record.device != packet_device_record.device
                || binding_record.device_generation != packet_device_record.device_generation
                || record.device != packet_device_record.device
                || record.device_generation != packet_device_record.device_generation
                || record.mtu != packet_device_record.mtu
                || record.rx_queue_depth != packet_device_record.rx_queue_depth
                || record.tx_queue_depth != packet_device_record.tx_queue_depth
                || record.mac != packet_device_record.mac
                || record.frame_format_version != packet_device_record.frame_format_version
                || record.max_payload_len != packet_device_record.max_payload_len
            {
                return Err(SemanticInvariantError::VirtioNetBackendObjectInvalid {
                    virtio_net_backend: record.id,
                });
            }
            if let Some(duplicate) = self.virtio_net_backends.iter().find(|other| {
                other.id != record.id
                    && other.packet_device == record.packet_device
                    && other.packet_device_generation == record.packet_device_generation
                    && other.state == VirtioNetBackendObjectState::SkeletonReady
            }) {
                return Err(SemanticInvariantError::VirtioNetBackendObjectDuplicateBinding {
                    virtio_net_backend: duplicate.id,
                    packet_device: record.packet_device,
                });
            }
            if let Some(duplicate) = self.virtio_net_backends.iter().find(|other| {
                other.id != record.id
                    && other.driver_binding == record.driver_binding
                    && other.driver_binding_generation == record.driver_binding_generation
                    && other.state == VirtioNetBackendObjectState::SkeletonReady
            }) {
                return Err(SemanticInvariantError::VirtioNetBackendObjectDuplicateDriverBinding {
                    virtio_net_backend: duplicate.id,
                    driver_binding: record.driver_binding,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::VirtioNetBackendSkeletonBound {
                            virtio_net_backend,
                            packet_device,
                            packet_device_generation,
                            driver_binding,
                            driver_binding_generation,
                            device,
                            device_generation,
                            queue_size,
                            rx_queue_index,
                            tx_queue_index,
                            negotiated_features,
                            generation,
                        } if *virtio_net_backend == record.id
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *driver_binding == record.driver_binding
                            && *driver_binding_generation == record.driver_binding_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *queue_size == record.queue_size
                            && *rx_queue_index == record.rx_queue_index
                            && *tx_queue_index == record.tx_queue_index
                            && *negotiated_features == record.negotiated_features
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::VirtioNetBackendObjectMissingEvent {
                    virtio_net_backend: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_virtio_net_backend_driver_binding_generation_for_test(
        &mut self,
        virtio_net_backend: VirtioNetBackendObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.virtio_net_backends.iter_mut().find(|record| record.id == virtio_net_backend)
        {
            record.driver_binding_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_virtio_net_backend_irq_vector_for_test(
        &mut self,
        virtio_net_backend: VirtioNetBackendObjectId,
        irq_vector: u16,
    ) {
        if let Some(record) =
            self.virtio_net_backends.iter_mut().find(|record| record.id == virtio_net_backend)
        {
            record.irq_vector = irq_vector;
        }
    }
}
