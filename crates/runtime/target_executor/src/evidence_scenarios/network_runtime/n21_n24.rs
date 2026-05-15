use net_stack_adapter::{
    SmoltcpAdapterConfig, SmoltcpPacketStack, pump_driver_backend, pump_stack_driver_backend,
};
use service_core::driver::DriverVirtioNetState;
use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};

use super::super::super::*;

const N21_TX_FRAME_LEN: usize = 42;
const N21_TX_FRAME_LEN_U32: u32 = 42;
const N21_TX_FRAME: [u8; N21_TX_FRAME_LEN] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst mac
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // src mac
    0x08, 0x06, // ethertype ARP
    0x00, 0x01, // htype ethernet
    0x08, 0x00, // ptype ipv4
    0x06, // hlen
    0x04, // plen
    0x00, 0x01, // request
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // sender mac
    10, 0, 2, 15, // sender ip
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target mac
    10, 0, 2, 2, // target ip
];

const N21_RX_FRAME: [u8; N21_TX_FRAME_LEN] = [
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // dst mac
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
    0x08, 0x06, // ethertype ARP
    0x00, 0x01, // htype ethernet
    0x08, 0x00, // ptype ipv4
    0x06, // hlen
    0x04, // plen
    0x00, 0x02, // reply
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // sender mac
    10, 0, 2, 2, // sender ip
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // target mac
    10, 0, 2, 15, // target ip
];

const N22_FRAME_LEN: usize = 42;
const N22_FRAME_LEN_U32: u32 = 42;
const N22_BACKEND_RX_ARP_REQUEST: [u8; N22_FRAME_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst broadcast
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src remote mac
    0x08, 0x06, // ethertype ARP
    0x00, 0x01, // htype ethernet
    0x08, 0x00, // ptype ipv4
    0x06, // hlen
    0x04, // plen
    0x00, 0x01, // request
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // sender mac
    10, 0, 2, 2, // sender ip
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target mac
    10, 0, 2, 15, // target ip
];
const N22_BACKEND_TX_ARP_REPLY: [u8; N22_FRAME_LEN] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst remote mac
    0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01, // src vmos mac
    0x08, 0x06, // ethertype ARP
    0x00, 0x01, // htype ethernet
    0x08, 0x00, // ptype ipv4
    0x06, // hlen
    0x04, // plen
    0x00, 0x02, // reply
    0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01, // sender mac
    10, 0, 2, 15, // sender ip
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // target mac
    10, 0, 2, 2, // target ip
];

pub(crate) fn record_network_runtime_n21_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n21 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n21 evidence")?;
    let tx_handle = semantic
        .device_capabilities()
        .iter()
        .find(|record| record.id == 10_020 && record.generation == 1)
        .and_then(|record| semantic.capabilities().record(record.capability))
        .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
        .ok_or("n21 packet tx capability handle is missing")?;

    let mut driver = DriverVirtioNetState::new();
    let submitted = driver
        .submit_tx_frame(21, &N21_TX_FRAME)
        .map_err(|errno| format!("n21 driver submit tx failed errno={errno}"))?;
    if submitted != N21_TX_FRAME_LEN_U32 {
        return Err(format!("n21 driver submitted {submitted} bytes").into());
    }
    let mut backend = HostValidationPacketBackend::with_rx_frame(&N21_RX_FRAME);
    let pump = pump_driver_backend(&mut driver, &mut backend, 21)
        .map_err(|error| format!("n21 driver/backend pump failed: {error:?}"))?;
    if pump.rx_frames_delivered != 1 || pump.tx_frames_submitted != 1 {
        return Err(format!(
            "n21 expected one rx delivery and one tx submit, got rx={} tx={}",
            pump.rx_frames_delivered, pump.tx_frames_submitted
        )
        .into());
    }
    if backend.tx_frames.len() != 1 || backend.tx_frames[0].as_slice() != N21_TX_FRAME {
        return Err("n21 backend did not receive the exact queued tx frame".into());
    }
    if driver.pending_tx_frames() != 0 || driver.pending_rx_frames() != 1 {
        return Err(format!(
            "n21 unexpected driver queue state after pump: pending_rx={} pending_tx={}",
            driver.pending_rx_frames(),
            driver.pending_tx_frames()
        )
        .into());
    }
    if let Err(error) = semantic.check_invariants() {
        return Err(
            format!("n21 cannot record packet backend evidence on dirty graph: {error:?}").into()
        );
    }

    let commands = [
        CommandEnvelope::new(
            196,
            "target-executor-n21",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_080,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Tx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: N21_TX_FRAME_LEN_U32,
                sequence: 22,
                state: PacketBufferObjectState::Filled,
                note: "n21-record-driver-backend-pump-tx-buffer".to_owned(),
            },
        ),
        CommandEnvelope::new(
            197,
            "target-executor-n21",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_081,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                packet_buffer: 10_080,
                packet_buffer_generation: 1,
                slot: 1,
                length: N21_TX_FRAME_LEN_U32,
                note: "n21-record-driver-backend-pump-tx-descriptor".to_owned(),
            },
        ),
        CommandEnvelope::new(
            198,
            "target-executor-n21",
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate: 10_082,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                packet_descriptor: 10_081,
                packet_descriptor_generation: 1,
                device_capability: 10_020,
                device_capability_generation: 1,
                handle: tx_handle,
                note: "n21-record-driver-backend-pump-tx-capability-gate".to_owned(),
            },
        ),
        CommandEnvelope::new(
            199,
            "target-executor-n21",
            SemanticCommand::RecordNetworkTxCompletion {
                completion: 10_083,
                tx_gate: 10_082,
                tx_gate_generation: 1,
                backend: ContractObjectRef::new(
                    ContractObjectKind::VirtioNetBackendObject,
                    10_010,
                    1,
                ),
                completion_sequence: 2,
                note: "n21-record-completion-after-packet-backend-submit".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n21 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n22_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n22 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n22 evidence")?;
    let tx_handle = semantic
        .device_capabilities()
        .iter()
        .find(|record| record.id == 10_020 && record.generation == 1)
        .and_then(|record| semantic.capabilities().record(record.capability))
        .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
        .ok_or("n22 packet tx capability handle is missing")?;

    let mut stack = SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos())
        .map_err(|error| format!("n22 smoltcp stack init failed: {error}"))?;
    let mut driver = DriverVirtioNetState::new();
    let mut backend = HostValidationPacketBackend::with_rx_frame(&N22_BACKEND_RX_ARP_REQUEST);
    stack
        .init_backend(&mut backend)
        .map_err(|error| format!("n22 packet backend init failed: {error:?}"))?;
    let pump = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 22, 22)
        .map_err(|error| format!("n22 stack/driver/backend pump failed: {error:?}"))?;
    if pump.backend_rx_frames_delivered_to_driver != 1
        || pump.driver_rx_frames_delivered_to_stack != 1
        || pump.stack_tx_frames_submitted_to_driver != 1
        || pump.driver_tx_frames_submitted_to_backend != 1
    {
        return Err(format!(
            "n22 expected one frame across each pump edge, got backend_rx={} driver_rx={} stack_tx={} driver_tx={}",
            pump.backend_rx_frames_delivered_to_driver,
            pump.driver_rx_frames_delivered_to_stack,
            pump.stack_tx_frames_submitted_to_driver,
            pump.driver_tx_frames_submitted_to_backend
        )
        .into());
    }
    if backend.tx_frames.len() != 1 || backend.tx_frames[0].as_slice() != N22_BACKEND_TX_ARP_REPLY {
        return Err("n22 backend did not receive the exact smoltcp ARP reply".into());
    }
    if driver.pending_tx_frames() != 0 || driver.pending_rx_frames() != 0 {
        return Err(format!(
            "n22 unexpected driver queue state after pump: pending_rx={} pending_tx={}",
            driver.pending_rx_frames(),
            driver.pending_tx_frames()
        )
        .into());
    }
    if stack.pending_rx_frames() != 0 || stack.pending_tx_frames() != 0 {
        return Err(format!(
            "n22 unexpected smoltcp queue state after pump: pending_rx={} pending_tx={}",
            stack.pending_rx_frames(),
            stack.pending_tx_frames()
        )
        .into());
    }
    if let Err(error) = semantic.check_invariants() {
        return Err(format!(
            "n22 cannot record stack/driver/backend evidence on dirty graph: {error:?}"
        )
        .into());
    }

    let commands = [
        CommandEnvelope::new(
            200,
            "target-executor-n22",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_084,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Tx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: N22_FRAME_LEN_U32,
                sequence: 23,
                state: PacketBufferObjectState::Filled,
                note: "n22-record-stack-driver-backend-pump-tx-buffer".to_owned(),
            },
        ),
        CommandEnvelope::new(
            201,
            "target-executor-n22",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_085,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                packet_buffer: 10_084,
                packet_buffer_generation: 1,
                slot: 2,
                length: N22_FRAME_LEN_U32,
                note: "n22-record-stack-driver-backend-pump-tx-descriptor".to_owned(),
            },
        ),
        CommandEnvelope::new(
            202,
            "target-executor-n22",
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate: 10_086,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                packet_descriptor: 10_085,
                packet_descriptor_generation: 1,
                device_capability: 10_020,
                device_capability_generation: 1,
                handle: tx_handle,
                note: "n22-record-stack-driver-backend-pump-tx-capability-gate".to_owned(),
            },
        ),
        CommandEnvelope::new(
            203,
            "target-executor-n22",
            SemanticCommand::RecordNetworkTxCompletion {
                completion: 10_087,
                tx_gate: 10_086,
                tx_gate_generation: 1,
                backend: ContractObjectRef::new(
                    ContractObjectKind::VirtioNetBackendObject,
                    10_010,
                    1,
                ),
                completion_sequence: 3,
                note: "n22-record-completion-after-stack-driver-backend-pump".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n22 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    Ok(())
}

struct HostValidationPacketBackend {
    init_mac: Option<[u8; 6]>,
    rx_frames: Vec<Vec<u8>>,
    tx_frames: Vec<Vec<u8>>,
}

impl HostValidationPacketBackend {
    fn with_rx_frame(frame: &[u8]) -> Self {
        Self { init_mac: None, rx_frames: vec![frame.to_vec()], tx_frames: Vec::new() }
    }
}

impl PacketDeviceBackend for HostValidationPacketBackend {
    fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
        self.init_mac = Some(mac);
        Ok(())
    }

    fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
        self.tx_frames.push(frame.to_vec());
        Ok(())
    }

    fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
        let count = self.rx_frames.len().min(out.len());
        for slot in out.iter_mut().take(count) {
            let frame = self.rx_frames.remove(0);
            if frame.len() > slot.data.len() {
                return Err(SubstrateError::ContractViolation {
                    detail: "host validation packet frame exceeds slot capacity",
                });
            }
            slot.len =
                u16::try_from(frame.len()).map_err(|_| SubstrateError::ContractViolation {
                    detail: "host validation packet frame length overflow",
                })?;
            slot.data[..frame.len()].copy_from_slice(&frame);
        }
        Ok(count)
    }

    fn mtu(&self) -> usize {
        1500
    }
}
