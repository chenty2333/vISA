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

const N23_REMOTE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const N23_REMOTE_IP: [u8; 4] = [10, 0, 2, 2];
const N23_REMOTE_PORT: u16 = 80;
const N23_SERVER_SEQ: u32 = 0x1234_5678;

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

pub(crate) fn record_network_runtime_n23_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n23 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n23 evidence")?;

    let mut stack = SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos())
        .map_err(|error| format!("n23 smoltcp stack init failed: {error}"))?;
    let mut driver = DriverVirtioNetState::new();
    let mut backend = HostValidationPacketBackend::empty();
    stack
        .init_backend(&mut backend)
        .map_err(|error| format!("n23 packet backend init failed: {error:?}"))?;
    let socket = stack
        .create_tcp_socket()
        .map_err(|error| format!("n23 create tcp socket failed: {error}"))?;
    let _local_port = stack
        .connect_tcp_ipv4(socket, N23_REMOTE_IP, N23_REMOTE_PORT)
        .map_err(|error| format!("n23 connect tcp failed: {error}"))?;

    let arp_pump = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 23, 23)
        .map_err(|error| format!("n23 arp pump failed: {error:?}"))?;
    if arp_pump.stack_tx_frames_submitted_to_driver != 1
        || arp_pump.driver_tx_frames_submitted_to_backend != 1
        || backend.tx_frames.len() != 1
        || !is_arp_request(&backend.tx_frames[0])
    {
        return Err(format!(
            "n23 expected one emitted arp request, stack_tx={} driver_tx={} tx_frames={}",
            arp_pump.stack_tx_frames_submitted_to_driver,
            arp_pump.driver_tx_frames_submitted_to_backend,
            backend.tx_frames.len()
        )
        .into());
    }

    backend.push_rx_frame(arp_reply_frame(
        N23_REMOTE_MAC,
        N23_REMOTE_IP,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        [10, 0, 2, 15],
    ));
    let syn_pump = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 24, 24)
        .map_err(|error| format!("n23 syn pump failed: {error:?}"))?;
    if syn_pump.backend_rx_frames_delivered_to_driver != 1
        || syn_pump.driver_rx_frames_delivered_to_stack != 1
        || syn_pump.stack_tx_frames_submitted_to_driver != 1
        || syn_pump.driver_tx_frames_submitted_to_backend != 1
        || backend.tx_frames.len() != 2
        || !is_tcp_syn(&backend.tx_frames[1])
    {
        return Err(format!(
            "n23 expected arp reply to produce one tcp syn, backend_rx={} driver_rx={} stack_tx={} driver_tx={} tx_frames={}",
            syn_pump.backend_rx_frames_delivered_to_driver,
            syn_pump.driver_rx_frames_delivered_to_stack,
            syn_pump.stack_tx_frames_submitted_to_driver,
            syn_pump.driver_tx_frames_submitted_to_backend,
            backend.tx_frames.len()
        )
        .into());
    }

    let syn_ack = tcp_syn_ack_for_syn(&backend.tx_frames[1], N23_REMOTE_MAC, N23_SERVER_SEQ)?;
    backend.push_rx_frame(syn_ack);
    let established_pump = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 25, 25)
        .map_err(|error| format!("n23 established pump failed: {error:?}"))?;
    let snapshot =
        stack.tcp_snapshot(socket).map_err(|error| format!("n23 tcp snapshot failed: {error}"))?;
    if established_pump.backend_rx_frames_delivered_to_driver != 1
        || established_pump.driver_rx_frames_delivered_to_stack != 1
        || established_pump.stack_tx_frames_submitted_to_driver != 1
        || established_pump.driver_tx_frames_submitted_to_backend != 1
        || backend.tx_frames.len() != 3
        || !is_tcp_ack(&backend.tx_frames[2])
        || snapshot.state != "established"
        || !snapshot.can_send
    {
        return Err(format!(
            "n23 expected syn-ack to establish tcp socket, backend_rx={} driver_rx={} stack_tx={} driver_tx={} tx_frames={} state={} can_send={}",
            established_pump.backend_rx_frames_delivered_to_driver,
            established_pump.driver_rx_frames_delivered_to_stack,
            established_pump.stack_tx_frames_submitted_to_driver,
            established_pump.driver_tx_frames_submitted_to_backend,
            backend.tx_frames.len(),
            snapshot.state,
            snapshot.can_send
        )
        .into());
    }
    if driver.pending_tx_frames() != 0 || driver.pending_rx_frames() != 0 {
        return Err(format!(
            "n23 unexpected driver queue state after handshake: pending_rx={} pending_tx={}",
            driver.pending_rx_frames(),
            driver.pending_tx_frames()
        )
        .into());
    }
    if stack.pending_rx_frames() != 0 || stack.pending_tx_frames() != 0 {
        return Err(format!(
            "n23 unexpected smoltcp queue state after handshake: pending_rx={} pending_tx={}",
            stack.pending_rx_frames(),
            stack.pending_tx_frames()
        )
        .into());
    }
    if let Err(error) = semantic.check_invariants() {
        return Err(format!(
            "n23 cannot record tcp established evidence on dirty graph: {error:?}"
        )
        .into());
    }

    let connected_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_032, 1);
    let commands = [
        CommandEnvelope::new(
            204,
            "target-executor-n23",
            SemanticCommand::CreateWait {
                wait: 10_088,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketWritable,
                generation: 1,
                blockers: vec![connected_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("n23-connect-in-progress".to_owned()),
            },
        ),
        CommandEnvelope::new(
            205,
            "target-executor-n23",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_089,
                wait: 10_088,
                wait_generation: 1,
                endpoint: 10_032,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketWritable,
                blocker: connected_endpoint,
                note: "n23-record-connect-writable-wait".to_owned(),
            },
        ),
        CommandEnvelope::new(
            206,
            "target-executor-n23",
            SemanticCommand::ResolveSocketWait {
                socket_wait: 10_089,
                socket_wait_generation: 1,
                ready_sequence: 5,
                byte_len: 0,
                note: "n23-resolve-connect-wait-after-smoltcp-established".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n23 evidence command {} ({}) failed: status={} violations={:?}",
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
    fn empty() -> Self {
        Self { init_mac: None, rx_frames: Vec::new(), tx_frames: Vec::new() }
    }

    fn with_rx_frame(frame: &[u8]) -> Self {
        Self { init_mac: None, rx_frames: vec![frame.to_vec()], tx_frames: Vec::new() }
    }

    fn push_rx_frame<F: Into<Vec<u8>>>(&mut self, frame: F) {
        self.rx_frames.push(frame.into());
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

fn arp_reply_frame(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> [u8; N22_FRAME_LEN] {
    let mut frame = [0u8; N22_FRAME_LEN];
    frame[0..6].copy_from_slice(&target_mac);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..16].copy_from_slice(&[0x00, 0x01]);
    frame[16..18].copy_from_slice(&[0x08, 0x00]);
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&[0x00, 0x02]);
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender_ip);
    frame[32..38].copy_from_slice(&target_mac);
    frame[38..42].copy_from_slice(&target_ip);
    frame
}

fn tcp_syn_ack_for_syn(
    syn: &[u8],
    server_mac: [u8; 6],
    server_seq: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if syn.len() < 54 {
        return Err("n23 tcp syn frame is too short".into());
    }
    let syn_ip_start = 14usize;
    let syn_ihl = ((syn[syn_ip_start] & 0x0f) as usize) * 4;
    if syn_ihl < 20 || syn.len() < syn_ip_start + syn_ihl + 20 {
        return Err("n23 tcp syn has invalid ipv4/tcp header length".into());
    }
    let syn_tcp_start = syn_ip_start + syn_ihl;
    let client_mac: [u8; 6] = syn[6..12].try_into()?;
    let client_ip: [u8; 4] = syn[26..30].try_into()?;
    let server_ip: [u8; 4] = syn[30..34].try_into()?;
    let client_port = u16::from_be_bytes([syn[syn_tcp_start], syn[syn_tcp_start + 1]]);
    let server_port = u16::from_be_bytes([syn[syn_tcp_start + 2], syn[syn_tcp_start + 3]]);
    let client_seq = u32::from_be_bytes([
        syn[syn_tcp_start + 4],
        syn[syn_tcp_start + 5],
        syn[syn_tcp_start + 6],
        syn[syn_tcp_start + 7],
    ]);

    let mut frame = vec![0u8; 54];
    frame[0..6].copy_from_slice(&client_mac);
    frame[6..12].copy_from_slice(&server_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    let ip_start = 14usize;
    frame[ip_start] = 0x45;
    frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
    frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip_start + 8] = 64;
    frame[ip_start + 9] = 6;
    frame[ip_start + 12..ip_start + 16].copy_from_slice(&server_ip);
    frame[ip_start + 16..ip_start + 20].copy_from_slice(&client_ip);
    let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp_start = ip_start + 20;
    frame[tcp_start..tcp_start + 2].copy_from_slice(&server_port.to_be_bytes());
    frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&client_port.to_be_bytes());
    frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&server_seq.to_be_bytes());
    frame[tcp_start + 8..tcp_start + 12].copy_from_slice(&client_seq.wrapping_add(1).to_be_bytes());
    frame[tcp_start + 12] = 5 << 4;
    frame[tcp_start + 13] = 0x12;
    frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
    let tcp_checksum = tcp_ipv4_checksum(&server_ip, &client_ip, &frame[tcp_start..]);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(frame)
}

fn is_arp_request(frame: &[u8]) -> bool {
    frame.len() >= N22_FRAME_LEN && frame[12..14] == [0x08, 0x06] && frame[20..22] == [0x00, 0x01]
}

fn is_tcp_syn(frame: &[u8]) -> bool {
    tcp_flags(frame).is_some_and(|flags| flags & 0x02 == 0x02 && flags & 0x10 == 0)
}

fn is_tcp_ack(frame: &[u8]) -> bool {
    tcp_flags(frame).is_some_and(|flags| flags & 0x10 == 0x10)
}

fn tcp_flags(frame: &[u8]) -> Option<u8> {
    if frame.len() < 54 || frame[12..14] != [0x08, 0x00] || frame[23] != 6 {
        return None;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    let tcp_start = 14 + ihl;
    frame.get(tcp_start + 13).copied()
}

fn tcp_ipv4_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut checksum_input = Vec::with_capacity(12 + tcp_segment.len());
    checksum_input.extend_from_slice(src_ip);
    checksum_input.extend_from_slice(dst_ip);
    checksum_input.push(0);
    checksum_input.push(6);
    checksum_input.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    checksum_input.extend_from_slice(tcp_segment);
    internet_checksum(&checksum_input)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
