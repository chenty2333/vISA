use super::*;

mod n0_n4_core;
mod n10_n12_stack_socket;
mod n13_socket_ops;
mod n14_n15_wait_backpressure;
mod n16_cleanup;
mod n5_virtio;
mod n6_n7_rx;
mod n8_n9_tx;

pub(super) use n0_n4_core::setup_n3_packet_descriptor_graph;
pub(super) use n5_virtio::setup_n5_virtio_net_backend_graph;
pub(super) use n6_n7_rx::setup_n6_network_rx_interrupt_graph;
pub(super) use n8_n9_tx::setup_n9_network_tx_completion_graph;
pub(super) use n10_n12_stack_socket::setup_n12_endpoint_object_graph;
pub(super) use n13_socket_ops::setup_n13_socket_operation_graph;
pub(super) use n14_n15_wait_backpressure::setup_n14_socket_wait_graph;
